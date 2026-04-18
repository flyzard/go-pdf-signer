package crypto

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/subtle"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"time"
)

// RFC 3161 TSA client. The moving parts split:
//
//   - BuildTimeStampReq: TimeStampReq DER from (hash, hashAlg, certReq flag).
//   - FetchTimeStampToken: POST the req to the TSA URL via the hardened
//     shared transport, parse TimeStampResp, return the embedded
//     TimeStampToken (raw CMS SignedData DER).
//   - ParseTSTInfo: pull genTime / nonce / messageImprint out of a token's
//     eContent so the caller can compare against what it sent.
//
// The token is *also* the attribute value that goes into CMS
// SignerInfo.unsignedAttrs (id-aa-signatureTimeStampToken). No re-wrapping
// needed.

// Content types used by RFC 3161.
const (
	ContentTypeTSReq = "application/timestamp-query"
	ContentTypeTSRsp = "application/timestamp-reply"
)

// OIDs used by the TSA layer.
var (
	oidTSTInfo = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4} // id-ct-TSTInfo
	oidTSADigestSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidTSADigestSHA384 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	oidTSADigestSHA512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
)

// PKIStatus values per RFC 3161 §2.4.2.
const (
	TSAStatusGranted          = 0
	TSAStatusGrantedWithMods  = 1
	TSAStatusRejection        = 2
	TSAStatusWaiting          = 3
	TSAStatusRevocationWarn   = 4
	TSAStatusRevocationNotify = 5
)

// DefaultTSAClockSkew caps how far a returned genTime may sit in the
// future relative to the local clock before we refuse the token. Half of
// a typical NTP drift window is enough leeway for honest servers and
// tight enough to refuse obvious forgeries.
const DefaultTSAClockSkew = 5 * time.Minute

// MessageImprint ::= SEQUENCE { hashAlgorithm AlgorithmIdentifier, hashedMessage OCTET STRING }
type messageImprint struct {
	HashAlgorithm pkix.AlgorithmIdentifier
	HashedMessage []byte
}

// TimeStampReq ::= SEQUENCE { version INTEGER, messageImprint, reqPolicy? OID, nonce? INTEGER, certReq? BOOL, extensions? [0] IMPLICIT Extensions }
type timeStampReq struct {
	Version        int
	MessageImprint messageImprint
	ReqPolicy      asn1.ObjectIdentifier `asn1:"optional"`
	Nonce          *big.Int              `asn1:"optional"`
	CertReq        bool                  `asn1:"optional,default:false"`
	Extensions     []pkix.Extension      `asn1:"optional,tag:0"`
}

// TimeStampResp ::= SEQUENCE { status PKIStatusInfo, timeStampToken TimeStampToken OPTIONAL }
type timeStampResp struct {
	Status         pkiStatusInfo
	TimeStampToken asn1.RawValue `asn1:"optional"`
}

// PKIStatusInfo ::= SEQUENCE { status INTEGER, statusString SEQUENCE OF UTF8String OPTIONAL, failInfo BIT STRING OPTIONAL }
type pkiStatusInfo struct {
	Status       int
	StatusString []string       `asn1:"optional"`
	FailInfo     asn1.BitString `asn1:"optional"`
}

// TSTInfo is the to-be-signed content inside a TimeStampToken. Exported so
// verify and appearance code can surface genTime and the imprint digest.
type TSTInfo struct {
	GenTime        time.Time
	SerialNumber   *big.Int
	HashAlgorithm  asn1.ObjectIdentifier
	HashedMessage  []byte
	Nonce          *big.Int // nil when absent
	Policy         asn1.ObjectIdentifier
}

// BuildTimeStampReq DER-encodes a RFC 3161 TimeStampReq for the given
// message digest. hashAlg is the algorithm the caller already used to
// produce digest. When includeNonce is true, a random 64-bit nonce is
// generated and returned alongside the DER bytes for later echo-check.
// certReq=true asks the TSA to include its signing cert in the response —
// strongly recommended so the verifier can validate without out-of-band
// chain resolution.
func BuildTimeStampReq(digest []byte, hashAlg crypto.Hash, includeNonce bool, certReq bool) (reqDER []byte, nonce *big.Int, err error) {
	oid, err := tsaOIDForHash(hashAlg)
	if err != nil {
		return nil, nil, err
	}
	imprint := messageImprint{
		HashAlgorithm: pkix.AlgorithmIdentifier{Algorithm: oid},
		HashedMessage: digest,
	}
	req := timeStampReq{
		Version:        1,
		MessageImprint: imprint,
		CertReq:        certReq,
	}
	if includeNonce {
		nb := make([]byte, 8)
		if _, err := rand.Read(nb); err != nil {
			return nil, nil, fmt.Errorf("tsa: nonce: %w", err)
		}
		req.Nonce = new(big.Int).SetBytes(nb)
	}
	der, err := asn1.Marshal(req)
	if err != nil {
		return nil, nil, fmt.Errorf("tsa: marshal req: %w", err)
	}
	return der, req.Nonce, nil
}

// FetchTimeStampToken POSTs the request to tsaURL, validates the
// TimeStampResp, and returns the raw TimeStampToken DER (a CMS SignedData
// blob). Honors the shared transport's DNS-rebinding and private-IP
// guards. Retries on 5xx / Retry-After via the existing withRetry helper.
//
// Caller must pass the nonce returned by BuildTimeStampReq (or nil if the
// request omitted one); we enforce the echo here so sign-finish doesn't
// have to re-parse the token just for that check.
func FetchTimeStampToken(ctx context.Context, tsaURL string, reqDER []byte, sentNonce *big.Int) ([]byte, error) {
	if err := validateFetchURL(tsaURL); err != nil {
		return nil, fmt.Errorf("tsa: %w", err)
	}

	var respBody []byte
	err := withRetry(ctx, 3, 200*time.Millisecond, func() error {
		r, e := postTSA(ctx, tsaURL, reqDER)
		respBody = r
		return e
	})
	if err != nil {
		return nil, fmt.Errorf("tsa: fetch %s: %w", tsaURL, err)
	}

	var resp timeStampResp
	if _, err := asn1.Unmarshal(respBody, &resp); err != nil {
		return nil, fmt.Errorf("tsa: parse response: %w", err)
	}
	if resp.Status.Status != TSAStatusGranted && resp.Status.Status != TSAStatusGrantedWithMods {
		return nil, fmt.Errorf("tsa: status=%d (%s)", resp.Status.Status, tsaStatusName(resp.Status.Status))
	}
	if len(resp.TimeStampToken.FullBytes) == 0 {
		return nil, fmt.Errorf("tsa: response status granted but timeStampToken missing")
	}

	tst, err := ParseTSTInfoFromToken(resp.TimeStampToken.FullBytes)
	if err != nil {
		return nil, fmt.Errorf("tsa: parse TSTInfo: %w", err)
	}
	if err := validateTSTInfo(tst, sentNonce); err != nil {
		return nil, err
	}
	return resp.TimeStampToken.FullBytes, nil
}

// ParseTSTInfoFromToken pulls the TSTInfo out of a raw TimeStampToken
// (CMS SignedData). Only the fields the caller cares about (genTime,
// messageImprint, nonce) are returned; the rest of the TSTInfo fields
// (accuracy, ordering, tsa, extensions) are intentionally unparsed.
func ParseTSTInfoFromToken(tokenDER []byte) (*TSTInfo, error) {
	var ci struct {
		ContentType asn1.ObjectIdentifier
		Content     asn1.RawValue `asn1:"explicit,tag:0"`
	}
	if _, err := asn1.Unmarshal(tokenDER, &ci); err != nil {
		return nil, fmt.Errorf("ContentInfo: %w", err)
	}
	// Walk SignedData to find encapContentInfo.eContent.
	var sd asn1.RawValue
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		return nil, fmt.Errorf("SignedData outer: %w", err)
	}
	remaining := sd.Bytes
	var version int
	var err error
	if remaining, err = asn1.Unmarshal(remaining, &version); err != nil {
		return nil, err
	}
	var digestAlgos asn1.RawValue
	if remaining, err = asn1.Unmarshal(remaining, &digestAlgos); err != nil {
		return nil, err
	}
	var encap asn1.RawValue
	if _, err = asn1.Unmarshal(remaining, &encap); err != nil {
		return nil, err
	}
	// EncapsulatedContentInfo ::= SEQUENCE { eContentType OID, eContent [0] EXPLICIT OCTET STRING OPTIONAL }
	var eContentType asn1.ObjectIdentifier
	encapRest, err := asn1.Unmarshal(encap.Bytes, &eContentType)
	if err != nil {
		return nil, fmt.Errorf("encapContentInfo type: %w", err)
	}
	if !eContentType.Equal(oidTSTInfo) {
		return nil, fmt.Errorf("eContentType %v, want id-ct-TSTInfo", eContentType)
	}
	var eContentTagged asn1.RawValue
	if _, err := asn1.Unmarshal(encapRest, &eContentTagged); err != nil {
		return nil, fmt.Errorf("eContent tag: %w", err)
	}
	// eContent is [0] EXPLICIT OCTET STRING → Bytes holds the OCTET STRING body,
	// which itself is the DER-encoded TSTInfo.
	var eContent []byte
	if _, err := asn1.Unmarshal(eContentTagged.Bytes, &eContent); err != nil {
		return nil, fmt.Errorf("eContent OCTET: %w", err)
	}
	// encoding/asn1 can't express "remaining raw tail", so walk TSTInfo's
	// SEQUENCE body manually: version → policy → imprint → serial →
	// genTime, then scan the optional tail for a nonce INTEGER.
	var outerSeq asn1.RawValue
	if _, err := asn1.Unmarshal(eContent, &outerSeq); err != nil {
		return nil, fmt.Errorf("TSTInfo outer: %w", err)
	}
	body := outerSeq.Bytes

	var (
		ver            int
		policy         asn1.ObjectIdentifier
		imprint        messageImprint
		serial         *big.Int
		genTime        time.Time
		nonce          *big.Int
	)
	if body, err = asn1.Unmarshal(body, &ver); err != nil {
		return nil, fmt.Errorf("TSTInfo version: %w", err)
	}
	if body, err = asn1.Unmarshal(body, &policy); err != nil {
		return nil, fmt.Errorf("TSTInfo policy: %w", err)
	}
	if body, err = asn1.Unmarshal(body, &imprint); err != nil {
		return nil, fmt.Errorf("TSTInfo imprint: %w", err)
	}
	if body, err = asn1.Unmarshal(body, &serial); err != nil {
		return nil, fmt.Errorf("TSTInfo serial: %w", err)
	}
	if body, err = asn1.Unmarshal(body, &genTime); err != nil {
		return nil, fmt.Errorf("TSTInfo genTime: %w", err)
	}
	// Walk optional tail: accuracy SEQUENCE (universal SEQUENCE) / ordering
	// BOOLEAN / nonce INTEGER / tsa [0] / extensions [1].
	for len(body) > 0 {
		var raw asn1.RawValue
		next, err := asn1.Unmarshal(body, &raw)
		if err != nil {
			break
		}
		body = next
		switch {
		case raw.Class == asn1.ClassUniversal && raw.Tag == asn1.TagInteger:
			var n big.Int
			if _, err := asn1.Unmarshal(raw.FullBytes, &n); err == nil {
				nonce = &n
			}
		}
	}
	return &TSTInfo{
		GenTime:       genTime,
		SerialNumber:  serial,
		HashAlgorithm: imprint.HashAlgorithm.Algorithm,
		HashedMessage: imprint.HashedMessage,
		Nonce:         nonce,
		Policy:        policy,
	}, nil
}

// validateTSTInfo enforces nonce echo + freshness. Clock skew is capped
// at DefaultTSAClockSkew. Called from FetchTimeStampToken; exposed to
// tests via TSTInfo round-trip.
func validateTSTInfo(tst *TSTInfo, sentNonce *big.Int) error {
	if sentNonce != nil {
		if tst.Nonce == nil {
			return fmt.Errorf("tsa: response missing nonce we asked for")
		}
		// Constant-time INT compare via byte marshalling to avoid leaking
		// via early-return timing if this ever matters.
		if subtle.ConstantTimeCompare(sentNonce.Bytes(), tst.Nonce.Bytes()) != 1 {
			return fmt.Errorf("tsa: nonce mismatch (sent=%s got=%s)",
				sentNonce.String(), tst.Nonce.String())
		}
	}
	now := time.Now()
	if tst.GenTime.After(now.Add(DefaultTSAClockSkew)) {
		return fmt.Errorf("tsa: genTime %s is in the future (skew > %s)",
			tst.GenTime.Format(time.RFC3339), DefaultTSAClockSkew)
	}
	return nil
}

// postTSA is a thin RFC 3161 client: POST with the right Content-Type,
// read up to 256 KB, return the body. Shares sharedTransport so the same
// DNS-rebinding + private-IP guards apply as to OCSP/CRL/AIA fetches.
func postTSA(ctx context.Context, url string, body []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", ContentTypeTSReq)
	req.Header.Set("Accept", ContentTypeTSRsp)
	resp, err := httpClient30s.Do(req)
	if err != nil {
		return nil, fmt.Errorf("POST to TSA %s: %w", url, err)
	}
	defer resp.Body.Close()
	if err := classifyHTTPStatus(resp, url); err != nil {
		return nil, err
	}
	const maxSize = 256 * 1024
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxSize))
	if err != nil {
		return nil, fmt.Errorf("read TSA body: %w", err)
	}
	return raw, nil
}

func tsaOIDForHash(h crypto.Hash) (asn1.ObjectIdentifier, error) {
	switch h {
	case crypto.SHA256:
		return oidTSADigestSHA256, nil
	case crypto.SHA384:
		return oidTSADigestSHA384, nil
	case crypto.SHA512:
		return oidTSADigestSHA512, nil
	}
	return nil, fmt.Errorf("tsa: unsupported hash %v", h)
}

func tsaStatusName(s int) string {
	switch s {
	case TSAStatusGranted:
		return "granted"
	case TSAStatusGrantedWithMods:
		return "grantedWithMods"
	case TSAStatusRejection:
		return "rejection"
	case TSAStatusWaiting:
		return "waiting"
	case TSAStatusRevocationWarn:
		return "revocationWarning"
	case TSAStatusRevocationNotify:
		return "revocationNotification"
	}
	return "unknown"
}

