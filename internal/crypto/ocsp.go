package crypto

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/subtle"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"golang.org/x/crypto/ocsp"
)

// Maximum age accepted for an OCSP response (ThisUpdate to now).
const maxOCSPAge = 7 * 24 * time.Hour

// Clock skew tolerance for the future-ThisUpdate guard.
const ocspClockSkew = 5 * time.Minute

// OCSP extension OIDs.
var (
	// id-pkix-ocsp-nonce (RFC 6960 §4.4.1).
	ocspNonceOID = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 2}
	// id-pkix-ocsp-nocheck (RFC 6960 §4.2.2.2.1) — marks the responder
	// cert as exempt from revocation checking to avoid a bootstrap loop.
	ocspNoCheckOID = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 5}
	// id-kp-OCSPSigning (RFC 6960 §4.2.2.2).
	ocspSigningEKU = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 9}
)

// OCSPResult holds the parsed OCSP response and its raw DER bytes.
type OCSPResult struct {
	Response    *ocsp.Response
	RawResponse []byte // DER-encoded for DSS embedding
}

// FetchOCSP fetches and validates an OCSP response for cert. The request
// includes a fresh nonce; the response is rejected if expired (NextUpdate in
// the past) or older than maxOCSPAge. Responder authorization and nocheck
// are enforced per RFC 6960. Network calls retry up to 3 times and respect
// ctx cancellation. On a "malformedRequest" or "unauthorized" response to a
// SHA-256 CertID, a one-time SHA-1 CertID retry is made for RFC 5019-style
// lightweight responders (R-4.1.1).
func FetchOCSP(ctx context.Context, cert, issuer *x509.Certificate) (*OCSPResult, error) {
	if len(cert.OCSPServer) == 0 {
		return nil, fmt.Errorf("certificate has no OCSP server URLs")
	}

	var lastErr error
	for _, serverURL := range cert.OCSPServer {
		res, err := ocspTrySingleHash(ctx, cert, issuer, serverURL, crypto.SHA256)
		if err == nil {
			return res, nil
		}
		// RFC 5019 lightweight responders advertise only SHA-1 CertID
		// support and reject SHA-256 with "malformedRequest" /
		// "unauthorized". Retry once at SHA-1 before giving up this URL.
		if isOCSPHashUnsupported(err) {
			if res2, err2 := ocspTrySingleHash(ctx, cert, issuer, serverURL, crypto.SHA1); err2 == nil {
				return res2, nil
			} else {
				err = err2
			}
		}
		lastErr = err
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("OCSP fetch failed for all servers")
}

// ocspTrySingleHash executes one full request-response round against
// serverURL using the given CertID hash. Split out of FetchOCSP so the
// SHA-256→SHA-1 fallback is a single retry, not a tangle of
// per-server branches.
func ocspTrySingleHash(ctx context.Context, cert, issuer *x509.Certificate, serverURL string, hash crypto.Hash) (*OCSPResult, error) {
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate OCSP nonce: %w", err)
	}
	reqBytes, err := ocsp.CreateRequest(cert, issuer, &ocsp.RequestOptions{Hash: hash})
	if err != nil {
		return nil, fmt.Errorf("create OCSP request: %w", err)
	}
	reqBytes, err = appendNonceToOCSPRequest(reqBytes, nonce)
	if err != nil {
		return nil, fmt.Errorf("attach OCSP nonce: %w", err)
	}

	var rawResp []byte
	if err := withRetry(ctx, 3, 200*time.Millisecond, func() error {
		r, e := postOCSP(ctx, httpClient10s, serverURL, reqBytes)
		rawResp = r
		return e
	}); err != nil {
		return nil, err
	}

	parsed, err := ocsp.ParseResponse(rawResp, issuer)
	if err != nil {
		return nil, fmt.Errorf("parsing OCSP response from %s: %w", serverURL, err)
	}
	if parsed.Status != ocsp.Good {
		return nil, fmt.Errorf("OCSP status not good (%d) from %s", parsed.Status, serverURL)
	}

	now := time.Now()
	if !parsed.NextUpdate.IsZero() && now.After(parsed.NextUpdate) {
		return nil, fmt.Errorf("OCSP response expired (NextUpdate=%s)", parsed.NextUpdate.Format(time.RFC3339))
	}
	if !parsed.ThisUpdate.IsZero() && now.Sub(parsed.ThisUpdate) > maxOCSPAge {
		return nil, fmt.Errorf("OCSP response too old (ThisUpdate=%s)", parsed.ThisUpdate.Format(time.RFC3339))
	}
	if !parsed.ThisUpdate.IsZero() && parsed.ThisUpdate.After(now.Add(ocspClockSkew)) {
		return nil, fmt.Errorf("OCSP ThisUpdate=%s is in the future (skew>%s)",
			parsed.ThisUpdate.Format(time.RFC3339), ocspClockSkew)
	}
	if err := validateOCSPNonce(parsed, nonce); err != nil {
		return nil, err
	}

	if _, err := classifyOCSPResponder(parsed); err != nil {
		return nil, err
	}

	return &OCSPResult{Response: parsed, RawResponse: rawResp}, nil
}

// classifyOCSPResponder enforces responder authorization per RFC 6960 §4.2.2.2:
//
//   (a) response signed directly by the issuer — parsed.Certificate absent.
//   (b) delegate — parsed.Certificate embedded, must carry id-kp-OCSPSigning
//       EKU. The x/crypto/ocsp parser has already verified the signature
//       against the delegate using its issuer chain; this function only
//       adds the EKU gate that RFC 6960 requires and a nocheck signal.
//   (c) preconfigured trust anchor — out of scope for v1.
//
// id-pkix-ocsp-nocheck (R-4.1.6) on the delegate cert is reported via
// hasNoCheck so a caller can skip the responder's own revocation check.
func classifyOCSPResponder(parsed *ocsp.Response) (hasNoCheck bool, err error) {
	if parsed.Certificate == nil {
		return false, nil
	}
	if !certHasEKU(parsed.Certificate, ocspSigningEKU) {
		return false, fmt.Errorf("OCSP delegate responder lacks id-kp-OCSPSigning EKU")
	}
	return certHasOCSPNoCheck(parsed.Certificate), nil
}

// certHasEKU returns true when cert lists `want` in its ExtKeyUsage
// extension. The stdlib parses EKU OIDs into cert.UnknownExtKeyUsage when
// they're outside the well-known set, so we check both fields.
func certHasEKU(cert *x509.Certificate, want asn1.ObjectIdentifier) bool {
	for _, oid := range cert.UnknownExtKeyUsage {
		if oid.Equal(want) {
			return true
		}
	}
	// Convert the stdlib's enum back to OIDs for comparison.
	for _, ku := range cert.ExtKeyUsage {
		if extKeyUsageToOID(ku).Equal(want) {
			return true
		}
	}
	return false
}

// extKeyUsageToOID maps the stdlib enum to the RFC 5280 OID. Only entries
// relevant to this codebase are listed; others map to nil. Returns the
// package-level OID vars directly so any future rename stays in one place.
func extKeyUsageToOID(ku x509.ExtKeyUsage) asn1.ObjectIdentifier {
	switch ku {
	case x509.ExtKeyUsageOCSPSigning:
		return ocspSigningEKU
	case x509.ExtKeyUsageTimeStamping:
		return oidKPTimeStamping
	}
	return nil
}

// certHasOCSPNoCheck reports whether cert carries the id-pkix-ocsp-nocheck
// extension. Per RFC 6960 §4.2.2.2.1 this is a signal (not a hard gate) —
// the caller decides whether to skip revocation checking of the responder.
func certHasOCSPNoCheck(cert *x509.Certificate) bool {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(ocspNoCheckOID) {
			return true
		}
	}
	return false
}

// isOCSPHashUnsupported detects an "unauthorized" or "malformedRequest"
// response from x/crypto/ocsp's ResponseError. Used only for the
// SHA-256 → SHA-1 one-shot fallback path; a false-positive costs an extra
// round-trip, not correctness.
func isOCSPHashUnsupported(err error) bool {
	if err == nil {
		return false
	}
	var rerr ocsp.ResponseError
	if errors.As(err, &rerr) {
		return rerr.Status == ocsp.Unauthorized || rerr.Status == ocsp.Malformed
	}
	return false
}

// appendNonceToOCSPRequest re-encodes the OCSPRequest DER to add a nonce
// extension. The Go stdlib's CreateRequest does not expose extensions, so we
// patch the encoded structure: OCSPRequest ::= SEQUENCE { tbsRequest, ... }
// where tbsRequest ::= SEQUENCE { version DEFAULT, requestorName?, requestList,
// requestExtensions [2] EXPLICIT Extensions OPTIONAL }.
func appendNonceToOCSPRequest(req, nonce []byte) ([]byte, error) {
	var outer struct {
		TBSRequest      asn1.RawValue
		OptionalSigPart asn1.RawValue `asn1:"optional"`
	}
	rest, err := asn1.Unmarshal(req, &outer)
	if err != nil {
		return nil, fmt.Errorf("decode OCSPRequest: %w", err)
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("trailing bytes in OCSPRequest")
	}

	nonceValue, err := asn1.Marshal(nonce)
	if err != nil {
		return nil, fmt.Errorf("marshal nonce value: %w", err)
	}
	exts := []pkix.Extension{{Id: ocspNonceOID, Value: nonceValue}}
	extsBytes, err := asn1.Marshal(exts)
	if err != nil {
		return nil, fmt.Errorf("marshal extensions: %w", err)
	}
	tagged, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        2,
		IsCompound: true,
		Bytes:      extsBytes,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal [2] extensions wrapper: %w", err)
	}

	tbs := append([]byte{}, outer.TBSRequest.Bytes...)
	tbs = append(tbs, tagged...)

	tbsWrapped, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      tbs,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal tbsRequest: %w", err)
	}

	outerSeq := tbsWrapped
	if len(outer.OptionalSigPart.FullBytes) > 0 {
		outerSeq = append(outerSeq, outer.OptionalSigPart.FullBytes...)
	}
	return asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      outerSeq,
	})
}

// validateOCSPNonce inspects parsed.Extensions for the OCSP nonce OID; if
// present, its wrapped OCTET STRING must equal sent. Absent nonce is treated
// as "not enforced" since many responders strip the extension.
func validateOCSPNonce(parsed *ocsp.Response, sent []byte) error {
	for _, ext := range parsed.Extensions {
		if !ext.Id.Equal(ocspNonceOID) {
			continue
		}
		var got []byte
		if _, err := asn1.Unmarshal(ext.Value, &got); err != nil {
			// Some responders omit the OCTET STRING wrapper and just echo the
			// bytes; try a raw compare as a fallback.
			if subtle.ConstantTimeCompare(ext.Value, sent) == 1 {
				return nil
			}
			return fmt.Errorf("OCSP response nonce extension is not a DER OCTET STRING: %w", err)
		}
		if subtle.ConstantTimeCompare(got, sent) == 1 {
			return nil
		}
		return fmt.Errorf("OCSP response nonce does not match request")
	}
	return nil
}

func postOCSP(ctx context.Context, client *http.Client, url string, body []byte) ([]byte, error) {
	if err := validateFetchURL(url); err != nil {
		return nil, fmt.Errorf("unsafe OCSP URL %s: %w", url, err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/ocsp-request")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("POST to OCSP server %s: %w", url, err)
	}
	defer resp.Body.Close()

	if err := classifyHTTPStatus(resp, url); err != nil {
		return nil, err
	}

	const maxSize = 1 << 20
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxSize))
	if err != nil {
		return nil, fmt.Errorf("reading OCSP response from %s: %w", url, err)
	}
	return raw, nil
}
