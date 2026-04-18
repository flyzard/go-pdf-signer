package pades

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"fmt"

	pdcrypto "github.com/flyzard/pdf-signer/internal/crypto"
)

// TSTokenInfo summarises the trust-relevant outputs of ValidateTSAToken,
// surfaced so callers can render them and fold the TSA cert chain into
// DSS /Certs.
type TSTokenInfo struct {
	SignerCert    *x509.Certificate
	EmbeddedCerts []*x509.Certificate
	TSTInfo       *pdcrypto.TSTInfo
}

// ValidateTSAToken is the full trust check for an RFC 3161 timestamp
// token. Runs on every sign-finish call that asks for B-T or higher.
//
// Steps, in order:
//
//  1. Parse token as CMS SignedData (reuses the existing CMS parser).
//  2. Verify the CMS SignerInfo signature — proves the TSA signed the
//     TSTInfo we're about to trust.
//  3. Extract TSTInfo; match the TSA signer cert from embedded certs.
//  4. Validate messageImprint matches hash(expectedDigest) — stops a
//     malicious TSA from stamping a different document digest than the
//     one we asked to timestamp.
//  5. Chain the TSA signer cert to tsaPool with id-kp-timeStamping EKU
//     enforcement (crypto.ValidateTSACertificate).
//
// The caller passes the digest they fed to the TSA so step (4) can
// bind-check. tsaPool is the split TSA trust pool (certs.TSARoots()).
func ValidateTSAToken(tokenDER []byte, expectedDigest []byte, tsaPool *x509.CertPool) (*TSTokenInfo, error) {
	parsed, err := parseCMS(tokenDER)
	if err != nil {
		return nil, fmt.Errorf("tsa token: parse CMS: %w", err)
	}
	if len(parsed.SignerInfos) != 1 {
		return nil, fmt.Errorf("tsa token: expected 1 SignerInfo, got %d", len(parsed.SignerInfos))
	}
	si := parsed.SignerInfos[0]

	signer, err := si.findSignerCert(parsed.Certificates)
	if err != nil {
		return nil, fmt.Errorf("tsa token: locate signer cert: %w", err)
	}
	if err := si.verifySignature(signer); err != nil {
		return nil, fmt.Errorf("tsa token: CMS signature: %w", err)
	}

	tst, err := pdcrypto.ParseTSTInfoFromToken(tokenDER)
	if err != nil {
		return nil, fmt.Errorf("tsa token: parse TSTInfo: %w", err)
	}

	if len(expectedDigest) > 0 && !bytes.Equal(tst.HashedMessage, expectedDigest) {
		return nil, fmt.Errorf("tsa token: messageImprint does not match requested digest")
	}

	if err := pdcrypto.ValidateTSACertificate(signer, parsed.Certificates, tsaPool, tst.GenTime); err != nil {
		return nil, err
	}

	return &TSTokenInfo{
		SignerCert:    signer,
		EmbeddedCerts: parsed.Certificates,
		TSTInfo:       tst,
	}, nil
}


// FetchSignatureTimestamp asks tsaURL for an RFC 3161 token over
// signatureBytes (the PKCS#1 / ECDSA / Ed25519 signature from the external
// signer), then wraps it as the id-aa-signatureTimeStampToken unsigned
// attribute per RFC 3161 §3.3 / ETSI EN 319 122-1. The returned bytes are
// the [1] IMPLICIT SET OF Attribute wrapper ready to drop into
// SignerInfo.unsignedAttrs.
//
// hashAlg is the digest used for messageImprint (typically SHA-256 to
// match the signer's digestAlgorithm; not mandatory but avoids a
// second-hash round-trip for verifiers).
//
// The returned raw token bytes (the CMS SignedData DER) are also returned
// for callers that need to walk validation data into the DSS.
func FetchSignatureTimestamp(ctx context.Context, tsaURL string, signatureBytes []byte, hashAlg crypto.Hash) (unsignedAttrsDER, tokenDER []byte, err error) {
	if tsaURL == "" {
		return nil, nil, fmt.Errorf("timestamp: TSA URL is empty")
	}
	imprintHash := hashAlg.New()
	imprintHash.Write(signatureBytes)
	digest := imprintHash.Sum(nil)

	// includeNonce=false: several public free TSAs (Sectigo/DigiCert free
	// tier) either do not echo nonces or drop oversize nonces silently,
	// tripping validateTSTInfo's strict echo check. Disabled pending AMA's
	// qualified TSA URL; flip back to true once that TSA is wired.
	reqDER, nonce, err := pdcrypto.BuildTimeStampReq(digest, hashAlg, false, true)
	if err != nil {
		return nil, nil, fmt.Errorf("timestamp: build req: %w", err)
	}
	token, err := pdcrypto.FetchTimeStampToken(ctx, tsaURL, reqDER, nonce)
	if err != nil {
		return nil, nil, fmt.Errorf("timestamp: fetch: %w", err)
	}

	// id-aa-signatureTimeStampToken Attribute ::= SEQUENCE { attrType OID,
	// attrValues SET OF TimeStampToken }. The token itself is the CMS
	// SignedData bytes returned by FetchTimeStampToken.
	attrDER, err := marshalAttributeRaw(oidAttrSigTimeStampToken, token)
	if err != nil {
		return nil, nil, fmt.Errorf("timestamp: wrap attribute: %w", err)
	}
	// unsignedAttrs ::= [1] IMPLICIT SET OF Attribute. SignerInfo body
	// expects the already-tagged bytes.
	unsignedAttrsDER, err = derContextTag(1, attrDER)
	if err != nil {
		return nil, nil, fmt.Errorf("timestamp: wrap unsigned attrs: %w", err)
	}
	return unsignedAttrsDER, token, nil
}
