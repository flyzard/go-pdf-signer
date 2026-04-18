package crypto

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"time"
)

// id-kp-timeStamping EKU OID. Per RFC 3161 §2.3 the TSA signing certificate
// MUST carry this and ONLY this purpose in its ExtendedKeyUsage extension,
// and the extension MUST be critical.
var oidKPTimeStamping = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 8}
var oidExtKeyUsage = asn1.ObjectIdentifier{2, 5, 29, 37}

// ValidateTSACertificate enforces the signer-side invariants an RFC 3161
// client MUST check before trusting a timestamp token. The token's
// embedded signer certificate must:
//
//  1. Carry id-kp-timeStamping in its ExtendedKeyUsage.
//  2. Have the EKU extension marked critical (RFC 3161 §2.3).
//  3. Chain to a root in the tsaPool (not the signer pool — they are
//     separately maintained to prevent a TSA root from being mistaken for
//     a signer anchor and vice-versa).
//  4. Have a validity window that includes `at` (typically the token's
//     genTime so the chain is checked at the claimed signing moment).
//
// Intermediates must be supplied via intermediates; callers that fetched
// them from the token's `certificates` set pass those in directly.
func ValidateTSACertificate(tsaCert *x509.Certificate, intermediates []*x509.Certificate, tsaPool *x509.CertPool, at time.Time) error {
	if tsaCert == nil {
		return fmt.Errorf("tsa trust: nil cert")
	}
	if err := enforceTimeStampingEKU(tsaCert); err != nil {
		return err
	}

	intermediatePool := x509.NewCertPool()
	for _, c := range intermediates {
		if c != nil && !c.Equal(tsaCert) {
			intermediatePool.AddCert(c)
		}
	}
	opts := x509.VerifyOptions{
		Roots:         tsaPool,
		Intermediates: intermediatePool,
		CurrentTime:   at,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
	}
	if _, err := tsaCert.Verify(opts); err != nil {
		return fmt.Errorf("tsa trust: chain: %w", err)
	}
	return nil
}

// enforceTimeStampingEKU walks the cert's EKU extension and refuses any
// shape that doesn't match RFC 3161 §2.3: extension MUST be present,
// critical, and contain EXACTLY one KeyPurposeId = id-kp-timeStamping.
func enforceTimeStampingEKU(cert *x509.Certificate) error {
	var ekuExt *pkix.Extension
	for i := range cert.Extensions {
		if cert.Extensions[i].Id.Equal(oidExtKeyUsage) {
			ekuExt = &cert.Extensions[i]
			break
		}
	}
	if ekuExt == nil {
		return fmt.Errorf("tsa trust: no ExtKeyUsage extension")
	}
	if !ekuExt.Critical {
		return fmt.Errorf("tsa trust: ExtKeyUsage must be critical (RFC 3161 §2.3)")
	}
	var oids []asn1.ObjectIdentifier
	if _, err := asn1.Unmarshal(ekuExt.Value, &oids); err != nil {
		return fmt.Errorf("tsa trust: parse EKU: %w", err)
	}
	if len(oids) != 1 || !oids[0].Equal(oidKPTimeStamping) {
		return fmt.Errorf("tsa trust: ExtKeyUsage must contain exactly id-kp-timeStamping, got %v", oids)
	}
	return nil
}
