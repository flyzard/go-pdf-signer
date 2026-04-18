package pades

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
)

// ESS helpers (RFC 5035 — the signing-certificate-v2 attribute).
//
// The attribute value binds the CMS signature to a specific signer
// certificate by carrying H(cert) + IssuerSerial. A verifier that honours
// the binding rejects any attempt to swap the cert in the CMS
// `certificates` set for a different one signed by the same key.
//
// Structure:
//
//   SigningCertificateV2 ::= SEQUENCE {
//       certs     SEQUENCE OF ESSCertIDv2,
//       policies  SEQUENCE OF PolicyInformation OPTIONAL  -- omitted here
//   }
//
//   ESSCertIDv2 ::= SEQUENCE {
//       hashAlgorithm  AlgorithmIdentifier DEFAULT id-sha256,
//       certHash       OCTET STRING,
//       issuerSerial   IssuerSerial OPTIONAL
//   }
//
//   IssuerSerial ::= SEQUENCE {
//       issuer        GeneralNames,
//       serialNumber  CertificateSerialNumber
//   }

// ESS CertIDv2 builder. Emits a DER SEQUENCE ready to drop into the SET OF
// AttributeValue for the signingCertificateV2 attribute. The HashAlgorithm
// field is omitted when using SHA-256 (DER DEFAULT rule) — Acrobat and EU
// DSS are strict about this and reject the same bytes in explicit form.
func buildESSCertIDv2(cert *x509.Certificate, hashAlg crypto.Hash) ([]byte, error) {
	if cert == nil {
		return nil, fmt.Errorf("ess: cert is nil")
	}
	if cert.SerialNumber == nil {
		return nil, fmt.Errorf("ess: cert has no serial number")
	}

	// certHash over cert.Raw (the to-be-signed-plus-signature bytes — i.e.
	// the full DER the verifier will fingerprint, matching what Adobe's
	// implementation does).
	h := hashAlg.New()
	h.Write(cert.Raw)
	certHash := h.Sum(nil)

	var content []byte

	if hashAlg != crypto.SHA256 {
		oid, err := oidForDigest(hashAlg)
		if err != nil {
			return nil, err
		}
		algDER, err := asn1.Marshal(pkix.AlgorithmIdentifier{Algorithm: oid})
		if err != nil {
			return nil, fmt.Errorf("ess: marshal hashAlgorithm: %w", err)
		}
		content = append(content, algDER...)
	}

	hashDER, err := asn1.Marshal(certHash)
	if err != nil {
		return nil, fmt.Errorf("ess: marshal certHash: %w", err)
	}
	content = append(content, hashDER...)

	issuerSerialDER, err := buildIssuerSerial(cert)
	if err != nil {
		return nil, err
	}
	content = append(content, issuerSerialDER...)

	return derSEQ(content)
}

// buildSigningCertificateV2Attr wraps a single ESSCertIDv2 in the outer
// SigningCertificateV2 SEQUENCE. We emit exactly one entry (the signer
// leaf); callers needing multi-cert binding would extend the inner slice.
func buildSigningCertificateV2Attr(cert *x509.Certificate, hashAlg crypto.Hash) ([]byte, error) {
	essDER, err := buildESSCertIDv2(cert, hashAlg)
	if err != nil {
		return nil, err
	}
	certsSeq, err := derSEQ(essDER)
	if err != nil {
		return nil, fmt.Errorf("ess: certs SEQUENCE OF: %w", err)
	}
	return derSEQ(certsSeq)
}

// buildIssuerSerial emits the IssuerSerial SEQUENCE (directoryName-only
// GeneralNames + serialNumber). Uses cert.RawIssuer verbatim so the bytes
// match Acrobat's fingerprint calculation.
func buildIssuerSerial(cert *x509.Certificate) ([]byte, error) {
	gnDER, err := derContextTag(4, cert.RawIssuer)
	if err != nil {
		return nil, fmt.Errorf("ess: directoryName: %w", err)
	}
	gnsDER, err := derSEQ(gnDER)
	if err != nil {
		return nil, fmt.Errorf("ess: GeneralNames: %w", err)
	}
	serialDER, err := asn1.Marshal(cert.SerialNumber)
	if err != nil {
		return nil, fmt.Errorf("ess: serialNumber: %w", err)
	}
	return derSEQ(append(gnsDER, serialDER...))
}

// ValidateESSBinding enforces the signing-certificate-v2 binding on verify:
// the cert's hash must equal the ESSCertIDv2 certHash, and the issuer/
// serial must match the supplied cert. Missing-attribute is accepted (the
// caller sets a different gate for mandatory-presence) so this function
// only returns an error when an attribute is present but does not bind.
func ValidateESSBinding(si *cmsSignerInfo, cert *x509.Certificate) error {
	if si == nil || cert == nil {
		return fmt.Errorf("ess binding: nil input")
	}
	a := si.findAttr(oidAttrSigningCertV2)
	if a == nil {
		// Presence is enforced elsewhere; a missing attribute is not this
		// gate's concern.
		return nil
	}
	if len(a.Values) != 1 {
		return fmt.Errorf("ess binding: signingCertificateV2 has %d values, want 1", len(a.Values))
	}

	var scv2 struct {
		Certs    asn1.RawValue
		Policies asn1.RawValue `asn1:"optional"`
	}
	if _, err := asn1.Unmarshal(a.Values[0].FullBytes, &scv2); err != nil {
		return fmt.Errorf("ess binding: decode SigningCertificateV2: %w", err)
	}
	essRaw := scv2.Certs.Bytes
	if len(essRaw) == 0 {
		return fmt.Errorf("ess binding: certs SEQUENCE OF is empty")
	}
	// Walk the SEQUENCE OF; find the entry that matches this cert and require
	// a binding-level match. Older emitters sometimes pre-pend cross-issuer
	// certs so we can't blindly assume the first entry is the leaf.
	for len(essRaw) > 0 {
		var raw asn1.RawValue
		rest, err := asn1.Unmarshal(essRaw, &raw)
		if err != nil {
			return fmt.Errorf("ess binding: decode ESSCertIDv2: %w", err)
		}
		essRaw = rest
		if err := matchESSCertIDv2(raw.Bytes, cert); err == nil {
			return nil
		}
	}
	return fmt.Errorf("ess binding: no ESSCertIDv2 entry matches signer certificate")
}

// matchESSCertIDv2 parses one ESSCertIDv2 and checks its certHash (over the
// caller-declared hash algorithm) and IssuerSerial against cert. Returns
// nil on match, a descriptive error otherwise.
func matchESSCertIDv2(body []byte, cert *x509.Certificate) error {
	// Peek the first element: AlgorithmIdentifier (SEQUENCE, universal) or
	// certHash (OCTET STRING). DER default rule omits AlgorithmIdentifier
	// when SHA-256.
	hashAlg := crypto.SHA256
	rest := body

	var first asn1.RawValue
	next, err := asn1.Unmarshal(rest, &first)
	if err != nil {
		return fmt.Errorf("parse first element: %w", err)
	}
	if first.Class == asn1.ClassUniversal && first.Tag == asn1.TagSequence {
		var algID pkix.AlgorithmIdentifier
		if _, err := asn1.Unmarshal(first.FullBytes, &algID); err != nil {
			return fmt.Errorf("parse hashAlgorithm: %w", err)
		}
		h, err := digestForOID(algID.Algorithm)
		if err != nil {
			return err
		}
		hashAlg = h
		rest = next
	}

	var certHash []byte
	next, err = asn1.Unmarshal(rest, &certHash)
	if err != nil {
		return fmt.Errorf("parse certHash: %w", err)
	}
	rest = next

	h := hashAlg.New()
	h.Write(cert.Raw)
	want := h.Sum(nil)
	if len(certHash) != len(want) {
		return fmt.Errorf("certHash length mismatch")
	}
	for i := range want {
		if certHash[i] != want[i] {
			return fmt.Errorf("certHash does not match signer certificate")
		}
	}

	// IssuerSerial is OPTIONAL but ETSI profiles require it. If present,
	// it must identify the signer.
	if len(rest) > 0 {
		var is struct {
			Issuer       asn1.RawValue
			SerialNumber *big.Int
		}
		if _, err := asn1.Unmarshal(rest, &is); err != nil {
			return fmt.Errorf("parse IssuerSerial: %w", err)
		}
		if is.SerialNumber == nil || cert.SerialNumber == nil {
			return fmt.Errorf("IssuerSerial serial missing")
		}
		if is.SerialNumber.Cmp(cert.SerialNumber) != 0 {
			return fmt.Errorf("IssuerSerial serial does not match")
		}
		// Compare issuer DNs via DER bytes. GeneralNames (SEQUENCE OF
		// GeneralName) is is.Issuer.Bytes; we find the [4] EXPLICIT entry
		// and compare its inner Name to cert.RawIssuer.
		if !issuerMatches(is.Issuer.Bytes, cert.RawIssuer) {
			return fmt.Errorf("IssuerSerial issuer does not match")
		}
	}
	return nil
}

// issuerMatches walks a GeneralNames DER blob and returns true iff any
// directoryName [4] entry equals target (a DER Name, e.g. cert.RawIssuer).
func issuerMatches(gnsBytes, target []byte) bool {
	rest := gnsBytes
	for len(rest) > 0 {
		var gn asn1.RawValue
		next, err := asn1.Unmarshal(rest, &gn)
		if err != nil {
			return false
		}
		rest = next
		if gn.Class == asn1.ClassContextSpecific && gn.Tag == 4 && gn.IsCompound {
			if bytes.Equal(gn.Bytes, target) {
				return true
			}
		}
	}
	return false
}

