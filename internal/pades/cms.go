package pades

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
)

// OIDs used by CMS SignedData and by the signed attributes we validate.
var (
	oidContentTypeData       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidContentTypeSignedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}

	oidAttrContentType        = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidAttrMessageDigest      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	oidAttrSigningTime        = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}
	oidAttrSigningCertV2      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 47} // RFC 5035 signingCertificateV2
	oidAttrSigPolicyID        = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 15} // ETSI signature-policy-identifier
	oidAttrCommitmentType     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 16} // ETSI commitment-type-indication
	oidAttrSigTimeStampToken  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 14} // RFC 3161 id-aa-signatureTimeStampToken

	oidDigestSHA1   = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	oidDigestSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidDigestSHA384 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	oidDigestSHA512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}

	oidRSAEncryption   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidRSASSAPSS       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10}
	oidSHA256WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	oidSHA384WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}
	oidSHA512WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}
	oidECPublicKey     = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
	oidECDSAWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	oidECDSAWithSHA384 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	oidECDSAWithSHA512 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}
	oidEd25519         = asn1.ObjectIdentifier{1, 3, 101, 112}

	oidMGF1 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 8}
)

// oidForDigest maps a supported hash to its OID for emission inside CMS
// structures (messageDigest and signingCertificateV2 hashAlgorithm).
// SHA-1 is deliberately absent — it is refused on both sides.
func oidForDigest(h crypto.Hash) (asn1.ObjectIdentifier, error) {
	switch h {
	case crypto.SHA256:
		return oidDigestSHA256, nil
	case crypto.SHA384:
		return oidDigestSHA384, nil
	case crypto.SHA512:
		return oidDigestSHA512, nil
	}
	return nil, fmt.Errorf("unsupported digest %v", h)
}

// digestForOID is the inverse of oidForDigest.
func digestForOID(oid asn1.ObjectIdentifier) (crypto.Hash, error) {
	switch {
	case oid.Equal(oidDigestSHA256):
		return crypto.SHA256, nil
	case oid.Equal(oidDigestSHA384):
		return crypto.SHA384, nil
	case oid.Equal(oidDigestSHA512):
		return crypto.SHA512, nil
	case oid.Equal(oidDigestSHA1):
		return 0, fmt.Errorf("SHA-1 digest refused")
	}
	return 0, fmt.Errorf("unsupported digest OID %v", oid)
}

// cmsAttribute is one Attribute ::= SEQUENCE { attrType OID, attrValues SET OF ANY }.
type cmsAttribute struct {
	Type   asn1.ObjectIdentifier
	Values []asn1.RawValue `asn1:"set"`
}

// cmsSignerInfo is the parsed SignerInfo of a CMS SignedData, with enough
// context kept around to verify the signature later.
type cmsSignerInfo struct {
	Version         int
	IssuerDER       []byte // raw DER of the issuer Name inside IssuerAndSerialNumber
	SerialNumber    *big.Int
	ski             []byte // subjectKeyIdentifier when the sid uses the [0] variant
	DigestAlgorithm asn1.ObjectIdentifier
	SignedAttrs     []cmsAttribute
	signedAttrsRaw  []byte // full TLV with original [0] IMPLICIT tag; signing input flips tag to SET
	SigAlgorithm    asn1.ObjectIdentifier
	Signature       []byte
}

// parsedCMS is the slice of things the verifier consumes out of a CMS blob.
type parsedCMS struct {
	Certificates []*x509.Certificate
	SignerInfos  []*cmsSignerInfo
	// DigestAlgorithmOIDs is the contents of SignedData.digestAlgorithms.
	// The HashAlgConsistency gate checks that each SignerInfo.digestAlgorithm
	// appears here (RFC 5652 §5.1). A mismatch is a known substitution vector.
	DigestAlgorithmOIDs []asn1.ObjectIdentifier
}

// parseCMS decodes a DER-encoded CMS SignedData ContentInfo, returning its
// embedded certificates and signer infos. Errors are returned for any
// structural malformation — callers can treat a parse error as a signature
// verification failure.
func parseCMS(der []byte) (*parsedCMS, error) {
	var ci struct {
		ContentType asn1.ObjectIdentifier
		Content     asn1.RawValue `asn1:"explicit,tag:0"`
	}
	if _, err := asn1.Unmarshal(der, &ci); err != nil {
		return nil, fmt.Errorf("cms: parse ContentInfo: %w", err)
	}
	if !ci.ContentType.Equal(oidContentTypeSignedData) {
		return nil, fmt.Errorf("cms: outer ContentType is %v, want signedData", ci.ContentType)
	}

	// SignedData ::= SEQUENCE { … }
	var sd asn1.RawValue
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		return nil, fmt.Errorf("cms: parse SignedData outer: %w", err)
	}
	if sd.Class != asn1.ClassUniversal || sd.Tag != asn1.TagSequence {
		return nil, fmt.Errorf("cms: SignedData not a SEQUENCE")
	}
	remaining := sd.Bytes

	// version
	var version int
	var err error
	if remaining, err = asn1.Unmarshal(remaining, &version); err != nil {
		return nil, fmt.Errorf("cms: version: %w", err)
	}

	// digestAlgorithms SET OF AlgorithmIdentifier. Parse every entry so
	// the HashAlgConsistency gate can cross-check against SignerInfo.
	var digestAlgos asn1.RawValue
	if remaining, err = asn1.Unmarshal(remaining, &digestAlgos); err != nil {
		return nil, fmt.Errorf("cms: digestAlgorithms: %w", err)
	}
	digestOIDs, err := parseDigestAlgorithms(digestAlgos.Bytes)
	if err != nil {
		return nil, fmt.Errorf("cms: parse digestAlgorithms: %w", err)
	}

	// encapContentInfo SEQUENCE
	var encap asn1.RawValue
	if remaining, err = asn1.Unmarshal(remaining, &encap); err != nil {
		return nil, fmt.Errorf("cms: encapContentInfo: %w", err)
	}

	// Optional [0] IMPLICIT certificates SET OF Certificate.
	var certs []*x509.Certificate
	if len(remaining) > 0 && isContextTag(remaining, 0) {
		var certsRaw asn1.RawValue
		if remaining, err = asn1.Unmarshal(remaining, &certsRaw); err != nil {
			return nil, fmt.Errorf("cms: certificates: %w", err)
		}
		certs, err = parseCertsField(certsRaw.Bytes)
		if err != nil {
			return nil, fmt.Errorf("cms: parse certificates: %w", err)
		}
	}

	// Optional [1] IMPLICIT crls — skip over if present.
	if len(remaining) > 0 && isContextTag(remaining, 1) {
		var crls asn1.RawValue
		if remaining, err = asn1.Unmarshal(remaining, &crls); err != nil {
			return nil, fmt.Errorf("cms: crls: %w", err)
		}
	}

	// signerInfos SET OF SignerInfo.
	var signerInfosRaw asn1.RawValue
	if _, err = asn1.Unmarshal(remaining, &signerInfosRaw); err != nil {
		return nil, fmt.Errorf("cms: signerInfos: %w", err)
	}
	if signerInfosRaw.Class != asn1.ClassUniversal || signerInfosRaw.Tag != asn1.TagSet {
		return nil, fmt.Errorf("cms: signerInfos is not a SET (class=%d tag=%d)",
			signerInfosRaw.Class, signerInfosRaw.Tag)
	}

	signers, err := parseSignerInfos(signerInfosRaw.Bytes)
	if err != nil {
		return nil, fmt.Errorf("cms: parse signerInfos: %w", err)
	}

	return &parsedCMS{Certificates: certs, SignerInfos: signers, DigestAlgorithmOIDs: digestOIDs}, nil
}

// parseDigestAlgorithms walks a SET OF AlgorithmIdentifier body and returns
// the embedded OIDs. Duplicates are preserved — the caller may want to
// detect them and refuse.
func parseDigestAlgorithms(body []byte) ([]asn1.ObjectIdentifier, error) {
	var out []asn1.ObjectIdentifier
	rest := body
	for len(rest) > 0 {
		var alg pkix.AlgorithmIdentifier
		next, err := asn1.Unmarshal(rest, &alg)
		if err != nil {
			return nil, err
		}
		rest = next
		out = append(out, alg.Algorithm)
	}
	return out, nil
}

// HashAlgConsistency enforces two invariants that block known substitution
// attacks on CMS signatures:
//
//  1. SignerInfo.digestAlgorithm MUST appear in SignedData.digestAlgorithms.
//     Otherwise an attacker can swap the stronger outer algorithm for a
//     weaker one without perturbing the already-signed digest.
//  2. The messageDigest attribute length MUST match the digest algorithm's
//     output size. A 32-byte messageDigest with digestAlgorithm=SHA-512
//     (64 bytes) is a malformed blob that some verifiers quietly accept.
//
// Returns nil on success; a descriptive error otherwise.
func HashAlgConsistency(p *parsedCMS, si *cmsSignerInfo) error {
	if p == nil || si == nil {
		return fmt.Errorf("hash-alg consistency: nil input")
	}
	if len(p.DigestAlgorithmOIDs) == 0 {
		return fmt.Errorf("hash-alg consistency: SignedData.digestAlgorithms empty")
	}
	found := false
	for _, oid := range p.DigestAlgorithmOIDs {
		if oid.Equal(si.DigestAlgorithm) {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("hash-alg consistency: SignerInfo digest %v not in SignedData digestAlgorithms", si.DigestAlgorithm)
	}
	md, err := si.MessageDigest()
	if err != nil {
		return fmt.Errorf("hash-alg consistency: %w", err)
	}
	hf, err := si.digestHash()
	if err != nil {
		return fmt.Errorf("hash-alg consistency: %w", err)
	}
	if len(md) != hf.Size() {
		return fmt.Errorf("hash-alg consistency: messageDigest length %d does not match %v (%d)",
			len(md), hf, hf.Size())
	}
	return nil
}

// isContextTag reports whether the next ASN.1 element in buf is a
// context-specific tag with the given number.
func isContextTag(buf []byte, tag int) bool {
	if len(buf) == 0 {
		return false
	}
	b := buf[0]
	class := (b & 0xC0) >> 6
	t := int(b & 0x1F)
	return class == 2 && t == tag
}

func parseCertsField(buf []byte) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	for len(buf) > 0 {
		var raw asn1.RawValue
		rest, err := asn1.Unmarshal(buf, &raw)
		if err != nil {
			return nil, err
		}
		// Only parse universal SEQUENCE entries as certificates; the CMS
		// certificates field can also hold attribute certificates ([1] IMPLICIT)
		// and other choices — skip those.
		if raw.Class == asn1.ClassUniversal && raw.Tag == asn1.TagSequence {
			cert, err := x509.ParseCertificate(raw.FullBytes)
			if err == nil {
				out = append(out, cert)
			}
		}
		buf = rest
	}
	return out, nil
}

func parseSignerInfos(buf []byte) ([]*cmsSignerInfo, error) {
	var out []*cmsSignerInfo
	for len(buf) > 0 {
		var raw asn1.RawValue
		rest, err := asn1.Unmarshal(buf, &raw)
		if err != nil {
			return nil, err
		}
		si, err := parseOneSignerInfo(raw.Bytes)
		if err != nil {
			return nil, err
		}
		out = append(out, si)
		buf = rest
	}
	return out, nil
}

func parseOneSignerInfo(body []byte) (*cmsSignerInfo, error) {
	si := &cmsSignerInfo{}
	var err error

	// version
	if body, err = asn1.Unmarshal(body, &si.Version); err != nil {
		return nil, fmt.Errorf("signerInfo version: %w", err)
	}

	// sid — IssuerAndSerialNumber (SEQUENCE) or SubjectKeyIdentifier ([0] OCTET STRING).
	var sid asn1.RawValue
	if body, err = asn1.Unmarshal(body, &sid); err != nil {
		return nil, fmt.Errorf("signerInfo sid: %w", err)
	}
	switch {
	case sid.Class == asn1.ClassUniversal && sid.Tag == asn1.TagSequence:
		// IssuerAndSerialNumber ::= SEQUENCE { issuer Name, serialNumber INTEGER }
		var ias struct {
			Issuer       asn1.RawValue
			SerialNumber *big.Int
		}
		if _, err := asn1.Unmarshal(sid.FullBytes, &ias); err != nil {
			return nil, fmt.Errorf("signerInfo IssuerAndSerialNumber: %w", err)
		}
		si.IssuerDER = ias.Issuer.FullBytes
		si.SerialNumber = ias.SerialNumber
	case sid.Class == asn1.ClassContextSpecific && sid.Tag == 0:
		// SubjectKeyIdentifier variant — we only record the SKI bytes and will
		// match by SKI later. sid.Bytes holds the SKI OCTET STRING contents.
		si.IssuerDER = nil
		si.SerialNumber = nil
		// Stash SKI inside SerialNumber bytes? Cleaner to add a field; use a
		// dedicated field.
		si.ski = append([]byte{}, sid.Bytes...)
	default:
		return nil, fmt.Errorf("signerInfo sid has unexpected tag class=%d tag=%d", sid.Class, sid.Tag)
	}

	// digestAlgorithm
	var digestAlgo pkix.AlgorithmIdentifier
	if body, err = asn1.Unmarshal(body, &digestAlgo); err != nil {
		return nil, fmt.Errorf("signerInfo digestAlgorithm: %w", err)
	}
	si.DigestAlgorithm = digestAlgo.Algorithm

	// Optional signedAttrs [0] IMPLICIT SET OF Attribute.
	if len(body) > 0 && isContextTag(body, 0) {
		var rawAttrs asn1.RawValue
		if body, err = asn1.Unmarshal(body, &rawAttrs); err != nil {
			return nil, fmt.Errorf("signerInfo signedAttrs: %w", err)
		}
		si.signedAttrsRaw = append([]byte{}, rawAttrs.FullBytes...)

		// Walk the SET contents element-by-element. Each Attribute is a
		// SEQUENCE, so the default UNIVERSAL-SEQUENCE decoding is correct.
		attrsBuf := rawAttrs.Bytes
		for len(attrsBuf) > 0 {
			var one cmsAttribute
			rest, err := asn1.Unmarshal(attrsBuf, &one)
			if err != nil {
				return nil, fmt.Errorf("signerInfo signedAttrs item: %w", err)
			}
			si.SignedAttrs = append(si.SignedAttrs, one)
			attrsBuf = rest
		}
	}

	// signatureAlgorithm
	var sigAlgo pkix.AlgorithmIdentifier
	if body, err = asn1.Unmarshal(body, &sigAlgo); err != nil {
		return nil, fmt.Errorf("signerInfo signatureAlgorithm: %w", err)
	}
	si.SigAlgorithm = sigAlgo.Algorithm

	// signature OCTET STRING
	var sig []byte
	if _, err = asn1.Unmarshal(body, &sig); err != nil {
		return nil, fmt.Errorf("signerInfo signature: %w", err)
	}
	si.Signature = sig
	return si, nil
}

// ski holds the SubjectKeyIdentifier when the SignerInfo sid uses that variant.
// Stored outside the exported field set to keep the parsed struct visually
// dominated by the common IssuerAndSerial case.
func (si *cmsSignerInfo) SubjectKeyID() []byte { return si.ski }

// -- attribute lookup -------------------------------------------------------

// findAttr returns the first attribute with the given OID, or nil.
func (si *cmsSignerInfo) findAttr(oid asn1.ObjectIdentifier) *cmsAttribute {
	for i := range si.SignedAttrs {
		if si.SignedAttrs[i].Type.Equal(oid) {
			return &si.SignedAttrs[i]
		}
	}
	return nil
}

// MessageDigest returns the messageDigest signed attribute value (the hash the
// signer committed to). It enforces that the attribute is present and holds
// exactly one OCTET STRING.
func (si *cmsSignerInfo) MessageDigest() ([]byte, error) {
	a := si.findAttr(oidAttrMessageDigest)
	if a == nil {
		return nil, errors.New("messageDigest attribute missing")
	}
	if len(a.Values) != 1 {
		return nil, fmt.Errorf("messageDigest attribute has %d values, want 1", len(a.Values))
	}
	var out []byte
	if _, err := asn1.Unmarshal(a.Values[0].FullBytes, &out); err != nil {
		return nil, fmt.Errorf("decode messageDigest: %w", err)
	}
	return out, nil
}

// ContentType returns the contentType signed attribute OID.
func (si *cmsSignerInfo) ContentType() (asn1.ObjectIdentifier, error) {
	a := si.findAttr(oidAttrContentType)
	if a == nil {
		return nil, errors.New("contentType attribute missing")
	}
	if len(a.Values) != 1 {
		return nil, fmt.Errorf("contentType attribute has %d values, want 1", len(a.Values))
	}
	var out asn1.ObjectIdentifier
	if _, err := asn1.Unmarshal(a.Values[0].FullBytes, &out); err != nil {
		return nil, fmt.Errorf("decode contentType: %w", err)
	}
	return out, nil
}

// signedAttrsForSigning returns the DER encoding of signedAttrs with the
// outer tag set to UNIVERSAL SET (0x31) instead of [0] IMPLICIT (0xA0). Per
// RFC 5652 §5.4, this is the exact byte sequence the signature is computed
// over when signedAttrs is present.
func (si *cmsSignerInfo) signedAttrsForSigning() ([]byte, error) {
	if len(si.signedAttrsRaw) == 0 {
		return nil, errors.New("signerInfo has no signedAttrs — signature-over-content not supported")
	}
	out := append([]byte{}, si.signedAttrsRaw...)
	out[0] = 0x31
	return out, nil
}

// digestHash returns the Go crypto.Hash that matches the signerInfo's
// digestAlgorithm OID.
func (si *cmsSignerInfo) digestHash() (crypto.Hash, error) {
	switch {
	case si.DigestAlgorithm.Equal(oidDigestSHA256):
		return crypto.SHA256, nil
	case si.DigestAlgorithm.Equal(oidDigestSHA384):
		return crypto.SHA384, nil
	case si.DigestAlgorithm.Equal(oidDigestSHA512):
		return crypto.SHA512, nil
	case si.DigestAlgorithm.Equal(oidDigestSHA1):
		// SHA-1 is cryptographically broken; refuse rather than accept.
		return 0, errors.New("SHA-1 digest rejected")
	}
	return 0, fmt.Errorf("unsupported digest OID %v", si.DigestAlgorithm)
}

// -- signer matching --------------------------------------------------------

// findSignerCert locates the certificate in certs that matches this SignerInfo's
// sid (IssuerAndSerial, or SKI).
func (si *cmsSignerInfo) findSignerCert(certs []*x509.Certificate) (*x509.Certificate, error) {
	if len(si.ski) > 0 {
		for _, c := range certs {
			if len(c.SubjectKeyId) > 0 && bytes.Equal(c.SubjectKeyId, si.ski) {
				return c, nil
			}
		}
		return nil, errors.New("no certificate matches signerInfo SubjectKeyIdentifier")
	}
	if si.IssuerDER == nil || si.SerialNumber == nil {
		return nil, errors.New("signerInfo has no sid")
	}
	for _, c := range certs {
		if bytes.Equal(c.RawIssuer, si.IssuerDER) && c.SerialNumber != nil && c.SerialNumber.Cmp(si.SerialNumber) == 0 {
			return c, nil
		}
	}
	return nil, errors.New("no certificate matches signerInfo IssuerAndSerialNumber")
}

// -- signature verification -------------------------------------------------

// verifySignature checks si.Signature against cert's public key using si's
// signatureAlgorithm and digestAlgorithm. The input to the signature is
// signedAttrs-as-SET if signedAttrs is present; otherwise the raw content
// is signed (not supported here; signers must use signedAttrs).
func (si *cmsSignerInfo) verifySignature(cert *x509.Certificate) error {
	input, err := si.signedAttrsForSigning()
	if err != nil {
		return err
	}
	hash, err := si.digestHash()
	if err != nil {
		return err
	}
	h := hash.New()
	h.Write(input)
	digest := h.Sum(nil)

	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		// RSASSA-PSS carries its own parameters and is a separate code path.
		if si.SigAlgorithm.Equal(oidRSASSAPSS) {
			return rsa.VerifyPSS(pub, hash, digest, si.Signature, &rsa.PSSOptions{
				SaltLength: rsa.PSSSaltLengthEqualsHash,
				Hash:       hash,
			})
		}
		// Accept rsaEncryption (legacy) or sha{256,384,512}WithRSAEncryption.
		if !si.SigAlgorithm.Equal(oidRSAEncryption) &&
			!si.SigAlgorithm.Equal(oidSHA256WithRSA) &&
			!si.SigAlgorithm.Equal(oidSHA384WithRSA) &&
			!si.SigAlgorithm.Equal(oidSHA512WithRSA) {
			return fmt.Errorf("signature algorithm %v not supported with RSA key", si.SigAlgorithm)
		}
		return rsa.VerifyPKCS1v15(pub, hash, digest, si.Signature)
	case *ecdsa.PublicKey:
		if !si.SigAlgorithm.Equal(oidECPublicKey) &&
			!si.SigAlgorithm.Equal(oidECDSAWithSHA256) &&
			!si.SigAlgorithm.Equal(oidECDSAWithSHA384) &&
			!si.SigAlgorithm.Equal(oidECDSAWithSHA512) {
			return fmt.Errorf("signature algorithm %v not supported with ECDSA key", si.SigAlgorithm)
		}
		if ecdsa.VerifyASN1(pub, digest, si.Signature) {
			return nil
		}
		return errors.New("ECDSA signature check failed")
	case ed25519.PublicKey:
		if !si.SigAlgorithm.Equal(oidEd25519) {
			return fmt.Errorf("signature algorithm %v not supported with Ed25519 key", si.SigAlgorithm)
		}
		// Ed25519 signs the raw input, not a pre-hashed digest. The stdlib
		// ignores the `hash` arg for ed25519 but we still pass input (not
		// digest) because ed25519.Verify operates on the message directly.
		if ed25519.Verify(pub, input, si.Signature) {
			return nil
		}
		return errors.New("Ed25519 signature check failed")
	}
	return fmt.Errorf("unsupported public key type %T", cert.PublicKey)
}
