package pades

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"sort"
	"time"
)

// BuildSignedAttrsOptions controls which optional signed attributes are
// included. contentHints / contentTimeStamp are out of scope for v1.
type BuildSignedAttrsOptions struct {
	// DigestAlgorithm is the hash used for both messageDigest and for
	// hashing the signedAttrs-as-SET that the external signer consumes.
	// Defaults to crypto.SHA256.
	DigestAlgorithm crypto.Hash

	// SigningTime stamps the attribute. Zero time → omit signingTime
	// (it's optional per RFC 5652).
	SigningTime time.Time

	// SignaturePolicyOID, when non-nil, emits a signature-policy-identifier
	// attribute with an explicit policy reference. Portuguese public-sector
	// signing may require a specific OID — wire once AMA confirms.
	SignaturePolicyOID asn1.ObjectIdentifier

	// CommitmentTypeOID, when non-nil, emits a commitment-type-indication
	// attribute (e.g. proofOfOrigin / proofOfApproval). Leave nil unless
	// the calling service has a policy reason to set it.
	CommitmentTypeOID asn1.ObjectIdentifier
}

// BuildSignedAttrs composes the CMS signedAttributes SET for a PAdES
// signature. Returns (signedAttrsDER, hashToSign):
//
//   - signedAttrsDER is the DER encoding with the outer [0] IMPLICIT tag,
//     ready to embed verbatim in SignerInfo.signedAttrs.
//   - hashToSign is the digest an external signer (AMA SCMDSign,
//     HSM, local key) consumes. It is computed over the same bytes but
//     with the outer tag rewritten to universal SET (0x31) per RFC 5652
//     §5.4 — this is the part of the protocol that historically trips up
//     hand-rolled ASN.1 and is why ValidateESSBinding is wired as a gate
//     on verify.
//
// docDigest is the SHA-256 (or requested digest) of the PDF ByteRange —
// the messageDigest attribute.
func BuildSignedAttrs(docDigest []byte, cert *x509.Certificate, opts BuildSignedAttrsOptions) (signedAttrs, hashToSign []byte, err error) {
	if cert == nil {
		return nil, nil, fmt.Errorf("cms builder: signer cert is nil")
	}
	hashAlg := opts.DigestAlgorithm
	if hashAlg == 0 {
		hashAlg = crypto.SHA256
	}
	if len(docDigest) != hashAlg.Size() {
		return nil, nil, fmt.Errorf("cms builder: docDigest length %d does not match digest alg %v (size %d)",
			len(docDigest), hashAlg, hashAlg.Size())
	}

	var attrs [][]byte

	ctDER, err := marshalAttribute(oidAttrContentType, oidContentTypeData)
	if err != nil {
		return nil, nil, err
	}
	attrs = append(attrs, ctDER)

	mdDER, err := marshalAttribute(oidAttrMessageDigest, docDigest)
	if err != nil {
		return nil, nil, err
	}
	attrs = append(attrs, mdDER)

	scv2Value, err := buildSigningCertificateV2Attr(cert, hashAlg)
	if err != nil {
		return nil, nil, err
	}
	scv2DER, err := marshalAttributeRaw(oidAttrSigningCertV2, scv2Value)
	if err != nil {
		return nil, nil, err
	}
	attrs = append(attrs, scv2DER)

	if !opts.SigningTime.IsZero() {
		stDER, err := marshalAttribute(oidAttrSigningTime, opts.SigningTime.UTC())
		if err != nil {
			return nil, nil, err
		}
		attrs = append(attrs, stDER)
	}

	if opts.SignaturePolicyOID != nil {
		polDER, err := buildSigPolicyIDAttr(opts.SignaturePolicyOID)
		if err != nil {
			return nil, nil, err
		}
		polAttr, err := marshalAttributeRaw(oidAttrSigPolicyID, polDER)
		if err != nil {
			return nil, nil, err
		}
		attrs = append(attrs, polAttr)
	}

	if opts.CommitmentTypeOID != nil {
		ctDER, err := buildCommitmentTypeAttr(opts.CommitmentTypeOID)
		if err != nil {
			return nil, nil, err
		}
		ctAttr, err := marshalAttributeRaw(oidAttrCommitmentType, ctDER)
		if err != nil {
			return nil, nil, err
		}
		attrs = append(attrs, ctAttr)
	}

	// DER canonicalisation: SET OF Attribute must sort by attribute bytes.
	sort.SliceStable(attrs, func(i, j int) bool {
		return bytes.Compare(attrs[i], attrs[j]) < 0
	})

	var setContent []byte
	for _, a := range attrs {
		setContent = append(setContent, a...)
	}

	// Two encodings of the same bytes:
	//   signedAttrs → [0] IMPLICIT SET (0xA0 ...), embedded as signerInfo.signedAttrs.
	//   hashInput   → universal SET (0x31 ...), hashed to produce hashToSign (RFC 5652 §5.4).
	signedAttrs, err = derContextTag(0, setContent)
	if err != nil {
		return nil, nil, fmt.Errorf("cms builder: signedAttrs [0]: %w", err)
	}
	hashInput, err := derSET(setContent)
	if err != nil {
		return nil, nil, fmt.Errorf("cms builder: signedAttrs SET: %w", err)
	}

	h := hashAlg.New()
	h.Write(hashInput)
	return signedAttrs, h.Sum(nil), nil
}

// AssembleSignedDataOptions holds the bytes produced outside the builder
// (signature + optional unsignedAttrs) and the certs the output will
// embed.
type AssembleSignedDataOptions struct {
	SignedAttrs    []byte // from BuildSignedAttrs
	Signature      []byte // raw signature bytes from external signer
	SignerCert     *x509.Certificate
	Chain          []*x509.Certificate // optional; signer cert is added first if absent
	DigestAlg      crypto.Hash
	// SignatureAlg selects the AlgorithmIdentifier emitted in SignerInfo.
	// Defaults to RSA-PKCS1-v1_5 when the signer key is RSA.
	SignatureAlg SignatureAlgorithm
	// UnsignedAttrs is the DER of the [1] IMPLICIT SET OF Attribute. When
	// non-nil, it is appended to the SignerInfo. The B-T flow passes the
	// signatureTimeStampToken attribute here.
	UnsignedAttrs []byte
}

// SignatureAlgorithm identifies which SignerInfo.signatureAlgorithm
// identifier to emit. Keeps the caller's intent explicit — cert.PublicKey
// alone does not disambiguate RSA PKCS#1 v1.5 from RSA-PSS.
type SignatureAlgorithm int

const (
	SigAlgDefault      SignatureAlgorithm = 0 // derive from cert key
	SigAlgRSAPKCS1v15  SignatureAlgorithm = 1
	SigAlgRSAPSS       SignatureAlgorithm = 2
	SigAlgECDSA        SignatureAlgorithm = 3
	SigAlgEd25519      SignatureAlgorithm = 4
)

// AssembleSignedData produces the DER-encoded CMS ContentInfo (signedData)
// ready to embed into a PDF /Contents slot. The signedAttrs bytes returned
// by BuildSignedAttrs must be passed through unchanged — the very bytes
// the external signer committed to via hashToSign.
func AssembleSignedData(opts AssembleSignedDataOptions) ([]byte, error) {
	if opts.SignerCert == nil {
		return nil, fmt.Errorf("cms builder: signer cert is nil")
	}
	if len(opts.Signature) == 0 {
		return nil, fmt.Errorf("cms builder: signature is empty")
	}
	if len(opts.SignedAttrs) == 0 {
		return nil, fmt.Errorf("cms builder: signedAttrs is empty")
	}
	hashAlg := opts.DigestAlg
	if hashAlg == 0 {
		hashAlg = crypto.SHA256
	}
	digestOID, err := oidForDigest(hashAlg)
	if err != nil {
		return nil, err
	}

	sigAlg := opts.SignatureAlg
	if sigAlg == SigAlgDefault {
		sigAlg, err = deriveSignatureAlgFromCert(opts.SignerCert)
		if err != nil {
			return nil, err
		}
	}
	sigAlgID, err := encodeSignatureAlgID(sigAlg, hashAlg)
	if err != nil {
		return nil, err
	}

	siContent, err := buildSignerInfo(opts.SignerCert, digestOID, opts.SignedAttrs,
		sigAlgID, opts.Signature, opts.UnsignedAttrs)
	if err != nil {
		return nil, err
	}
	signerInfosSET, err := derSET(siContent)
	if err != nil {
		return nil, fmt.Errorf("cms builder: signerInfos SET: %w", err)
	}

	digestAlgIDDER, err := asn1.Marshal(pkix.AlgorithmIdentifier{Algorithm: digestOID})
	if err != nil {
		return nil, fmt.Errorf("cms builder: digestAlgorithm: %w", err)
	}
	digestAlgsSET, err := derSET(digestAlgIDDER)
	if err != nil {
		return nil, fmt.Errorf("cms builder: digestAlgorithms SET: %w", err)
	}

	// EncapContentInfo: detached → content omitted; only contentType carried.
	encapOIDDER, err := asn1.Marshal(oidContentTypeData)
	if err != nil {
		return nil, fmt.Errorf("cms builder: encap contentType: %w", err)
	}
	encap, err := derSEQ(encapOIDDER)
	if err != nil {
		return nil, fmt.Errorf("cms builder: encapContentInfo: %w", err)
	}

	certsField, err := buildCertsField(opts.SignerCert, opts.Chain)
	if err != nil {
		return nil, err
	}

	versionDER, err := asn1.Marshal(1)
	if err != nil {
		return nil, err
	}
	sdContent := append([]byte{}, versionDER...)
	sdContent = append(sdContent, digestAlgsSET...)
	sdContent = append(sdContent, encap...)
	sdContent = append(sdContent, certsField...)
	sdContent = append(sdContent, signerInfosSET...)

	sdSEQ, err := derSEQ(sdContent)
	if err != nil {
		return nil, fmt.Errorf("cms builder: SignedData SEQUENCE: %w", err)
	}

	// --- ContentInfo SEQUENCE { contentType, content [0] EXPLICIT ANY } ---
	ciOIDDER, err := asn1.Marshal(oidContentTypeSignedData)
	if err != nil {
		return nil, err
	}
	contentTag, err := derContextTag(0, sdSEQ)
	if err != nil {
		return nil, fmt.Errorf("cms builder: content [0] EXPLICIT: %w", err)
	}
	return derSEQ(append(ciOIDDER, contentTag...))
}

// buildSignerInfo emits a single SignerInfo SEQUENCE body (not the outer
// SET wrapper). Uses IssuerAndSerialNumber for the sid — SubjectKeyIdentifier
// is a 2004-era optimization the PT signing chain does not require.
func buildSignerInfo(cert *x509.Certificate, digestOID asn1.ObjectIdentifier, signedAttrs, sigAlgID, signature, unsignedAttrs []byte) ([]byte, error) {
	versionDER, err := asn1.Marshal(1) // v1 aligns with IssuerAndSerial sid
	if err != nil {
		return nil, err
	}
	sidDER, err := buildIssuerAndSerialNumber(cert)
	if err != nil {
		return nil, err
	}
	digestAlgDER, err := asn1.Marshal(pkix.AlgorithmIdentifier{Algorithm: digestOID})
	if err != nil {
		return nil, err
	}
	sigDER, err := asn1.Marshal(signature)
	if err != nil {
		return nil, fmt.Errorf("cms builder: marshal signature OCTET STRING: %w", err)
	}

	body := bytes.Join([][]byte{versionDER, sidDER, digestAlgDER, signedAttrs, sigAlgID, sigDER}, nil)
	if len(unsignedAttrs) > 0 {
		// unsignedAttrs is already DER with [1] IMPLICIT outer tag — append verbatim.
		body = append(body, unsignedAttrs...)
	}
	return derSEQ(body)
}

// buildIssuerAndSerialNumber emits SEQUENCE { Issuer DN, SerialNumber }.
// cert.RawIssuer is already DER.
func buildIssuerAndSerialNumber(cert *x509.Certificate) ([]byte, error) {
	if cert.SerialNumber == nil {
		return nil, fmt.Errorf("cms builder: cert has no serial")
	}
	serialDER, err := asn1.Marshal(cert.SerialNumber)
	if err != nil {
		return nil, err
	}
	body := append([]byte{}, cert.RawIssuer...)
	body = append(body, serialDER...)
	return derSEQ(body)
}

// buildCertsField emits [0] IMPLICIT SET OF Certificate with the signer cert
// first and any additional chain certs appended. Each cert goes in verbatim
// (cert.Raw is already a DER-encoded Certificate SEQUENCE).
func buildCertsField(signer *x509.Certificate, chain []*x509.Certificate) ([]byte, error) {
	var body []byte
	body = append(body, signer.Raw...)
	for _, c := range chain {
		if c == nil {
			continue
		}
		// Don't duplicate the signer cert if caller passed it inside chain.
		if bytes.Equal(c.Raw, signer.Raw) {
			continue
		}
		body = append(body, c.Raw...)
	}
	return derContextTag(0, body)
}

// marshalAttribute emits an Attribute SEQUENCE { OID, SET OF AttributeValue }
// with a single value marshalled via asn1.Marshal(value).
func marshalAttribute(oid asn1.ObjectIdentifier, value any) ([]byte, error) {
	valueDER, err := asn1.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("cms builder: marshal attr value (%v): %w", oid, err)
	}
	return marshalAttributeRaw(oid, valueDER)
}

// marshalAttributeRaw is like marshalAttribute but the caller has already
// encoded the AttributeValue body as DER (used when the value is a nested
// SEQUENCE the stdlib marshaller can't produce directly).
func marshalAttributeRaw(oid asn1.ObjectIdentifier, valueDER []byte) ([]byte, error) {
	oidDER, err := asn1.Marshal(oid)
	if err != nil {
		return nil, fmt.Errorf("cms builder: attr OID: %w", err)
	}
	valuesSET, err := derSET(valueDER)
	if err != nil {
		return nil, fmt.Errorf("cms builder: attr values SET: %w", err)
	}
	return derSEQ(append(oidDER, valuesSET...))
}

// buildSigPolicyIDAttr emits SignaturePolicyId with OID-only + NULL hash
// placeholder. Intentionally minimal — Portuguese policy OID and hash
// value are open questions; this is a scaffold.
func buildSigPolicyIDAttr(policyOID asn1.ObjectIdentifier) ([]byte, error) {
	oidDER, err := asn1.Marshal(policyOID)
	if err != nil {
		return nil, err
	}
	algDER, _ := asn1.Marshal(pkix.AlgorithmIdentifier{Algorithm: oidDigestSHA256})
	emptyHash, _ := asn1.Marshal([]byte{})
	hashAlgVal, err := derSEQ(append(algDER, emptyHash...))
	if err != nil {
		return nil, err
	}
	return derSEQ(append(oidDER, hashAlgVal...))
}

// buildCommitmentTypeAttr emits CommitmentTypeIndication with OID-only
// (no qualifiers). Portuguese public-sector commitment types TBD.
func buildCommitmentTypeAttr(commitmentOID asn1.ObjectIdentifier) ([]byte, error) {
	oidDER, err := asn1.Marshal(commitmentOID)
	if err != nil {
		return nil, err
	}
	return derSEQ(oidDER)
}
