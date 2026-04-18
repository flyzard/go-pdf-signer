package pades

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"
)

// buildSignedCMS generates a self-signed RSA-2048 cert and produces a valid
// detached CMS SignedData blob that signs contentHash (SHA-256). The output is
// a complete PKCS#7/CMS structure verifying end-to-end: messageDigest,
// signedAttrs-as-SET signature input, and certificate embedded.
func buildSignedCMS(t *testing.T, contentHash []byte) ([]byte, *x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	if len(contentHash) != 32 {
		t.Fatalf("buildSignedCMS expects SHA-256 (32 bytes), got %d", len(contentHash))
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa gen: %v", err)
	}

	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(0xC0FFEE),
		Subject:      pkix.Name{CommonName: "Test CMS Signer"},
		Issuer:       pkix.Name{CommonName: "Test CMS Signer"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}

	// signedAttrs (SET OF Attribute):
	//   contentType   = id-data
	//   messageDigest = OCTET STRING(contentHash)
	contentTypeAttr, err := makeAttrOID(oidAttrContentType, oidContentTypeData)
	if err != nil {
		t.Fatalf("contentType attr: %v", err)
	}
	msgDigestAttr, err := makeAttrOctet(oidAttrMessageDigest, contentHash)
	if err != nil {
		t.Fatalf("messageDigest attr: %v", err)
	}

	// Canonical DER for signing: SET OF Attribute (sorted by DER value per RFC 6268/DER rules —
	// two attrs with known distinct OIDs, we emit in whatever order and let the SET sort be
	// implicit for test purposes; most verifiers tolerate either order).
	attrsForSign, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSet, // 0x31
		IsCompound: true,
		Bytes:      append(append([]byte{}, contentTypeAttr...), msgDigestAttr...),
	})
	if err != nil {
		t.Fatalf("marshal signedAttrs-for-signing: %v", err)
	}

	// Sign the DER-encoded SET (with 0x31 tag) using RSA-SHA256.
	digest := sha256.Sum256(attrsForSign)
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("rsa sign: %v", err)
	}

	// signedAttrs for embedding in SignerInfo: same bytes but with [0] IMPLICIT tag (0xA0).
	// We reuse attrsForSign and flip the first byte.
	signedAttrsImplicit := append([]byte{}, attrsForSign...)
	signedAttrsImplicit[0] = 0xA0

	// SignerInfo.
	signerInfo := signerInfoDER(t, cert, signedAttrsImplicit, signature)

	// SignedData.
	signedData := signedDataDER(t, certDER, signerInfo)

	// ContentInfo wrapping SignedData.
	contentInfo := contentInfoDER(t, signedData)

	return contentInfo, cert, key
}

// makeAttrOID builds an Attribute whose single value is an OID.
func makeAttrOID(attrType, valueOID asn1.ObjectIdentifier) ([]byte, error) {
	val, err := asn1.Marshal(valueOID)
	if err != nil {
		return nil, err
	}
	return marshalAttributeForTest(attrType, val)
}

// makeAttrOctet builds an Attribute whose single value is an OCTET STRING.
func makeAttrOctet(attrType asn1.ObjectIdentifier, octet []byte) ([]byte, error) {
	val, err := asn1.Marshal(octet)
	if err != nil {
		return nil, err
	}
	return marshalAttributeForTest(attrType, val)
}

// marshalAttributeForTest wraps the given pre-marshalled value inside a DER
// Attribute ::= SEQUENCE { attrType OID, attrValues SET OF ANY }.
func marshalAttributeForTest(attrType asn1.ObjectIdentifier, valueDER []byte) ([]byte, error) {
	oidBytes, err := asn1.Marshal(attrType)
	if err != nil {
		return nil, err
	}
	valuesSet, err := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true, Bytes: valueDER,
	})
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true,
		Bytes: append(oidBytes, valuesSet...),
	})
}

func signerInfoDER(t *testing.T, cert *x509.Certificate, signedAttrsImplicit, signature []byte) []byte {
	t.Helper()

	version, _ := asn1.Marshal(1)

	// IssuerAndSerialNumber ::= SEQUENCE { issuer Name, serialNumber INTEGER }
	sid, err := asn1.Marshal(struct {
		Issuer       asn1.RawValue
		SerialNumber *big.Int
	}{
		Issuer:       asn1.RawValue{FullBytes: cert.RawIssuer},
		SerialNumber: cert.SerialNumber,
	})
	if err != nil {
		t.Fatalf("marshal sid: %v", err)
	}

	digestAlgo, err := asn1.Marshal(pkix.AlgorithmIdentifier{
		Algorithm:  oidDigestSHA256,
		Parameters: asn1.RawValue{Tag: asn1.TagNull},
	})
	if err != nil {
		t.Fatalf("marshal digestAlgo: %v", err)
	}

	sigAlgo, err := asn1.Marshal(pkix.AlgorithmIdentifier{
		Algorithm:  oidRSAEncryption,
		Parameters: asn1.RawValue{Tag: asn1.TagNull},
	})
	if err != nil {
		t.Fatalf("marshal sigAlgo: %v", err)
	}

	sigOctet, err := asn1.Marshal(signature)
	if err != nil {
		t.Fatalf("marshal signature: %v", err)
	}

	var body []byte
	body = append(body, version...)
	body = append(body, sid...)
	body = append(body, digestAlgo...)
	body = append(body, signedAttrsImplicit...)
	body = append(body, sigAlgo...)
	body = append(body, sigOctet...)

	out, err := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: body,
	})
	if err != nil {
		t.Fatalf("marshal signerInfo: %v", err)
	}
	return out
}

func signedDataDER(t *testing.T, certDER, signerInfo []byte) []byte {
	t.Helper()

	version, _ := asn1.Marshal(1)

	// digestAlgorithms SET OF AlgorithmIdentifier containing SHA-256.
	sha256Algo, _ := asn1.Marshal(pkix.AlgorithmIdentifier{
		Algorithm:  oidDigestSHA256,
		Parameters: asn1.RawValue{Tag: asn1.TagNull},
	})
	digestAlgos, _ := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true, Bytes: sha256Algo,
	})

	// encapContentInfo SEQUENCE { contentType id-data } (no content = detached).
	encapOID, _ := asn1.Marshal(oidContentTypeData)
	encap, _ := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: encapOID,
	})

	// certificates [0] IMPLICIT SET OF Certificate.
	certs, _ := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: certDER,
	})

	// signerInfos SET OF SignerInfo.
	signerInfos, _ := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true, Bytes: signerInfo,
	})

	var body []byte
	body = append(body, version...)
	body = append(body, digestAlgos...)
	body = append(body, encap...)
	body = append(body, certs...)
	body = append(body, signerInfos...)

	out, _ := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: body,
	})
	return out
}

func contentInfoDER(t *testing.T, signedData []byte) []byte {
	t.Helper()
	oidBytes, _ := asn1.Marshal(oidContentTypeSignedData)
	explicit, _ := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: signedData,
	})
	out, _ := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true,
		Bytes: append(oidBytes, explicit...),
	})
	return out
}
