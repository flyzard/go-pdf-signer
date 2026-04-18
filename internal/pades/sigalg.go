package pades

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
)

// deriveSignatureAlgFromCert picks a default SignatureAlgorithm when the
// caller did not specify one. RSA keys default to PKCS#1 v1.5 (the AMA CMD
// path); callers that want PSS must pass SigAlgRSAPSS explicitly.
func deriveSignatureAlgFromCert(cert *x509.Certificate) (SignatureAlgorithm, error) {
	switch cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return SigAlgRSAPKCS1v15, nil
	case *ecdsa.PublicKey:
		return SigAlgECDSA, nil
	case ed25519.PublicKey:
		return SigAlgEd25519, nil
	}
	return 0, fmt.Errorf("cms builder: unsupported public key type %T", cert.PublicKey)
}

// encodeSignatureAlgID returns the DER bytes of SignerInfo.signatureAlgorithm.
// RFC 5652 permits either rsaEncryption (no-hash OID, the legacy "old" form)
// or sha256WithRSAEncryption-style composite OIDs. Adobe + EU DSS accept
// the legacy rsaEncryption form and it matches what CmsAssembler.php emits —
// we stay byte-identical there. PSS and Ed25519 use their own OIDs with
// empty or specific parameters.
func encodeSignatureAlgID(sigAlg SignatureAlgorithm, hashAlg crypto.Hash) ([]byte, error) {
	switch sigAlg {
	case SigAlgRSAPKCS1v15:
		// Emit rsaEncryption with NULL parameters (ETSI recommendation for
		// CAdES interop).
		return asn1.Marshal(pkix.AlgorithmIdentifier{
			Algorithm:  oidRSAEncryption,
			Parameters: asn1.RawValue{Tag: 5, Class: asn1.ClassUniversal}, // NULL
		})
	case SigAlgRSAPSS:
		return encodeRSAPSSAlgID(hashAlg)
	case SigAlgECDSA:
		oid, err := ecdsaOIDForHash(hashAlg)
		if err != nil {
			return nil, err
		}
		return asn1.Marshal(pkix.AlgorithmIdentifier{Algorithm: oid})
	case SigAlgEd25519:
		return asn1.Marshal(pkix.AlgorithmIdentifier{Algorithm: oidEd25519})
	}
	return nil, fmt.Errorf("cms builder: unknown SignatureAlgorithm %d", sigAlg)
}

func ecdsaOIDForHash(h crypto.Hash) (asn1.ObjectIdentifier, error) {
	switch h {
	case crypto.SHA256:
		return oidECDSAWithSHA256, nil
	case crypto.SHA384:
		return oidECDSAWithSHA384, nil
	case crypto.SHA512:
		return oidECDSAWithSHA512, nil
	}
	return nil, fmt.Errorf("cms builder: ECDSA + %v not supported", h)
}

// encodeRSAPSSAlgID emits the RSASSA-PSS AlgorithmIdentifier carrying
// explicit parameters: hash = hashAlg, maskGenAlgorithm = MGF1(hashAlg),
// saltLength = hashAlg.Size(), trailerField = 1 (the only defined value).
// PSS parameters MUST be encoded when they differ from the NULL defaults,
// and ETSI requires matching-hash MGF1 with explicit saltLength.
func encodeRSAPSSAlgID(hashAlg crypto.Hash) ([]byte, error) {
	hashOID, err := oidForDigest(hashAlg)
	if err != nil {
		return nil, err
	}

	hashAlgID, _ := asn1.Marshal(pkix.AlgorithmIdentifier{Algorithm: hashOID})
	mgf1Params, _ := asn1.Marshal(pkix.AlgorithmIdentifier{Algorithm: hashOID})
	mgf1AlgID, _ := asn1.Marshal(pkix.AlgorithmIdentifier{
		Algorithm:  oidMGF1,
		Parameters: asn1.RawValue{FullBytes: mgf1Params},
	})
	saltDER, _ := asn1.Marshal(hashAlg.Size())

	// PSS parameters are EXPLICIT-tagged: [0] hashAlgorithm, [1]
	// maskGenAlgorithm, [2] saltLength, [3] trailerField (default 1, omit).
	hashTagged, _ := derContextTag(0, hashAlgID)
	mgfTagged, _ := derContextTag(1, mgf1AlgID)
	saltTagged, _ := derContextTag(2, saltDER)

	params := append([]byte{}, hashTagged...)
	params = append(params, mgfTagged...)
	params = append(params, saltTagged...)
	paramsSEQ, err := derSEQ(params)
	if err != nil {
		return nil, fmt.Errorf("cms builder: pss parameters: %w", err)
	}
	return asn1.Marshal(pkix.AlgorithmIdentifier{
		Algorithm:  oidRSASSAPSS,
		Parameters: asn1.RawValue{FullBytes: paramsSEQ},
	})
}

