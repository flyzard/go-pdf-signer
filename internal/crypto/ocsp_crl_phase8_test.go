package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"
)

// TestCertHasOCSPNoCheck covers the R-4.1.6 honor path: a responder cert
// with the id-pkix-ocsp-nocheck extension must be detected so verify
// skips its own revocation check.
func TestCertHasOCSPNoCheck(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "OCSP Responder"},
		Issuer:       pkix.Name{CommonName: "OCSP Responder"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		ExtraExtensions: []pkix.Extension{
			{Id: ocspNoCheckOID, Value: []byte{0x05, 0x00}}, // NULL
		},
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(der)
	if !certHasOCSPNoCheck(cert) {
		t.Fatal("certHasOCSPNoCheck must detect id-pkix-ocsp-nocheck when present")
	}

	// Control: cert without the extension.
	tmpl2 := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "Plain"},
		Issuer:       pkix.Name{CommonName: "Plain"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der2, _ := x509.CreateCertificate(rand.Reader, tmpl2, tmpl2, &key.PublicKey, key)
	plain, _ := x509.ParseCertificate(der2)
	if certHasOCSPNoCheck(plain) {
		t.Fatal("certHasOCSPNoCheck must return false when the extension is absent")
	}
}

// TestCertHasEKU_OCSPSigning covers responder-authorization: a delegate
// responder cert must advertise id-kp-OCSPSigning for classifyOCSPResponder
// to accept it.
func TestCertHasEKU_OCSPSigning(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Delegate"},
		Issuer:       pkix.Name{CommonName: "Delegate"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning},
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(der)
	if !certHasEKU(cert, ocspSigningEKU) {
		t.Fatal("certHasEKU must detect OCSPSigning via stdlib enum")
	}
}

// TestIsIndirectCRL covers R-4.2.2: isIndirectCRL must detect the
// indirectCRL=TRUE flag in the IssuingDistributionPoint extension.
func TestIsIndirectCRL(t *testing.T) {
	// Build an IDP extension body with indirectCRL=TRUE at context tag [4].
	// Minimal SEQUENCE containing only that field is valid DER.
	indirectField, err := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassContextSpecific, Tag: 4, IsCompound: false, Bytes: []byte{0xff},
	})
	if err != nil {
		t.Fatalf("marshal tag: %v", err)
	}
	idpBody, err := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: indirectField,
	})
	if err != nil {
		t.Fatalf("marshal idp: %v", err)
	}

	crl := &x509.RevocationList{
		Extensions: []pkix.Extension{{Id: issuingDistributionPointOID, Value: idpBody}},
	}
	if !isIndirectCRL(crl) {
		t.Fatal("isIndirectCRL must return true for IDP with indirectCRL=TRUE")
	}

	// Control: no IDP extension → direct CRL.
	if isIndirectCRL(&x509.RevocationList{}) {
		t.Fatal("isIndirectCRL must return false when the extension is absent")
	}
}

