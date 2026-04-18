package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"
)

// mkCert is a policy-tests helper. Accepts a template mutator so each test
// can set only the fields it cares about and keep defaults otherwise.
func mkCert(t *testing.T, mutate func(*x509.Certificate), keyBits int, useECDSA bool) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Policy Test"},
		Issuer:       pkix.Name{CommonName: "Policy Test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	if mutate != nil {
		mutate(tmpl)
	}

	var pub any
	var signerKey any
	if useECDSA {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("ec key: %v", err)
		}
		pub = &k.PublicKey
		signerKey = k
	} else {
		k, err := rsa.GenerateKey(rand.Reader, keyBits)
		if err != nil {
			t.Fatalf("rsa key: %v", err)
		}
		pub = &k.PublicKey
		signerKey = k
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, signerKey)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	return cert
}

func TestValidateSignerCertAccepts2048RSA(t *testing.T) {
	cert := mkCert(t, nil, 2048, false)
	if err := ValidateSignerCert(cert); err != nil {
		t.Fatalf("ValidateSignerCert 2048 RSA: %v", err)
	}
}

func TestValidateSignerCertRejectsWeakRSA(t *testing.T) {
	cert := mkCert(t, nil, 1024, false)
	err := ValidateSignerCert(cert)
	var pe *CertPolicyError
	if !errors.As(err, &pe) || pe.Code != "CERT_WEAK_KEY" {
		t.Fatalf("expected CERT_WEAK_KEY, got %v", err)
	}
}

func TestValidateSignerCertRejectsCALeaf(t *testing.T) {
	cert := mkCert(t, func(c *x509.Certificate) {
		c.IsCA = true
		c.KeyUsage = x509.KeyUsageCertSign
		c.BasicConstraintsValid = true
	}, 2048, false)
	err := ValidateSignerCert(cert)
	var pe *CertPolicyError
	if !errors.As(err, &pe) || pe.Code != "CERT_CA_LEAF" {
		t.Fatalf("expected CERT_CA_LEAF, got %v", err)
	}
}

func TestValidateSignerCertRejectsWrongKeyUsage(t *testing.T) {
	cert := mkCert(t, func(c *x509.Certificate) {
		c.KeyUsage = x509.KeyUsageKeyEncipherment
	}, 2048, false)
	err := ValidateSignerCert(cert)
	var pe *CertPolicyError
	if !errors.As(err, &pe) || pe.Code != "CERT_KEYUSAGE_REJECTED" {
		t.Fatalf("expected CERT_KEYUSAGE_REJECTED, got %v", err)
	}
}

func TestValidateSignerCertAcceptsECDSAP256(t *testing.T) {
	cert := mkCert(t, nil, 0, true)
	if err := ValidateSignerCert(cert); err != nil {
		t.Fatalf("ECDSA P-256: %v", err)
	}
}
