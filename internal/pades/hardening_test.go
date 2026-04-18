package pades

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"testing"
	"time"
)

func expiredCert(t *testing.T) *x509.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(9999),
		Subject:      pkix.Name{CommonName: "Expired Signer"},
		Issuer:       pkix.Name{CommonName: "Expired Signer"},
		NotBefore:    time.Now().Add(-48 * time.Hour),
		NotAfter:     time.Now().Add(-24 * time.Hour), // expired yesterday
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return cert
}

func TestCollectValidationDataWarnsOnExpiredSigner(t *testing.T) {
	expired := expiredCert(t)
	dss, err := CollectValidationData(context.Background(), []*x509.Certificate{expired}, [][]byte{{0x30, 0x80}})
	if err != nil {
		t.Fatalf("CollectValidationData: %v", err)
	}
	if len(dss.Warnings) == 0 {
		t.Fatal("expected a warning for expired signer cert")
	}
	// The warning should name the cert and the reason.
	joined := strings.ToLower(strings.Join(dss.Warnings, " | "))
	if !strings.Contains(joined, "expired signer") || !strings.Contains(joined, "expired") {
		t.Errorf("warning does not identify the expired cert: %v", dss.Warnings)
	}
}
