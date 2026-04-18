package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"
)

func makeTSATestCert(t *testing.T, criticalEKU bool, ekuOIDs []asn1.ObjectIdentifier) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key gen: %v", err)
	}
	ekuDER, err := asn1.Marshal(ekuOIDs)
	if err != nil {
		t.Fatalf("eku marshal: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test TSA"},
		Issuer:       pkix.Name{CommonName: "Test TSA"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtraExtensions: []pkix.Extension{
			{Id: oidExtKeyUsage, Critical: criticalEKU, Value: ekuDER},
		},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	return cert, key
}

func TestValidateTSACertRejectsNonCriticalEKU(t *testing.T) {
	cert, _ := makeTSATestCert(t, false, []asn1.ObjectIdentifier{oidKPTimeStamping})
	err := enforceTimeStampingEKU(cert)
	if err == nil {
		t.Fatal("expected rejection of non-critical EKU")
	}
}

func TestValidateTSACertRejectsExtraEKU(t *testing.T) {
	extra := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1} // serverAuth
	cert, _ := makeTSATestCert(t, true, []asn1.ObjectIdentifier{oidKPTimeStamping, extra})
	err := enforceTimeStampingEKU(cert)
	if err == nil {
		t.Fatal("expected rejection of extra EKU")
	}
}

func TestValidateTSACertAcceptsCriticalSoleTimestampingEKU(t *testing.T) {
	cert, _ := makeTSATestCert(t, true, []asn1.ObjectIdentifier{oidKPTimeStamping})
	if err := enforceTimeStampingEKU(cert); err != nil {
		t.Fatalf("should accept: %v", err)
	}
}

func TestValidateTSACertChainRejectsUnknownRoot(t *testing.T) {
	// TSA cert chains to itself, but we give it an empty pool — verify fails.
	cert, _ := makeTSATestCert(t, true, []asn1.ObjectIdentifier{oidKPTimeStamping})
	pool := x509.NewCertPool()
	err := ValidateTSACertificate(cert, nil, pool, time.Now())
	if err == nil {
		t.Fatal("expected chain validation to fail against empty pool")
	}
}

func TestValidateTSACertChainAcceptsSelfSignedWhenInPool(t *testing.T) {
	cert, _ := makeTSATestCert(t, true, []asn1.ObjectIdentifier{oidKPTimeStamping})
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	if err := ValidateTSACertificate(cert, nil, pool, time.Now()); err != nil {
		t.Fatalf("self-signed TSA cert in pool should validate: %v", err)
	}
}
