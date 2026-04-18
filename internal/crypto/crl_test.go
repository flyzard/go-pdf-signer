package crypto

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func makeCRL(t *testing.T, issuer *x509.Certificate, issuerKey *rsa.PrivateKey, nextUpdate time.Time) []byte {
	t.Helper()
	// ThisUpdate must be before NextUpdate (x509 rejects otherwise) AND
	// must not be in the future (verifyCRL's new skew gate rejects
	// otherwise). Clamp to the earlier of nextUpdate-2h and now-1h so
	// both "valid" and "expired" fixtures produce a sane CRL.
	thisUpdate := nextUpdate.Add(-2 * time.Hour)
	if nowMinus := time.Now().Add(-time.Hour); nowMinus.Before(thisUpdate) {
		thisUpdate = nowMinus
	}
	tmpl := &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: thisUpdate,
		NextUpdate: nextUpdate,
	}
	der, err := x509.CreateRevocationList(rand.Reader, tmpl, issuer, issuerKey)
	if err != nil {
		t.Fatalf("CreateRevocationList: %v", err)
	}
	return der
}

func TestFetchCRLRejectsExpired(t *testing.T) {
	allowLoopbackForTest(t)
	ca, caKey := generateTestCA(t)
	expired := makeCRL(t, ca, caKey, time.Now().Add(-time.Hour))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write(expired)
	}))
	defer srv.Close()

	leafTpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "Leaf"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		CRLDistributionPoints: []string{srv.URL},
	}
	leafKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTpl, ca, &leafKey.PublicKey, caKey)
	leaf, _ := x509.ParseCertificate(leafDER)

	if _, err := FetchCRL(context.Background(), leaf, ca); err == nil {
		t.Fatal("expected error for expired CRL, got nil")
	}
}

func TestFetchCRLRejectsWrongIssuer(t *testing.T) {
	allowLoopbackForTest(t)
	realCA, realKey := generateTestCA(t)
	otherCA, otherKey := generateTestCA(t)
	wrongCRL := makeCRL(t, otherCA, otherKey, time.Now().Add(time.Hour))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write(wrongCRL)
	}))
	defer srv.Close()

	leafTpl := &x509.Certificate{
		SerialNumber:          big.NewInt(3),
		Subject:               pkix.Name{CommonName: "Leaf"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		CRLDistributionPoints: []string{srv.URL},
	}
	leafKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTpl, realCA, &leafKey.PublicKey, realKey)
	leaf, _ := x509.ParseCertificate(leafDER)

	if _, err := FetchCRL(context.Background(), leaf, realCA); err == nil {
		t.Fatal("expected error for CRL signed by wrong issuer, got nil")
	}
}

func TestFetchCRLAcceptsValid(t *testing.T) {
	allowLoopbackForTest(t)
	ca, caKey := generateTestCA(t)
	good := makeCRL(t, ca, caKey, time.Now().Add(24*time.Hour))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write(good)
	}))
	defer srv.Close()

	leafTpl := &x509.Certificate{
		SerialNumber:          big.NewInt(4),
		Subject:               pkix.Name{CommonName: "Leaf"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		CRLDistributionPoints: []string{srv.URL},
	}
	leafKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTpl, ca, &leafKey.PublicKey, caKey)
	leaf, _ := x509.ParseCertificate(leafDER)

	res, err := FetchCRL(context.Background(), leaf, ca)
	if err != nil {
		t.Fatalf("FetchCRL: %v", err)
	}
	if len(res.RawCRL) == 0 {
		t.Error("RawCRL is empty")
	}
}
