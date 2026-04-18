package crypto

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"
)

func TestFetchOCSPRejectsExpired(t *testing.T) {
	allowLoopbackForTest(t)
	ca, caKey := generateTestCA(t)

	leafTpl := &x509.Certificate{
		SerialNumber: big.NewInt(50),
		Subject:      pkix.Name{CommonName: "Leaf"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	leafKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTpl, ca, &leafKey.PublicKey, caKey)
	leaf, _ := x509.ParseCertificate(leafDER)

	tmpl := ocsp.Response{
		Status:       ocsp.Good,
		SerialNumber: leaf.SerialNumber,
		ThisUpdate:   time.Now().Add(-48 * time.Hour),
		NextUpdate:   time.Now().Add(-24 * time.Hour), // expired
	}
	respBytes, err := ocsp.CreateResponse(ca, ca, tmpl, caKey)
	if err != nil {
		t.Fatalf("CreateResponse: %v", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write(respBytes)
	}))
	defer srv.Close()
	leaf.OCSPServer = []string{srv.URL}

	if _, err := FetchOCSP(context.Background(), leaf, ca); err == nil {
		t.Fatal("expected error for expired OCSP response, got nil")
	}
}

// TestAppendNonceToOCSPRequest_RoundTrip exercises the request-mutation
// helper independently of the network path, ensuring the resulting bytes are
// a valid OCSPRequest containing the nonce extension.
func TestAppendNonceToOCSPRequest_RoundTrip(t *testing.T) {
	ca, caKey := generateTestCA(t)
	leafTpl := &x509.Certificate{
		SerialNumber: big.NewInt(60),
		Subject:      pkix.Name{CommonName: "Leaf"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	leafKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTpl, ca, &leafKey.PublicKey, caKey)
	leaf, _ := x509.ParseCertificate(leafDER)

	original, err := ocsp.CreateRequest(leaf, ca, &ocsp.RequestOptions{Hash: crypto.SHA1})
	if err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}
	withNonce, err := appendNonceToOCSPRequest(original, []byte{1, 2, 3, 4})
	if err != nil {
		t.Fatalf("appendNonceToOCSPRequest: %v", err)
	}
	if _, err := ocsp.ParseRequest(withNonce); err != nil {
		t.Fatalf("ParseRequest after nonce attachment: %v", err)
	}
	// Nonce OID: 1.3.6.1.5.5.7.48.1.2 = 06 09 2B 06 01 05 05 07 30 01 02.
	nonceOID := []byte{0x06, 0x09, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x02}
	if !bytes.Contains(withNonce, nonceOID) {
		t.Error("nonce OID not found in re-encoded request bytes")
	}
}
