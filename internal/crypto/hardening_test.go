package crypto

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"
)

// -- M2: SHA-256 OCSP request hash -----------------------------------------

func TestFetchOCSPUsesSHA256HashAlgorithm(t *testing.T) {
	allowLoopbackForTest(t)
	ca, caKey := generateTestCA(t)

	leafTpl := &x509.Certificate{
		SerialNumber: big.NewInt(110),
		Subject:      pkix.Name{CommonName: "Leaf"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	leafKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTpl, ca, &leafKey.PublicKey, caKey)
	leaf, _ := x509.ParseCertificate(leafDER)

	var capturedHash crypto.Hash
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := make([]byte, r.ContentLength)
		r.Body.Read(body)
		req, err := ocsp.ParseRequest(body)
		if err == nil {
			capturedHash = req.HashAlgorithm
		}
		// Return expired response so FetchOCSP fails — we only care about the request hash.
		tmpl := ocsp.Response{
			Status: ocsp.Good, SerialNumber: leaf.SerialNumber,
			ThisUpdate: time.Now().Add(-48 * time.Hour),
			NextUpdate: time.Now().Add(-24 * time.Hour),
		}
		resp, _ := ocsp.CreateResponse(ca, ca, tmpl, caKey)
		w.Write(resp)
	}))
	defer srv.Close()
	leaf.OCSPServer = []string{srv.URL}

	_, _ = FetchOCSP(context.Background(), leaf, ca)

	if capturedHash != crypto.SHA256 {
		t.Errorf("OCSP request hash = %v, want SHA-256", capturedHash)
	}
}

// -- M3: OCSP future ThisUpdate is rejected --------------------------------

func TestFetchOCSPRejectsFutureThisUpdate(t *testing.T) {
	allowLoopbackForTest(t)
	ca, caKey := generateTestCA(t)

	leafTpl := &x509.Certificate{
		SerialNumber: big.NewInt(120),
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
		ThisUpdate:   time.Now().Add(24 * time.Hour), // way in the future
		NextUpdate:   time.Now().Add(48 * time.Hour),
	}
	respBytes, _ := ocsp.CreateResponse(ca, ca, tmpl, caKey)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write(respBytes)
	}))
	defer srv.Close()
	leaf.OCSPServer = []string{srv.URL}

	if _, err := FetchOCSP(context.Background(), leaf, ca); err == nil {
		t.Fatal("expected error for future ThisUpdate, got nil")
	}
}

// -- C3: OCSP nonce mismatch is rejected; absent nonce is tolerated --------

func TestValidateOCSPNonceAcceptsMatchingNonce(t *testing.T) {
	nonce := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	octet, _ := asn1.Marshal(nonce)
	parsed := &ocsp.Response{
		Extensions: []pkix.Extension{{Id: ocspNonceOID, Value: octet}},
	}
	if err := validateOCSPNonce(parsed, nonce); err != nil {
		t.Errorf("matching nonce should be accepted: %v", err)
	}
}

func TestValidateOCSPNonceRejectsWrongNonce(t *testing.T) {
	sent := []byte{1, 2, 3, 4}
	other := []byte{9, 9, 9, 9}
	octet, _ := asn1.Marshal(other)
	parsed := &ocsp.Response{
		Extensions: []pkix.Extension{{Id: ocspNonceOID, Value: octet}},
	}
	if err := validateOCSPNonce(parsed, sent); err == nil {
		t.Fatal("wrong nonce should be rejected")
	}
}

func TestValidateOCSPNonceTolerateAbsentNonce(t *testing.T) {
	parsed := &ocsp.Response{}
	if err := validateOCSPNonce(parsed, []byte("whatever")); err != nil {
		t.Errorf("absent nonce extension should be accepted (real responders omit it): %v", err)
	}
}

// -- H3: AIA-fetched issuer must be a CA permitted to sign certs ----------

func TestBuildChainRejectsNonCAIssuer(t *testing.T) {
	allowLoopbackForTest(t)

	ca, caKey := generateTestCA(t)
	// Non-CA leaf used as a fraudulent AIA response.
	badTpl := &x509.Certificate{
		SerialNumber: big.NewInt(200),
		Subject:      pkix.Name{CommonName: "Not-A-CA"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	badKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	badDER, _ := x509.CreateCertificate(rand.Reader, badTpl, ca, &badKey.PublicKey, caKey)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write(badDER)
	}))
	defer srv.Close()

	// Leaf whose AIA points to the bad cert.
	leafTpl := &x509.Certificate{
		SerialNumber:          big.NewInt(210),
		Subject:               pkix.Name{CommonName: "Leaf under Fake AIA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		IssuingCertificateURL: []string{srv.URL},
	}
	leafKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTpl, ca, &leafKey.PublicKey, caKey)
	leaf, _ := x509.ParseCertificate(leafDER)
	leaf.IssuingCertificateURL = []string{srv.URL}

	res, err := BuildChain(context.Background(), leaf)
	if err != nil {
		t.Fatalf("BuildChain: %v", err)
	}
	for _, c := range res.Certificates[1:] {
		if bytes.Equal(c.Raw, badDER) {
			t.Fatal("BuildChain accepted a non-CA cert as issuer")
		}
	}
}

// -- H10: CRL AuthorityKeyId must match issuer SubjectKeyId ----------------

func TestVerifyCRLRejectsAKIMismatch(t *testing.T) {
	ca, caKey := generateTestCA(t)
	// Real CRL signed by CA; AKI will be set to CA's SKI.
	crl := makeCRL(t, ca, caKey, time.Now().Add(24*time.Hour))

	// Mutate the parsed issuer cert's SKI to a non-matching value to simulate
	// a different-but-valid-looking issuer presented to verifyCRL.
	impostor := *ca
	impostor.SubjectKeyId = []byte("deadbeef-deadbeef-deadbeef-dea0")

	_, _, err := verifyCRL(crl, &impostor)
	if err == nil {
		t.Fatal("expected error when CRL AKI does not match issuer SKI")
	}
}
