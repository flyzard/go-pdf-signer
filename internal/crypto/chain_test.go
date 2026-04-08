package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

// generateTestCA creates a self-signed CA certificate and its private key.
func generateTestCA(t *testing.T) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating CA key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Test Root CA",
			Organization: []string{"Test"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating CA cert: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("parsing CA cert: %v", err)
	}

	return cert, key
}

// generateTestLeaf creates a leaf certificate signed by the given CA.
func generateTestLeaf(t *testing.T, caCert *x509.Certificate, caKey *rsa.PrivateKey) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating leaf key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName:   "Test Leaf",
			Organization: []string{"Test"},
		},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(24 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
		// Intentionally no IssuingCertificateURL (AIA) and no OCSPServer / CRL
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("creating leaf cert: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("parsing leaf cert: %v", err)
	}

	return cert, key
}

// TestBuildChainSelfSigned verifies that a self-signed root cert produces a
// chain of length 1 with IsComplete=true and no error.
func TestBuildChainSelfSigned(t *testing.T) {
	root, _ := generateTestCA(t)

	result, err := BuildChain(root)
	if err != nil {
		t.Fatalf("BuildChain returned error: %v", err)
	}

	if len(result.Certificates) == 0 {
		t.Fatal("expected at least 1 certificate in chain")
	}

	if result.Certificates[0].SerialNumber.Cmp(root.SerialNumber) != 0 {
		t.Error("first cert in chain should be the leaf/root")
	}

	if !result.IsComplete {
		t.Error("self-signed root chain should be marked IsComplete=true")
	}
}

// TestBuildChainNoAIA verifies that a leaf cert with no AIA URLs produces a
// chain containing just the leaf with IsComplete=false.
func TestBuildChainNoAIA(t *testing.T) {
	root, rootKey := generateTestCA(t)
	leaf, _ := generateTestLeaf(t, root, rootKey)

	result, err := BuildChain(leaf)
	if err != nil {
		t.Fatalf("BuildChain returned error: %v", err)
	}

	if len(result.Certificates) != 1 {
		t.Fatalf("expected chain length 1, got %d", len(result.Certificates))
	}

	if result.Certificates[0].SerialNumber.Cmp(leaf.SerialNumber) != 0 {
		t.Error("chain should contain the leaf certificate")
	}

	if result.IsComplete {
		t.Error("chain without AIA and no trusted root should be IsComplete=false")
	}
}
