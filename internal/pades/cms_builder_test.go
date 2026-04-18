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

// makeTestSignerCert creates a self-signed RSA-2048 cert usable as a CMS
// signer. The cert is NOT valid for x509.Verify (no trust anchor), but it
// carries a real RawIssuer + SerialNumber + PublicKey, which is all the
// CMS builder + verifier exercise.
func makeTestSignerCert(t *testing.T) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: "Test Signer"},
		Issuer:       pkix.Name{CommonName: "Test Signer"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	return cert, key
}

// buildAndSign is the shared helper that runs BuildSignedAttrs →
// external sign → AssembleSignedData → parseCMS for a self-signed cert.
func buildAndSign(t *testing.T, cert *x509.Certificate, key *rsa.PrivateKey) *parsedCMS {
	t.Helper()
	docHash := sha256.Sum256([]byte("doc"))
	signedAttrs, hashToSign, err := BuildSignedAttrs(docHash[:], cert, BuildSignedAttrsOptions{
		DigestAlgorithm: crypto.SHA256,
		SigningTime:     time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("BuildSignedAttrs: %v", err)
	}
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hashToSign)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	cmsDER, err := AssembleSignedData(AssembleSignedDataOptions{
		SignedAttrs: signedAttrs, Signature: signature, SignerCert: cert,
		DigestAlg: crypto.SHA256, SignatureAlg: SigAlgRSAPKCS1v15,
	})
	if err != nil {
		t.Fatalf("AssembleSignedData: %v", err)
	}
	parsed, err := parseCMS(cmsDER)
	if err != nil {
		t.Fatalf("parseCMS: %v", err)
	}
	return parsed
}

// TestCMSBuilderRoundTrip exercises BuildSignedAttrs → external sign →
// AssembleSignedData → parseCMS → verifySignature — the full happy path
// sign-start/sign-finish will run.
func TestCMSBuilderRoundTrip(t *testing.T) {
	cert, key := makeTestSignerCert(t)
	parsed := buildAndSign(t, cert, key)
	if len(parsed.SignerInfos) != 1 {
		t.Fatalf("got %d SignerInfos, want 1", len(parsed.SignerInfos))
	}
	si := parsed.SignerInfos[0]

	signer, err := si.findSignerCert(parsed.Certificates)
	if err != nil {
		t.Fatalf("findSignerCert: %v", err)
	}
	if err := si.verifySignature(signer); err != nil {
		t.Fatalf("verifySignature: %v", err)
	}
	if err := ValidateESSBinding(si, signer); err != nil {
		t.Fatalf("ValidateESSBinding: %v", err)
	}
	if err := HashAlgConsistency(parsed, si); err != nil {
		t.Fatalf("HashAlgConsistency: %v", err)
	}
}

// TestESSBindingRejectsCertSwap guards against the cert-substitution
// attack: ValidateESSBinding must refuse when the cert offered doesn't
// match the ESSCertIDv2 hash in signedAttrs.
func TestESSBindingRejectsCertSwap(t *testing.T) {
	cert, key := makeTestSignerCert(t)
	other, _ := makeTestSignerCert(t)

	parsed := buildAndSign(t, cert, key)
	si := parsed.SignerInfos[0]

	// Sanity: the original cert binds.
	if err := ValidateESSBinding(si, cert); err != nil {
		t.Fatalf("ESS binding should accept original cert: %v", err)
	}
	// Swap to `other`: must refuse.
	if err := ValidateESSBinding(si, other); err == nil {
		t.Fatal("expected ESS binding to reject cert swap, got nil")
	}
}

// TestHashAlgConsistencyDetectsMismatch locks the §6.2.8 check: if the
// outer SignedData.digestAlgorithms set disagrees with SignerInfo's digest
// algorithm, the gate must refuse.
func TestHashAlgConsistencyDetectsMismatch(t *testing.T) {
	cert, key := makeTestSignerCert(t)
	parsed := buildAndSign(t, cert, key)
	si := parsed.SignerInfos[0]

	// Replace digestAlgorithms with SHA-384-only so the SHA-256 SignerInfo
	// no longer has a matching entry in the outer set.
	parsed.DigestAlgorithmOIDs = []asn1.ObjectIdentifier{oidDigestSHA384}
	if err := HashAlgConsistency(parsed, si); err == nil {
		t.Fatal("expected hash-alg consistency failure, got nil")
	}
}
