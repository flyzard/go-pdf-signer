package pades

import (
	"bytes"
	"crypto/sha256"
	"testing"
)

func TestParseCMSExtractsCertAndSigner(t *testing.T) {
	content := []byte("payload-being-signed")
	hash := sha256.Sum256(content)
	cms, cert, _ := buildSignedCMS(t, hash[:])

	parsed, err := parseCMS(cms)
	if err != nil {
		t.Fatalf("parseCMS: %v", err)
	}
	if len(parsed.Certificates) != 1 {
		t.Fatalf("want 1 cert, got %d", len(parsed.Certificates))
	}
	if !bytes.Equal(parsed.Certificates[0].Raw, cert.Raw) {
		t.Errorf("extracted cert does not match generated fixture")
	}
	if len(parsed.SignerInfos) != 1 {
		t.Fatalf("want 1 signerInfo, got %d", len(parsed.SignerInfos))
	}
}

func TestParseCMSMessageDigestRoundTrips(t *testing.T) {
	hash := sha256.Sum256([]byte("whatever"))
	cms, _, _ := buildSignedCMS(t, hash[:])

	parsed, err := parseCMS(cms)
	if err != nil {
		t.Fatalf("parseCMS: %v", err)
	}
	got, err := parsed.SignerInfos[0].MessageDigest()
	if err != nil {
		t.Fatalf("MessageDigest: %v", err)
	}
	if !bytes.Equal(got, hash[:]) {
		t.Errorf("messageDigest mismatch:\n got  %x\n want %x", got, hash[:])
	}
}

func TestCMSSignatureVerifies(t *testing.T) {
	hash := sha256.Sum256([]byte("signed content"))
	cms, cert, _ := buildSignedCMS(t, hash[:])

	parsed, err := parseCMS(cms)
	if err != nil {
		t.Fatalf("parseCMS: %v", err)
	}
	si := parsed.SignerInfos[0]
	signer, err := si.findSignerCert(parsed.Certificates)
	if err != nil {
		t.Fatalf("findSignerCert: %v", err)
	}
	if !bytes.Equal(signer.Raw, cert.Raw) {
		t.Errorf("signer cert mismatch")
	}
	if err := si.verifySignature(signer); err != nil {
		t.Errorf("verifySignature should accept fixture signature: %v", err)
	}
}

func TestCMSSignatureRejectsTamperedAttrs(t *testing.T) {
	hash := sha256.Sum256([]byte("content"))
	cms, _, _ := buildSignedCMS(t, hash[:])

	parsed, err := parseCMS(cms)
	if err != nil {
		t.Fatalf("parseCMS: %v", err)
	}
	si := parsed.SignerInfos[0]

	// Flip one byte in the signedAttrs we verify against (simulating tamper).
	if len(si.signedAttrsRaw) < 5 {
		t.Fatalf("signedAttrsRaw suspiciously short: %d bytes", len(si.signedAttrsRaw))
	}
	si.signedAttrsRaw[len(si.signedAttrsRaw)-1] ^= 0x01

	signer, _ := si.findSignerCert(parsed.Certificates)
	if err := si.verifySignature(signer); err == nil {
		t.Fatal("verifySignature accepted tampered signedAttrs")
	}
}

func TestCMSRejectsSHA1Digest(t *testing.T) {
	hash := sha256.Sum256([]byte("content"))
	cms, _, _ := buildSignedCMS(t, hash[:])
	parsed, _ := parseCMS(cms)
	si := parsed.SignerInfos[0]
	si.DigestAlgorithm = oidDigestSHA1
	if _, err := si.digestHash(); err == nil {
		t.Fatal("digestHash should refuse SHA-1")
	}
}
