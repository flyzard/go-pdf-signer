package pades

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"github.com/flyzard/pdf-signer/internal/appearance"
	"github.com/flyzard/pdf-signer/internal/pdf"
)

// signTestPDFFixture runs Prepare to generate a prepared PDF, signs the
// returned byte-range hash with a fresh self-signed cert via buildSignedCMS,
// and embeds the CMS into the prepared PDF. Returns the fully-signed PDF
// bytes — ready for Verify.
func signTestPDFFixture(t *testing.T, inputPath string) []byte {
	t.Helper()

	preparedPath := filepath.Join(t.TempDir(), "prepared.pdf")
	result, err := Prepare(PrepareOptions{
		InputPath:     inputPath,
		OutputPath:    preparedPath,
		SignerName:    "Real Test Signer",
		SignerNIC:     "12345678",
		SigningMethod: "cmd",
		SignaturePos:  appearance.DefaultPosition(0),
	})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}

	hash, err := base64.StdEncoding.DecodeString(result.Hash)
	if err != nil {
		t.Fatalf("decode hash: %v", err)
	}

	cms, _, _ := buildSignedCMS(t, hash)

	prepared, err := os.ReadFile(preparedPath)
	if err != nil {
		t.Fatalf("read prepared: %v", err)
	}

	signed, err := pdf.EmbedCMS(prepared, cms)
	if err != nil {
		t.Fatalf("EmbedCMS: %v", err)
	}
	return signed
}

func TestVerifyAcceptsValidSignature(t *testing.T) {
	inputPath := createTestPDF(t)
	signed := signTestPDFFixture(t, inputPath)

	signedPath := filepath.Join(t.TempDir(), "signed.pdf")
	if err := os.WriteFile(signedPath, signed, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	res, err := Verify(VerifyOptions{InputPath: signedPath})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if len(res.Signatures) != 1 {
		t.Fatalf("want 1 signature, got %d", len(res.Signatures))
	}
	sig := res.Signatures[0]
	if !sig.ByteRangeValid {
		t.Errorf("ByteRangeValid=false: %q", sig.VerifyError)
	}
	if !sig.HashMatch {
		t.Errorf("HashMatch=false: %q", sig.VerifyError)
	}
	if !sig.SignatureValid {
		t.Errorf("SignatureValid=false: %q", sig.VerifyError)
	}
	if !sig.CertValid {
		t.Errorf("CertValid=false (fixture cert is valid for 24h)")
	}
	if sig.Signer != "Test CMS Signer" {
		t.Errorf("Signer=%q, want %q", sig.Signer, "Test CMS Signer")
	}
	if sig.VerifyError != "" {
		t.Errorf("VerifyError should be empty, got %q", sig.VerifyError)
	}
}

func TestVerifyRejectsContentTamper(t *testing.T) {
	inputPath := createTestPDF(t)
	signed := signTestPDFFixture(t, inputPath)

	// Flip a byte well inside the signed body (position 10 is the "%PDF-1.7\n" header's LF).
	// Position 10 is inside range 1 of the byte range → invalidates the hash.
	pos := 10
	signed[pos] ^= 0x01

	signedPath := filepath.Join(t.TempDir(), "signed.pdf")
	if err := os.WriteFile(signedPath, signed, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	res, err := Verify(VerifyOptions{InputPath: signedPath})
	if err != nil {
		// A parser-level failure is also an acceptable rejection.
		t.Logf("Verify rejected by parse error: %v", err)
		return
	}
	if len(res.Signatures) == 0 {
		t.Fatal("expected the signature to still be enumerated so verify can report failure")
	}
	sig := res.Signatures[0]
	if sig.HashMatch {
		t.Error("HashMatch should be false after content tamper")
	}
	if sig.SignatureValid {
		t.Error("SignatureValid should be false after content tamper")
	}
	if sig.VerifyError == "" {
		t.Error("VerifyError should describe the failure")
	}
}

func TestVerifyRejectsAppendAfterEOF(t *testing.T) {
	inputPath := createTestPDF(t)
	signed := signTestPDFFixture(t, inputPath)

	signed = append(signed, []byte(" extra unsigned bytes")...)

	signedPath := filepath.Join(t.TempDir(), "signed.pdf")
	if err := os.WriteFile(signedPath, signed, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	res, err := Verify(VerifyOptions{InputPath: signedPath})
	if err != nil {
		t.Logf("Verify rejected by parse error (acceptable): %v", err)
		return
	}
	if len(res.Signatures) == 0 {
		return // parser refused — also acceptable
	}
	sig := res.Signatures[0]
	if sig.ByteRangeValid {
		t.Error("ByteRangeValid should be false when data extends past byte range")
	}
	if sig.SignatureValid {
		t.Error("SignatureValid should be false when byte range is invalid")
	}
}
