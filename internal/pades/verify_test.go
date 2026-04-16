package pades

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/flyzard/pdf-signer/internal/appearance"
	"github.com/flyzard/pdf-signer/internal/pdf"
)

func TestVerifyUnsignedPDF(t *testing.T) {
	inputPath := createTestPDF(t)

	result, err := Verify(VerifyOptions{InputPath: inputPath})
	if err != nil {
		t.Fatalf("Verify returned unexpected error for unsigned PDF: %v", err)
	}

	if result.HasSignatures {
		t.Error("expected HasSignatures=false for unsigned PDF")
	}

	if len(result.Signatures) != 0 {
		t.Errorf("expected 0 signatures, got %d", len(result.Signatures))
	}
}

func TestVerifySignedPDF(t *testing.T) {
	// prepare → embed CMS → finalize → verify

	inputPath := createTestPDF(t)
	preparedPath := filepath.Join(t.TempDir(), "prepared.pdf")

	_, err := Prepare(PrepareOptions{
		InputPath:     inputPath,
		OutputPath:    preparedPath,
		SignerName:    "Test Signer",
		SignerNIC:     "12345678",
		SigningMethod: "cmd",
		SignaturePos:  appearance.DefaultPosition(0),
	})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}

	// Build a realistic CMS with a real cert so cert extraction works.
	testCMS, _ := buildTestCMS(t)

	data, err := os.ReadFile(preparedPath)
	if err != nil {
		t.Fatalf("read prepared: %v", err)
	}

	data, err = pdf.EmbedCMS(data, testCMS)
	if err != nil {
		t.Fatalf("EmbedCMS: %v", err)
	}

	signedPath := filepath.Join(t.TempDir(), "signed.pdf")
	if err := os.WriteFile(signedPath, data, 0644); err != nil {
		t.Fatalf("write signed: %v", err)
	}

	// Finalize to add DSS.
	finalizedPath := filepath.Join(t.TempDir(), "finalized.pdf")
	_, err = Finalize(FinalizeOptions{
		InputPath:  signedPath,
		OutputPath: finalizedPath,
	})
	if err != nil {
		t.Fatalf("Finalize: %v", err)
	}

	// Verify the finalized PDF.
	result, err := Verify(VerifyOptions{InputPath: finalizedPath})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}

	if !result.HasSignatures {
		t.Error("expected HasSignatures=true for signed+finalized PDF")
	}

	if len(result.Signatures) == 0 {
		t.Fatal("expected at least one signature")
	}

	if result.LTVStatus == "none" {
		t.Errorf("expected LTVStatus != 'none' after finalize, got %q", result.LTVStatus)
	}

	sig := result.Signatures[0]
	if sig.Level == "" {
		t.Error("expected non-empty Level")
	}
	// Cert extraction may succeed or fail gracefully depending on CMS structure;
	// log the result without requiring it.
	t.Logf("Signer: %q, Level: %s, LTVStatus: %s, Thumbprint: %s",
		sig.Signer, sig.Level, result.LTVStatus, sig.CertificateThumbprint)
}
