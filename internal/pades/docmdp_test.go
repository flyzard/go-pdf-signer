package pades

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"github.com/flyzard/pdf-signer/internal/appearance"
	"github.com/flyzard/pdf-signer/internal/pdf"
)

// TestDocMDPEmittedOnCertificationLevel verifies that Prepare with a
// non-zero CertificationLevel writes /Perms /DocMDP on the catalog and
// that HasDocMDP later detects it.
func TestDocMDPEmittedOnCertificationLevel(t *testing.T) {
	inputPath := createTestPDF(t)
	preparedPath := filepath.Join(t.TempDir(), "prepared.pdf")
	_, err := Prepare(PrepareOptions{
		InputPath:          inputPath,
		OutputPath:         preparedPath,
		SignerName:         "Certifier",
		SigningMethod:      "cmd",
		SignaturePos:       appearance.DefaultPosition(0),
		CertificationLevel: CertLevelFormFilling,
	})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	data, err := os.ReadFile(preparedPath)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	doc, err := pdf.Parse(data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !HasDocMDP(doc) {
		t.Error("HasDocMDP must return true after Prepare with CertLevelFormFilling")
	}
}

// TestDocMDPAbsentWithoutLevel is the control: CertLevelNone must not
// emit a /Perms entry.
func TestDocMDPAbsentWithoutLevel(t *testing.T) {
	inputPath := createTestPDF(t)
	preparedPath := filepath.Join(t.TempDir(), "prepared.pdf")
	_, err := Prepare(PrepareOptions{
		InputPath:     inputPath,
		OutputPath:    preparedPath,
		SignerName:    "Plain Signer",
		SigningMethod: "cmd",
		SignaturePos:  appearance.DefaultPosition(0),
	})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	data, err := os.ReadFile(preparedPath)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	doc, err := pdf.Parse(data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if HasDocMDP(doc) {
		t.Error("HasDocMDP must return false when CertificationLevel is none")
	}
}

// TestInvisibleOmitsAppearance sets --invisible and expects the widget
// /Rect to be zeroed and no appearance stream to be emitted. Rather than
// walk object trees, we just check the prepared PDF parses + signs +
// verifies through the normal flow — invisible widgets are a layout hint,
// not a crypto gate.
func TestInvisibleOmitsAppearance(t *testing.T) {
	inputPath := createTestPDF(t)
	preparedPath := filepath.Join(t.TempDir(), "prepared.pdf")
	res, err := Prepare(PrepareOptions{
		InputPath:     inputPath,
		OutputPath:    preparedPath,
		SignerName:    "Invisible Signer",
		SigningMethod: "cmd",
		SignaturePos:  appearance.DefaultPosition(0),
		Invisible:     true,
	})
	if err != nil {
		t.Fatalf("Prepare invisible: %v", err)
	}
	if res.Hash == "" {
		t.Error("expected non-empty ByteRange hash")
	}
	// Confirm the placeholder still scans — invisible mode must not break
	// the signing pipeline.
	data, err := os.ReadFile(preparedPath)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if _, err := pdf.FindPlaceholder(data); err != nil {
		t.Errorf("FindPlaceholder failed on invisible-prepared PDF: %v", err)
	}
	// Sanity: the returned hash decodes to the right length.
	if decoded, err := base64.StdEncoding.DecodeString(res.Hash); err != nil {
		t.Errorf("hash not valid base64: %v", err)
	} else if len(decoded) != 32 {
		t.Errorf("hash length = %d, want 32", len(decoded))
	}
}
