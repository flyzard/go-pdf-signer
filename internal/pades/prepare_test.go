package pades

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/flyzard/pdf-signer/internal/appearance"
	"github.com/flyzard/pdf-signer/internal/pdf"
)

// createTestPDF writes a minimal valid PDF to a temp directory and returns the path.
func createTestPDF(t *testing.T) string {
	t.Helper()

	content := "" +
		"%PDF-1.7\n" +
		"1 0 obj\n" +
		"<< /Type /Catalog /Pages 2 0 R >>\n" +
		"endobj\n" +
		"2 0 obj\n" +
		"<< /Type /Pages /Kids [3 0 R] /Count 1 >>\n" +
		"endobj\n" +
		"3 0 obj\n" +
		"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\n" +
		"endobj\n" +
		"xref\n" +
		"0 4\n" +
		"0000000000 65535 f \n" +
		"0000000009 00000 n \n" +
		"0000000058 00000 n \n" +
		"0000000115 00000 n \n" +
		"trailer\n" +
		"<< /Size 4 /Root 1 0 R >>\n" +
		"startxref\n" +
		"186\n" +
		"%%EOF\n"

	dir := t.TempDir()
	path := filepath.Join(dir, "test.pdf")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("createTestPDF: %v", err)
	}
	return path
}

func TestPrepare(t *testing.T) {
	inputPath := createTestPDF(t)
	outputPath := filepath.Join(t.TempDir(), "prepared.pdf")

	result, err := Prepare(PrepareOptions{
		InputPath:     inputPath,
		OutputPath:    outputPath,
		SignerName:    "Test User",
		SignerNIC:     "12345678",
		SigningMethod: "cmd",
		SignaturePos:  appearance.DefaultPosition(0),
	})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}

	// Verify hash algorithm.
	if result.HashAlgorithm != "SHA-256" {
		t.Errorf("HashAlgorithm = %q, want SHA-256", result.HashAlgorithm)
	}

	// Verify field name.
	if result.FieldName != "Sig_1" {
		t.Errorf("FieldName = %q, want Sig_1", result.FieldName)
	}

	// Verify hash is valid base64 of 32 bytes.
	hashBytes, err := base64.StdEncoding.DecodeString(result.Hash)
	if err != nil {
		t.Fatalf("hash base64 decode: %v", err)
	}
	if len(hashBytes) != 32 {
		t.Errorf("hash length = %d bytes, want 32", len(hashBytes))
	}

	// Verify output file exists.
	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}

	// Verify output contains signature placeholder.
	if !strings.Contains(string(data), pdf.SignaturePlaceholder()) {
		t.Error("output does not contain signature placeholder")
	}

	// Verify output is a parseable PDF.
	_, err = pdf.Parse(data)
	if err != nil {
		t.Fatalf("parse output: %v", err)
	}

	// Verify the ByteRange was patched (should not contain [0 0 0 0]).
	if strings.Contains(string(data), "/ByteRange [0 0 0 0]") {
		t.Error("ByteRange was not patched — still contains [0 0 0 0]")
	}
}

func TestPrepareMultipleSignatures(t *testing.T) {
	inputPath := createTestPDF(t)
	firstOutput := filepath.Join(t.TempDir(), "first.pdf")

	// First signature.
	result1, err := Prepare(PrepareOptions{
		InputPath:     inputPath,
		OutputPath:    firstOutput,
		SignerName:    "Signer One",
		SignerNIC:     "11111111",
		SigningMethod: "cmd",
		SignaturePos:  appearance.DefaultPosition(0),
	})
	if err != nil {
		t.Fatalf("Prepare first: %v", err)
	}
	if result1.FieldName != "Sig_1" {
		t.Errorf("first FieldName = %q, want Sig_1", result1.FieldName)
	}

	// Embed dummy CMS into the first prepared PDF.
	data, err := os.ReadFile(firstOutput)
	if err != nil {
		t.Fatalf("read first output: %v", err)
	}

	// Create a dummy CMS (just non-zero bytes to fill the placeholder).
	dummyCMS := make([]byte, 256)
	for i := range dummyCMS {
		dummyCMS[i] = byte(i % 256)
	}
	data, err = pdf.EmbedCMS(data, dummyCMS)
	if err != nil {
		t.Fatalf("EmbedCMS: %v", err)
	}

	// Write the "signed" first PDF.
	signedFirst := filepath.Join(t.TempDir(), "signed_first.pdf")
	if err := os.WriteFile(signedFirst, data, 0644); err != nil {
		t.Fatalf("write signed first: %v", err)
	}

	// Second signature on top of the signed first.
	secondOutput := filepath.Join(t.TempDir(), "second.pdf")
	result2, err := Prepare(PrepareOptions{
		InputPath:     signedFirst,
		OutputPath:    secondOutput,
		SignerName:    "Signer Two",
		SignerNIC:     "22222222",
		SigningMethod: "cc",
		SignaturePos:  appearance.DefaultPosition(1),
	})
	if err != nil {
		t.Fatalf("Prepare second: %v", err)
	}

	if result2.FieldName != "Sig_2" {
		t.Errorf("second FieldName = %q, want Sig_2", result2.FieldName)
	}

	// Hashes must be different.
	if result1.Hash == result2.Hash {
		t.Error("first and second hashes are identical, expected different")
	}
}
