package pades

import (
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"

	"github.com/flyzard/pdf-signer/internal/appearance"
	"github.com/flyzard/pdf-signer/internal/pdf"
)

func TestEmbed(t *testing.T) {
	// 1. Create test PDF.
	inputPath := createTestPDF(t)

	// 2. Prepare the PDF to get a prepared PDF with placeholder.
	preparedPath := filepath.Join(t.TempDir(), "prepared.pdf")
	_, err := Prepare(PrepareOptions{
		InputPath:     inputPath,
		OutputPath:    preparedPath,
		SignerName:    "Test User",
		SignerNIC:     "12345678",
		SigningMethod: "cmd",
		SignaturePos:  appearance.DefaultPosition(0),
	})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}

	// 3. Create a fake CMS blob (100 random bytes).
	cmsData := make([]byte, 100)
	if _, err := rand.Read(cmsData); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}

	// 4. Write fake CMS to a temp file.
	cmsPath := filepath.Join(t.TempDir(), "fake.cms")
	if err := os.WriteFile(cmsPath, cmsData, 0644); err != nil {
		t.Fatalf("write CMS file: %v", err)
	}

	// 5. Call Embed.
	outputPath := filepath.Join(t.TempDir(), "signed.pdf")
	err = Embed(EmbedOptions{
		InputPath:  preparedPath,
		OutputPath: outputPath,
		CMSPath:    cmsPath,
	})
	if err != nil {
		t.Fatalf("Embed: %v", err)
	}

	// 6. Verify: output file exists.
	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}

	// Output is a valid PDF (pdf.Parse succeeds).
	if _, err := pdf.Parse(data); err != nil {
		t.Fatalf("parse signed PDF: %v", err)
	}

	// Placeholder is gone (pdf.FindPlaceholder returns error).
	if _, err := pdf.FindPlaceholder(data); err == nil {
		t.Error("expected FindPlaceholder to fail after embed, but it succeeded — placeholder still present")
	}
}

func TestEmbedCMSTooLarge(t *testing.T) {
	// 1. Prepare a PDF.
	inputPath := createTestPDF(t)
	preparedPath := filepath.Join(t.TempDir(), "prepared.pdf")
	_, err := Prepare(PrepareOptions{
		InputPath:     inputPath,
		OutputPath:    preparedPath,
		SignerName:    "Test User",
		SignerNIC:     "12345678",
		SigningMethod: "cmd",
		SignaturePos:  appearance.DefaultPosition(0),
	})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}

	// 2. Create CMS blob of PlaceholderSize+1 bytes.
	oversizedCMS := make([]byte, pdf.PlaceholderSize+1)

	// 3. Write oversized CMS to temp file.
	cmsPath := filepath.Join(t.TempDir(), "oversized.cms")
	if err := os.WriteFile(cmsPath, oversizedCMS, 0644); err != nil {
		t.Fatalf("write CMS file: %v", err)
	}

	// 4. Call Embed — should return an error.
	outputPath := filepath.Join(t.TempDir(), "signed.pdf")
	err = Embed(EmbedOptions{
		InputPath:  preparedPath,
		OutputPath: outputPath,
		CMSPath:    cmsPath,
	})
	if err == nil {
		t.Fatal("expected error for oversized CMS, got nil")
	}
}
