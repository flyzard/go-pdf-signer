package pades

import (
	"fmt"
	"os"

	"github.com/flyzard/pdf-signer/internal/pdf"
)

// EmbedOptions configures the embed step.
type EmbedOptions struct {
	InputPath  string // Prepared PDF with placeholder
	OutputPath string
	CMSPath    string // Path to DER-encoded CMS blob file
}

// Embed reads a prepared PDF and a CMS blob, embeds the CMS into the placeholder,
// and writes the signed PDF to output.
func Embed(opts EmbedOptions) error {
	preparedData, err := os.ReadFile(opts.InputPath)
	if err != nil {
		return fmt.Errorf("read prepared PDF: %w", err)
	}

	cmsData, err := os.ReadFile(opts.CMSPath)
	if err != nil {
		return fmt.Errorf("read CMS blob: %w", err)
	}

	signedData, err := pdf.EmbedCMS(preparedData, cmsData)
	if err != nil {
		return fmt.Errorf("embed CMS: %w", err)
	}

	if err := os.WriteFile(opts.OutputPath, signedData, 0644); err != nil {
		return fmt.Errorf("write output PDF: %w", err)
	}

	return nil
}
