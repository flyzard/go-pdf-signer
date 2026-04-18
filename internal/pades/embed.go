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

	// Sanity: EmbedCMS overwrites only bytes inside the fixed-size placeholder,
	// so xref and trailer cannot have moved. The one realistic regression —
	// a logic bug that fails to replace the zero hex — is caught here without
	// a full reparse of the output. FindPlaceholder only matches all-zero
	// runs between angle brackets, so real CMS content (which starts with
	// DER `30 82 ...`) will not register even if it contains embedded zero
	// bytes.
	if _, err := pdf.FindPlaceholder(signedData); err == nil {
		return fmt.Errorf("embed CMS: placeholder still present in output")
	}

	if err := pdf.WriteFileAtomic(opts.OutputPath, signedData); err != nil {
		return fmt.Errorf("write output PDF %s: %w", opts.OutputPath, err)
	}

	return nil
}
