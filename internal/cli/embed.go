package cli

import (
	"errors"
	"flag"

	"github.com/flyzard/pdf-signer/internal/pades"
	"github.com/flyzard/pdf-signer/internal/pdf"
)

// RunEmbed handles the "embed" subcommand.
func RunEmbed(args []string) {
	fs := flag.NewFlagSet("embed", flag.ContinueOnError)

	input := fs.String("input", "", "Prepared PDF file path (required)")
	output := fs.String("output", "", "Output signed PDF file path (required)")
	cms := fs.String("cms", "", "DER-encoded CMS blob file path (required)")
	_ = fs.String("field-name", "", "Signature field name (accepted for compatibility)")

	if err := fs.Parse(args); err != nil {
		Fatalf("INVALID_ARGS", "failed to parse arguments: %v", err)
	}

	if *input == "" {
		Fatalf("INVALID_ARGS", "missing required flag: --input")
	}
	if *output == "" {
		Fatalf("INVALID_ARGS", "missing required flag: --output")
	}
	if *cms == "" {
		Fatalf("INVALID_ARGS", "missing required flag: --cms")
	}

	err := pades.Embed(pades.EmbedOptions{
		InputPath:  *input,
		OutputPath: *output,
		CMSPath:    *cms,
	})
	if err != nil {
		if errors.Is(err, pdf.ErrPlaceholderTooSmall) {
			Fatalf("PLACEHOLDER_TOO_SMALL", "CMS does not fit in signature placeholder: %v", err)
		}
		Fatalf("EMBED_FAILED", "embed failed: %v", err)
	}

	PrintJSON(EmbedOutput{Success: true})
}
