package cli

import (
	"flag"

	"github.com/flyzard/pdf-signer/internal/pades"
)

// RunVerify handles the "verify" subcommand.
func RunVerify(args []string) {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)

	input := fs.String("input", "", "PDF file path to verify (required)")

	if err := fs.Parse(args); err != nil {
		Fatalf("INVALID_ARGS", "failed to parse arguments: %v", err)
	}

	if *input == "" {
		Fatalf("INVALID_ARGS", "missing required flag: --input")
	}

	result, err := pades.Verify(pades.VerifyOptions{
		InputPath: *input,
	})
	if err != nil {
		Fatalf("VERIFY_FAILED", "verify failed: %v", err)
	}

	PrintJSON(result)
}
