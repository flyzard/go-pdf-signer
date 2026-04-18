package cli

import (
	"context"
	"flag"
	"os"
	"os/signal"
	"syscall"

	"github.com/flyzard/pdf-signer/internal/pades"
)

// RunFinalize handles the "finalize" subcommand.
func RunFinalize(args []string) {
	fs := flag.NewFlagSet("finalize", flag.ContinueOnError)

	input := fs.String("input", "", "Signed PDF file path (required)")
	output := fs.String("output", "", "Output PDF file path with DSS (required)")
	tsaURL := fs.String("tsa-url", "", "RFC 3161 TSA URL for document timestamp (optional)")

	if err := fs.Parse(args); err != nil {
		Fatalf("INVALID_ARGS", "failed to parse arguments: %v", err)
	}

	if *input == "" {
		Fatalf("INVALID_ARGS", "missing required flag: --input")
	}
	if *output == "" {
		Fatalf("INVALID_ARGS", "missing required flag: --output")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	result, err := pades.Finalize(ctx, pades.FinalizeOptions{
		InputPath:  *input,
		OutputPath: *output,
		TSAUrl:     *tsaURL,
	})
	if err != nil {
		Fatalf("FINALIZE_FAILED", "finalize failed: %v", err)
	}

	PrintJSON(struct {
		Success bool `json:"success"`
		*pades.FinalizeResult
	}{true, result})
}
