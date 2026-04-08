package cli

import (
	"flag"
	"fmt"
	"strconv"
	"strings"

	"github.com/flyzard/pdf-signer/internal/appearance"
	"github.com/flyzard/pdf-signer/internal/pades"
)

// RunPrepare handles the "prepare" subcommand.
func RunPrepare(args []string) {
	fs := flag.NewFlagSet("prepare", flag.ContinueOnError)

	input := fs.String("input", "", "Input PDF file path (required)")
	output := fs.String("output", "", "Output PDF file path (required)")
	signerName := fs.String("signer-name", "", "Signer name (required)")
	signerNIC := fs.String("signer-nic", "", "Signer NIC (optional)")
	signingMethod := fs.String("signing-method", "cmd", "Signing method: cmd or cc")
	sigPos := fs.String("signature-position", "", "Signature position: page,x,y,w,h (default: auto)")

	if err := fs.Parse(args); err != nil {
		Fatalf("INVALID_ARGS", "failed to parse arguments: %v", err)
	}

	if *input == "" {
		Fatalf("INVALID_ARGS", "missing required flag: --input")
	}
	if *output == "" {
		Fatalf("INVALID_ARGS", "missing required flag: --output")
	}
	if *signerName == "" {
		Fatalf("INVALID_ARGS", "missing required flag: --signer-name")
	}

	// Parse position or use default.
	pos := appearance.DefaultPosition(0)
	if *sigPos != "" {
		var err error
		pos, err = parsePosition(*sigPos)
		if err != nil {
			Fatalf("INVALID_ARGS", "invalid --signature-position: %v", err)
		}
	}

	result, err := pades.Prepare(pades.PrepareOptions{
		InputPath:     *input,
		OutputPath:    *output,
		SignerName:    *signerName,
		SignerNIC:     *signerNIC,
		SigningMethod: *signingMethod,
		SignaturePos:  pos,
	})
	if err != nil {
		Fatalf("PREPARE_FAILED", "prepare failed: %v", err)
	}

	PrintJSON(result)
}

// parsePosition parses "page,x,y,w,h" into an appearance.Position.
func parsePosition(s string) (appearance.Position, error) {
	parts := strings.Split(s, ",")
	if len(parts) != 5 {
		return appearance.Position{}, fmt.Errorf("expected page,x,y,w,h — got %d parts", len(parts))
	}

	page, err := strconv.Atoi(strings.TrimSpace(parts[0]))
	if err != nil {
		return appearance.Position{}, fmt.Errorf("invalid page: %w", err)
	}
	x, err := strconv.ParseFloat(strings.TrimSpace(parts[1]), 64)
	if err != nil {
		return appearance.Position{}, fmt.Errorf("invalid x: %w", err)
	}
	y, err := strconv.ParseFloat(strings.TrimSpace(parts[2]), 64)
	if err != nil {
		return appearance.Position{}, fmt.Errorf("invalid y: %w", err)
	}
	w, err := strconv.ParseFloat(strings.TrimSpace(parts[3]), 64)
	if err != nil {
		return appearance.Position{}, fmt.Errorf("invalid width: %w", err)
	}
	h, err := strconv.ParseFloat(strings.TrimSpace(parts[4]), 64)
	if err != nil {
		return appearance.Position{}, fmt.Errorf("invalid height: %w", err)
	}

	return appearance.Position{
		Page:   page,
		X:      x,
		Y:      y,
		Width:  w,
		Height: h,
	}, nil
}
