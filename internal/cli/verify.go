package cli

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/flyzard/pdf-signer/internal/pades"
)

// RunVerify handles the "verify" subcommand.
func RunVerify(args []string) {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)

	input := fs.String("input", "", "PDF file path to verify (required)")
	format := fs.String("format", "json", "Output format: json | text")

	if err := fs.Parse(args); err != nil {
		Fatalf("INVALID_ARGS", "failed to parse arguments: %v", err)
	}
	if *input == "" {
		Fatalf("INVALID_ARGS", "missing required flag: --input")
	}
	if *format != "json" && *format != "text" {
		Fatalf("INVALID_ARGS", "--format must be json or text, got %q", *format)
	}

	result, err := pades.Verify(pades.VerifyOptions{InputPath: *input})
	if err != nil {
		Fatalf("VERIFY_FAILED", "verify failed: %v", err)
	}

	// Exit code 4 (R-7.2.3) when any signature fails a hard crypto gate.
	// Soft gates (ESS binding, cert policy, chain-to-root) only degrade
	// the verdict without forcing exit 4 — they surface in the report so
	// callers can decide for themselves.
	failed := !result.HasSignatures
	for _, sig := range result.Signatures {
		if !sig.ByteRangeValid || !sig.HashMatch || !sig.SignatureValid {
			failed = true
			break
		}
	}

	if *format == "text" {
		printVerifyText(result)
	} else {
		PrintJSON(result)
	}
	if failed {
		os.Exit(ExitVerificationFailed)
	}
}

// printVerifyText emits a human-readable per-signature rundown. Intended
// for operator shells and CI logs; the JSON envelope stays the
// machine-readable contract.
func printVerifyText(r *pades.VerifyResult) {
	if !r.HasSignatures {
		fmt.Println("no signatures found")
		return
	}
	fmt.Printf("%d signature(s). LTV=%s\n", len(r.Signatures), r.LTVStatus)
	for i, s := range r.Signatures {
		fmt.Printf("--- signature %d ---\n", i+1)
		fmt.Printf("  signer:      %s\n", s.Signer)
		fmt.Printf("  issuer:      %s\n", s.CertificateIssuer)
		fmt.Printf("  thumbprint:  %s\n", s.CertificateThumbprint)
		fmt.Printf("  level:       %s\n", s.Level)
		if s.ProfileType != "" {
			fmt.Printf("  qc profile:  type=%s qualified=%v qscd=%v\n", s.ProfileType, s.Qualified, s.QSCD)
		}
		fmt.Printf("  gates:\n")
		for label, ok := range map[string]bool{
			"byte_range_valid":           s.ByteRangeValid,
			"hash_match":                 s.HashMatch,
			"signature_valid":            s.SignatureValid,
			"cert_valid":                 s.CertValid,
			"ess_v2_binding_valid":       s.ESSBindingValid,
			"hash_alg_consistency_valid": s.HashAlgConsistencyOK,
			"cert_policy_valid":          s.CertPolicyValid,
			"chain_to_root_valid":        s.ChainToRootValid,
		} {
			mark := "✗"
			if ok {
				mark = "✓"
			}
			fmt.Printf("    %s %s\n", mark, label)
		}
		if s.VerifyError != "" {
			fmt.Printf("  error:       %s\n", strings.ReplaceAll(s.VerifyError, "\n", " "))
		}
	}
}
