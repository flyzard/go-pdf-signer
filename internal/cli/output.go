package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
)

// OutputVersion is the schema version stamped on every JSON emission. Bump
// only on a breaking change; additive fields keep the same version string.
const OutputVersion = "1.0"

// Exit codes per requirements §8.1.4. The numeric contract is load-bearing
// for any calling service that distinguishes failure modes without parsing
// JSON — e.g. a CI step that wants to retry network errors but not invalid
// args.
const (
	ExitSuccess            = 0
	ExitGeneralFailure     = 1
	ExitInvalidArgs        = 2
	ExitNetwork            = 3
	ExitVerificationFailed = 4
	ExitPlaceholderTooSmall = 5
)

type EmbedOutput struct {
	Success bool `json:"success"`
}

type ErrorOutput struct {
	Error   string `json:"error"`
	Message string `json:"message"`
	Detail  string `json:"detail,omitempty"`
}

// PrintJSON marshals v, injects the version envelope, and writes it to stdout.
// v must marshal to a JSON object (not array or scalar) — every CLI output
// type in this package does.
func PrintJSON(v any) {
	body, err := marshalIndentedWithVersion(v)
	if err != nil {
		fmt.Fprintf(os.Stderr, "{\"version\":%q,\"error\":\"OUTPUT_FAILED\",\"message\":%q}\n",
			OutputVersion, err.Error())
		os.Exit(ExitInvalidArgs)
	}
	os.Stdout.Write(body)
	os.Stdout.Write([]byte("\n"))
}

// PrintError emits the error envelope to stderr and exits with the mapped
// status. code is the machine-readable token surfaced in the "error" field;
// the exit status is derived from exitCodeFor unless the caller uses
// FatalfWithExit to force a specific code.
func PrintError(code, message string, detail ...string) {
	printErrorAndExit(code, message, exitCodeFor(code), detail...)
}

// Fatalf is the most common error exit — code becomes the "error" field,
// formatted message becomes "message", and the exit status is derived from
// the code's class.
func Fatalf(code, format string, args ...any) {
	PrintError(code, fmt.Sprintf(format, args...))
}

func printErrorAndExit(code, message string, exit int, detail ...string) {
	out := ErrorOutput{Error: code, Message: message}
	if len(detail) > 0 {
		out.Detail = detail[0]
	}
	body, err := marshalIndentedWithVersion(out)
	if err != nil {
		fmt.Fprintf(os.Stderr, "{\"version\":%q,\"error\":\"OUTPUT_FAILED\",\"message\":%q}\n",
			OutputVersion, err.Error())
	} else {
		os.Stderr.Write(body)
		os.Stderr.Write([]byte("\n"))
	}
	os.Exit(exit)
}

// exitCodeFor maps an error code string to its numeric exit status. Unknown
// codes default to ExitGeneralFailure (1). Keep this table in sync with the
// requirements doc §8.1.4 exit-code contract.
func exitCodeFor(code string) int {
	switch code {
	case "INVALID_ARGS":
		return ExitInvalidArgs
	case "NETWORK_ERROR", "OCSP_FETCH_FAILED", "CRL_FETCH_FAILED", "TSA_FETCH_FAILED", "AIA_FETCH_FAILED":
		return ExitNetwork
	case "VERIFICATION_FAILED", "SIGNATURE_INVALID", "BYTE_RANGE_INVALID", "CHAIN_INVALID", "REVOCATION_FAILED":
		return ExitVerificationFailed
	case "PLACEHOLDER_TOO_SMALL":
		return ExitPlaceholderTooSmall
	}
	return ExitGeneralFailure
}

// marshalIndentedWithVersion marshals v as a JSON object and splices a
// top-level "version" field as the first key, preserving Go struct field
// order for every following key. v must be non-nil and must marshal to a
// JSON object; any other shape is a programmer error.
func marshalIndentedWithVersion(v any) ([]byte, error) {
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, err
	}
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) < 2 || trimmed[0] != '{' {
		return nil, fmt.Errorf("marshalIndentedWithVersion: expected JSON object, got %q", string(raw))
	}
	versionLine := fmt.Sprintf("{\n  \"version\": %q", OutputVersion)
	rest := raw[1:] // drop the leading '{'
	// If the object was non-empty, the next non-space byte after '{' is '"' —
	// prepend a comma. If it was "{}", rest is "}" (possibly with whitespace).
	afterBrace := bytes.TrimLeft(rest, " \t\n\r")
	if len(afterBrace) == 0 || afterBrace[0] == '}' {
		return append([]byte(versionLine), rest...), nil
	}
	return append([]byte(versionLine+","), rest...), nil
}
