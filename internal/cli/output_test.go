package cli

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestMarshalEnvelopeStamps verifies every output carries a top-level
// "version" field positioned first in the emitted JSON (load-bearing for
// callers that grep the first few bytes) and that original struct fields
// follow.
func TestMarshalEnvelopeStamps(t *testing.T) {
	type payload struct {
		Hash      string `json:"hash"`
		Algorithm string `json:"hash_algorithm"`
	}
	out, err := marshalIndentedWithVersion(payload{Hash: "abc", Algorithm: "SHA-256"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.HasPrefix(string(out), "{\n  \"version\": \"1.0\",") {
		t.Fatalf("version key must come first, got: %s", out)
	}

	var decoded map[string]any
	if err := json.Unmarshal(out, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded["version"] != OutputVersion {
		t.Errorf("version = %v, want %q", decoded["version"], OutputVersion)
	}
	if decoded["hash"] != "abc" || decoded["hash_algorithm"] != "SHA-256" {
		t.Errorf("original fields dropped or mutated: %v", decoded)
	}
}

// TestMarshalEnvelopeHandlesEmptyObject guards the boundary case where the
// caller's struct has no exported fields — the envelope must still close
// cleanly with just the version key.
func TestMarshalEnvelopeHandlesEmptyObject(t *testing.T) {
	out, err := marshalIndentedWithVersion(struct{}{})
	if err != nil {
		t.Fatalf("marshal empty: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(out, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(decoded) != 1 || decoded["version"] != OutputVersion {
		t.Fatalf("empty envelope should contain only version, got %v", decoded)
	}
}

// TestExitCodeMapping pins the §8.1.4 error-code → exit-status contract so
// downstream callers keep getting the numeric class they filter on.
func TestExitCodeMapping(t *testing.T) {
	cases := map[string]int{
		"INVALID_ARGS":          ExitInvalidArgs,
		"PLACEHOLDER_TOO_SMALL": ExitPlaceholderTooSmall,
		"NETWORK_ERROR":         ExitNetwork,
		"OCSP_FETCH_FAILED":     ExitNetwork,
		"TSA_FETCH_FAILED":      ExitNetwork,
		"VERIFICATION_FAILED":   ExitVerificationFailed,
		"SIGNATURE_INVALID":     ExitVerificationFailed,
		"EMBED_FAILED":          ExitGeneralFailure,
		"SOMETHING_UNKNOWN":     ExitGeneralFailure,
	}
	for code, want := range cases {
		if got := exitCodeFor(code); got != want {
			t.Errorf("exitCodeFor(%q) = %d, want %d", code, got, want)
		}
	}
}
