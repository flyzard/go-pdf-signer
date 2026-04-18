package appearance

import (
	"strings"
	"testing"
)

func TestTruncateForStampLeavesShortIntact(t *testing.T) {
	if got := truncateForStamp("John Doe", 50); got != "John Doe" {
		t.Errorf("got %q, want unchanged", got)
	}
}

func TestTruncateForStampTrimsLongNamesWithEllipsis(t *testing.T) {
	long := strings.Repeat("A", 200)
	got := truncateForStamp(long, 20)
	if len([]rune(got)) != 20 {
		t.Errorf("truncation length = %d runes, want 20", len([]rune(got)))
	}
	if !strings.HasSuffix(got, "...") {
		t.Errorf("truncated string should end in ...: %q", got)
	}
}

func TestTruncateForStampRespectsRuneBoundaries(t *testing.T) {
	// 10 multi-byte Portuguese chars, maxChars=5 → 2 runes + "..."
	in := "áéíóúâêôãõç"
	got := truncateForStamp(in, 5)
	if rc := len([]rune(got)); rc != 5 {
		t.Errorf("rune count = %d, want 5", rc)
	}
	// Must decode as valid UTF-8 — no mid-codepoint cut.
	if strings.ContainsRune(got, '\uFFFD') {
		t.Errorf("truncation broke a codepoint: %q", got)
	}
}

func TestTruncateForStampZeroBudgetReturnsEmpty(t *testing.T) {
	if got := truncateForStamp("anything", 0); got != "" {
		t.Errorf("maxChars=0 should produce empty string, got %q", got)
	}
}

func TestTruncateForStampTinyBudgetSkipsEllipsis(t *testing.T) {
	// Budget <= 3 → no room for "...", emit raw prefix.
	got := truncateForStamp("ABCDEFG", 2)
	if got != "AB" {
		t.Errorf("got %q, want %q", got, "AB")
	}
}
