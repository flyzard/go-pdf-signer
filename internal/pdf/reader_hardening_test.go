package pdf

import (
	"fmt"
	"strings"
	"testing"
)

// withMaxTokenBytes temporarily reduces the parser's per-token size cap so
// tests can exercise the limit without allocating MB-sized fixtures.
func withMaxTokenBytes(t *testing.T, n int) {
	t.Helper()
	prev := maxPDFTokenBytes
	maxPDFTokenBytes = n
	t.Cleanup(func() { maxPDFTokenBytes = prev })
}

func TestParseStringRejectsOversizedLiteral(t *testing.T) {
	withMaxTokenBytes(t, 16)
	input := []byte("<< /K (" + strings.Repeat("a", 32) + ") >>")
	if _, err := parseDict(input); err == nil {
		t.Fatal("expected error for oversized literal string, got nil")
	}
}

func TestParseHexStringRejectsOversized(t *testing.T) {
	withMaxTokenBytes(t, 16)
	input := []byte("<< /K <" + strings.Repeat("ab", 32) + "> >>")
	if _, err := parseDict(input); err == nil {
		t.Fatal("expected error for oversized hex string, got nil")
	}
}

func TestParseXRefRejectsNegativeStartXRef(t *testing.T) {
	// Build a PDF whose startxref points to a negative int64. Parse must fail
	// without panicking.
	prefix := "%PDF-1.7\n1 0 obj\n<< /Type /Catalog >>\nendobj\n"
	suffix := "startxref\n-100\n%%EOF\n"
	data := []byte(prefix + suffix)
	_, err := Parse(data)
	if err == nil {
		t.Fatal("expected error for negative startxref, got nil")
	}
}

func TestReadDictObjectRejectsNegativeOffset(t *testing.T) {
	doc := &Document{
		Data: []byte("%PDF-1.7\n"),
		XRef: map[int]int64{5: -1},
	}
	if _, err := doc.ReadDictObject(Ref{Number: 5, Generation: 0}); err == nil {
		t.Fatal("expected error for negative xref offset, got nil")
	}
}

func TestParseRejectsBadTrailerSize(t *testing.T) {
	// Build a PDF whose trailer /Size is negative. The parser must reject.
	objects := []string{
		"1 0 obj\n<< /Type /Catalog >>\nendobj\n",
	}
	data := buildPDFBytes(objects, "")
	// Patch "/Size 2" → "/Size -1".
	patched := []byte(strings.Replace(string(data), "/Size 2", "/Size -1", 1))
	if _, err := Parse(patched); err == nil {
		t.Fatal("expected error for negative trailer /Size, got nil")
	}
}

func TestParseXRefRejectsSubsectionOverflow(t *testing.T) {
	// firstObj + count would overflow int. Must be rejected.
	prefix := "%PDF-1.7\n1 0 obj\n<< /Type /Catalog >>\nendobj\n"
	xrefStart := len(prefix)
	// Use a firstObj near math.MaxInt64-safe range — we just want the parser to
	// detect that firstObj + count exceeds math.MaxInt.
	xref := fmt.Sprintf(
		"xref\n9223372036854775800 100\n0000000000 65535 f \ntrailer\n<< /Size 1 /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n",
		xrefStart)
	data := []byte(prefix + xref)
	if _, err := Parse(data); err == nil {
		t.Fatal("expected error for xref subsection overflow, got nil")
	}
}
