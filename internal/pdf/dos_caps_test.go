package pdf

import (
	"strings"
	"testing"
)

// TestParserDepthCap verifies MaxParserDepth refuses pathological nesting.
// Crafting a real PDF that blows the stack is hard; we exercise the parser
// directly on a deeply nested dict-of-dict literal.
func TestParserDepthCap(t *testing.T) {
	depth := MaxParserDepth + 50
	body := strings.Repeat("<< /K ", depth) + "0" + strings.Repeat(" >>", depth)
	p := &parser{data: []byte(body)}
	if _, err := p.parseValue(); err == nil {
		t.Fatal("expected depth cap to reject deeply nested dict, got nil")
	}
}

// TestParserDepthAcceptsShallow ensures a reasonable nesting doesn't trip
// the cap.
func TestParserDepthAcceptsShallow(t *testing.T) {
	p := &parser{data: []byte("<< /A << /B << /C 1 >> >> >>")}
	if _, err := p.parseValue(); err != nil {
		t.Fatalf("shallow nesting rejected: %v", err)
	}
}

// TestMaxObjectCountRejectsOversizedTrailer crafts a minimal PDF whose
// trailer /Size exceeds MaxObjectCount and confirms Parse refuses it
// before any xref work runs. The xref tries to reference objects we
// don't serialise, so this also incidentally exercises the size gate as
// the first check after trailer parse.
func TestMaxObjectCountRejectsOversizedTrailer(t *testing.T) {
	// Minimal fixture: one tiny catalog object + an xref table + a
	// crafted trailer. The /Size value below is MaxObjectCount+1 so the
	// Parse gate must fire regardless of whether the xref is coherent.
	pdfBody := "%PDF-1.7\n" +
		"1 0 obj\n<< /Type /Catalog >>\nendobj\n" +
		"xref\n0 2\n" +
		"0000000000 65535 f \n" +
		"0000000009 00000 n \n" +
		"trailer\n" +
		"<< /Size 5000001 /Root 1 0 R >>\n" +
		"startxref\n45\n%%EOF\n"
	if _, err := Parse([]byte(pdfBody)); err == nil {
		t.Fatal("Parse must refuse trailer /Size > MaxObjectCount")
	}
}
