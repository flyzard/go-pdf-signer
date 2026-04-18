package pades

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// buildPDFBytes assembles a minimal PDF whose body objects are the supplied
// strings (each must already include "N G obj\n", body, and "\nendobj\n").
// Records each object's start offset and writes a correct traditional xref +
// trailer + startxref + EOF marker. Returns the bytes.
//
// extraTrailerKeys, if non-empty, is inlined into the trailer dict (e.g.,
// `/Prev 47`). Only the inline portion is supplied; the helper handles
// `/Size` and `/Root`.
func buildPDFBytes(objects []string, extraTrailerKeys string) []byte {
	var b bytes.Buffer
	b.WriteString("%PDF-1.7\n")
	offsets := make([]int, len(objects))
	for i, o := range objects {
		offsets[i] = b.Len()
		b.WriteString(o)
	}
	xrefStart := b.Len()
	fmt.Fprintf(&b, "xref\n0 %d\n0000000000 65535 f \n", len(objects)+1)
	for _, off := range offsets {
		fmt.Fprintf(&b, "%010d 00000 n \n", off)
	}
	fmt.Fprintf(&b, "trailer\n<< /Size %d /Root 1 0 R %s>>\nstartxref\n%d\n%%%%EOF\n",
		len(objects)+1, extraTrailerKeys, xrefStart)
	return b.Bytes()
}

// writePDFFixture writes the assembled bytes to a temp file and returns the path.
func writePDFFixture(t *testing.T, objects []string, extraTrailerKeys string) string {
	t.Helper()
	data := buildPDFBytes(objects, extraTrailerKeys)
	dir := t.TempDir()
	p := filepath.Join(dir, "fixture.pdf")
	if err := os.WriteFile(p, data, 0600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return p
}
