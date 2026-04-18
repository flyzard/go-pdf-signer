package pdf

import (
	"bytes"
	"strconv"
	"testing"
)

func TestParseRejectsEncryptedPDF(t *testing.T) {
	// Build a PDF whose trailer carries an /Encrypt entry.
	objs := []string{"1 0 obj\n<< /Type /Catalog >>\nendobj\n"}
	data := buildPDFBytes(objs, "/Encrypt 99 0 R ")
	if _, err := Parse(data); err == nil {
		t.Fatal("expected Parse to reject encrypted PDF")
	}
}

func TestWriterPreservesTrailerID(t *testing.T) {
	// Base PDF with /ID array. buildPDFBytes doesn't produce one, so we
	// construct a minimal PDF manually.
	base := "%PDF-1.7\n" +
		"1 0 obj\n<< /Type /Catalog >>\nendobj\n"
	xrefStart := len(base)
	base += "xref\n0 2\n" +
		"0000000000 65535 f \n" +
		"0000000009 00000 n \n" +
		"trailer\n<< /Size 2 /Root 1 0 R /ID [<ABCDEF> <123456>] >>\n" +
		"startxref\n" +
		strconv.Itoa(xrefStart) + "\n" +
		"%%EOF\n"

	doc, err := Parse([]byte(base))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if _, ok := doc.Trailer["ID"]; !ok {
		t.Fatal("sanity: base trailer should have /ID")
	}

	w := NewWriter(doc)
	w.AddObject(Dict{"Foo": Name("Bar")})

	out, err := w.WriteToBytes()
	if err != nil {
		t.Fatalf("WriteToBytes: %v", err)
	}

	// Re-parse and check /ID survived.
	doc2, err := Parse(out)
	if err != nil {
		t.Fatalf("Parse updated: %v", err)
	}
	id, ok := doc2.Trailer["ID"]
	if !ok {
		t.Fatal("/ID dropped from updated trailer")
	}
	arr, ok := id.([]any)
	if !ok || len(arr) != 2 {
		t.Fatalf("/ID should be 2-element array, got %T %v", id, id)
	}

	// The two hex strings round-trip as []byte.
	first, ok := arr[0].([]byte)
	if !ok || !bytes.Equal(first, []byte{0xAB, 0xCD, 0xEF}) {
		t.Errorf("/ID[0] = %v, want ABCDEF", arr[0])
	}
}

