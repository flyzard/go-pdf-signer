package pdf

import (
	"bytes"
	"path/filepath"
	"testing"
)

// TestIncrementalWrite verifies that AddObject + WriteTo produces valid output.
func TestIncrementalWrite(t *testing.T) {
	srcPath := createTestPDF(t)

	doc, err := Open(srcPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	w := NewWriter(doc)
	newRef := w.AddObject(Dict{
		"Type":  Name("Test"),
		"Value": 42,
	})

	outPath := filepath.Join(t.TempDir(), "out.pdf")
	if err := w.WriteTo(outPath); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}

	// Output must start with the original data.
	outDoc, err := Open(outPath)
	if err != nil {
		t.Fatalf("re-parse: %v", err)
	}

	// Output must be longer than the original.
	if int64(len(outDoc.Data)) <= int64(len(doc.Data)) {
		t.Errorf("output (%d bytes) is not longer than original (%d bytes)", len(outDoc.Data), len(doc.Data))
	}

	// The original bytes must be a prefix of the output.
	if !bytes.HasPrefix(outDoc.Data, doc.Data) {
		t.Error("output does not start with original PDF data")
	}

	// New object must appear in xref.
	if _, ok := outDoc.XRef[newRef.Number]; !ok {
		t.Errorf("new object %d not found in re-parsed xref", newRef.Number)
	}
}

// TestIncrementalWriteStream verifies that AddStream produces valid output.
func TestIncrementalWriteStream(t *testing.T) {
	srcPath := createTestPDF(t)

	doc, err := Open(srcPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	w := NewWriter(doc)
	content := []byte("stream content here")
	streamRef := w.AddStream(content, Dict{
		"Type": Name("EmbeddedStream"),
	})

	outBytes, err := w.WriteToBytes()
	if err != nil {
		t.Fatalf("WriteToBytes: %v", err)
	}

	// Re-parse from bytes.
	outDoc, err := Parse(outBytes)
	if err != nil {
		t.Fatalf("re-parse: %v", err)
	}

	// Stream object must be in xref.
	if _, ok := outDoc.XRef[streamRef.Number]; !ok {
		t.Errorf("stream object %d not found in re-parsed xref", streamRef.Number)
	}

	// The raw stream data must be present in the output bytes.
	if !bytes.Contains(outBytes, content) {
		t.Error("stream content not found in output bytes")
	}
}

// TestUpdateCatalog verifies that UpdateCatalog adds a new catalog to the trailer.
func TestUpdateCatalog(t *testing.T) {
	srcPath := createTestPDF(t)

	doc, err := Open(srcPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	w := NewWriter(doc)

	// Add a dummy DSS dictionary object.
	dssRef := w.AddObject(Dict{
		"Type": Name("DSS"),
	})

	// Register catalog updater that adds /DSS ref.
	w.UpdateCatalog(func(cat Dict) Dict {
		cat["DSS"] = dssRef
		return cat
	})

	outBytes, err := w.WriteToBytes()
	if err != nil {
		t.Fatalf("WriteToBytes: %v", err)
	}

	outDoc, err := Parse(outBytes)
	if err != nil {
		t.Fatalf("re-parse: %v", err)
	}

	// The re-parsed catalog must contain /DSS.
	gotRef, ok := outDoc.Catalog.GetRef("DSS")
	if !ok {
		t.Fatal("re-parsed catalog missing /DSS")
	}
	if gotRef.Number != dssRef.Number {
		t.Errorf("/DSS ref = %d, want %d", gotRef.Number, dssRef.Number)
	}
}
