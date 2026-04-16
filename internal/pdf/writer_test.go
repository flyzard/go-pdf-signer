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


// TestTrailerSizeCoversAllObjects verifies that the trailer /Size is 1 greater
// than the highest object number, including the catalog object added by UpdateCatalog.
func TestTrailerSizeCoversAllObjects(t *testing.T) {
	srcPath := createTestPDF(t)
	doc, err := Open(srcPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	w := NewWriter(doc)
	// Add two objects: they get numbers 4 and 5 (test PDF has Size=4).
	w.AddObject(Dict{"Type": Name("Test1")})
	w.AddObject(Dict{"Type": Name("Test2")})

	// Update catalog — this adds a catalog object (number 6).
	w.UpdateCatalog(func(cat Dict) Dict {
		cat["TestKey"] = Name("TestValue")
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

	// The catalog should be object 6. Size must be >= 7 to cover it.
	rootRef := outDoc.CatalogRef
	expectedMinSize := rootRef.Number + 1
	actualSize := outDoc.NextObjNum // NextObjNum is set from trailer /Size

	if actualSize < expectedMinSize {
		t.Errorf("trailer /Size = %d, but catalog is object %d — Size must be >= %d",
			actualSize, rootRef.Number, expectedMinSize)
	}

	// Verify the catalog object is accessible via xref.
	if _, ok := outDoc.XRef[rootRef.Number]; !ok {
		t.Errorf("catalog object %d not found in xref", rootRef.Number)
	}
}

// TestBuildBytesIdempotent verifies that WriteToBytes produces identical results on successive calls.
func TestBuildBytesIdempotent(t *testing.T) {
	srcPath := createTestPDF(t)
	doc, err := Open(srcPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	w := NewWriter(doc)
	w.AddObject(Dict{"Type": Name("Test1")})

	w.UpdateCatalog(func(cat Dict) Dict {
		cat["TestKey"] = Name("TestValue")
		return cat
	})

	first, err := w.WriteToBytes()
	if err != nil {
		t.Fatalf("first WriteToBytes: %v", err)
	}

	second, err := w.WriteToBytes()
	if err != nil {
		t.Fatalf("second WriteToBytes: %v", err)
	}

	if !bytes.Equal(first, second) {
		t.Error("WriteToBytes produced different results on second call — buildBytes is not idempotent")
	}
}
