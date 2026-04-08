package pdf

import (
	"fmt"
	"os"
	"strings"
)

// PlaceholderSize is the byte capacity of the signature /Contents placeholder.
const PlaceholderSize = 16384

// PlaceholderHexLen is the number of hex characters in the placeholder (2 per byte).
const PlaceholderHexLen = PlaceholderSize * 2

// SignaturePlaceholder returns the hex-encoded zero-filled Contents placeholder
// including surrounding angle brackets, ready to embed in a PDF object.
func SignaturePlaceholder() string {
	return "<" + strings.Repeat("0", PlaceholderHexLen) + ">"
}

// writtenObject holds the byte offset (within the incremental section) and
// serialised bytes of a newly added object.
type writtenObject struct {
	ref  Ref
	data []byte
}

// Writer appends new objects to an existing PDF using incremental updates.
type Writer struct {
	doc        *Document
	objects    []writtenObject
	nextObjNum int
	catalogFn  func(Dict) Dict
}

// NewWriter creates a Writer that will append to doc.
func NewWriter(doc *Document) *Writer {
	return &Writer{
		doc:        doc,
		nextObjNum: doc.NextObjNum,
	}
}

// NextObjectNumber returns the object number that will be assigned to the next
// object added via any Add* method.
func (w *Writer) NextObjectNumber() int {
	return w.nextObjNum
}

// cloneDict returns a shallow copy of d.
func cloneDict(d Dict) Dict {
	out := make(Dict, len(d))
	for k, v := range d {
		out[k] = v
	}
	return out
}

// allocRef consumes and returns the next object reference.
func (w *Writer) allocRef() Ref {
	ref := Ref{Number: w.nextObjNum, Generation: 0}
	w.nextObjNum++
	return ref
}

// addRaw stores pre-built object bytes with the given ref.
func (w *Writer) addRaw(ref Ref, data []byte) {
	w.objects = append(w.objects, writtenObject{ref: ref, data: data})
}

// AddObject serialises d as a PDF dictionary object, assigns the next object
// number, stores it, and returns its reference.
func (w *Writer) AddObject(d Dict) Ref {
	ref := w.allocRef()
	body := fmt.Sprintf("%d %d obj\n%s\nendobj\n", ref.Number, ref.Generation, Serialize(d))
	w.addRaw(ref, []byte(body))
	return ref
}

// AddStream creates a stream object whose dictionary is extraDict merged with
// /Length, assigns the next object number, and returns its reference.
func (w *Writer) AddStream(content []byte, extraDict Dict) Ref {
	ref := w.allocRef()

	d := cloneDict(extraDict)
	d["Length"] = len(content)

	var sb strings.Builder
	fmt.Fprintf(&sb, "%d %d obj\n", ref.Number, ref.Generation)
	sb.WriteString(Serialize(d))
	sb.WriteString("\nstream\n")
	sb.Write(content)
	sb.WriteString("\nendstream\nendobj\n")

	w.addRaw(ref, []byte(sb.String()))
	return ref
}

// AddRawObject stores pre-serialised object data (must include "N G obj … endobj")
// and assigns the next object number.
func (w *Writer) AddRawObject(data []byte) Ref {
	ref := w.allocRef()
	w.addRaw(ref, data)
	return ref
}

// AddSignatureObject adds a signature dictionary object with reserved
// /ByteRange and /Contents placeholders that can be patched in-place later.
// Keys "Contents" and "ByteRange" in d are ignored; they are handled here.
func (w *Writer) AddSignatureObject(d Dict) Ref {
	ref := w.allocRef()

	var sb strings.Builder
	fmt.Fprintf(&sb, "%d %d obj\n<<", ref.Number, ref.Generation)

	// Write all keys except Contents and ByteRange (handled specially below).
	for k, v := range d {
		if k == "Contents" || k == "ByteRange" {
			continue
		}
		fmt.Fprintf(&sb, " /%s %s", k, Serialize(v))
	}

	// /ByteRange placeholder – padded to ~60 chars so real values fit.
	byteRangeLine := "/ByteRange [0 0 0 0]"
	// Pad to 60 chars total so the signer can overwrite without shifting bytes.
	for len(byteRangeLine) < 60 {
		byteRangeLine += " "
	}
	sb.WriteString(" ")
	sb.WriteString(byteRangeLine)

	// /Contents placeholder – exactly PlaceholderHexLen zero hex chars.
	sb.WriteString(" /Contents ")
	sb.WriteString(SignaturePlaceholder())

	sb.WriteString(" >>\nendobj\n")

	w.addRaw(ref, []byte(sb.String()))
	return ref
}

// UpdateCatalog registers a transform function applied to a clone of the
// original catalog when writing. A new catalog object is appended and the new
// trailer /Root points to it.
func (w *Writer) UpdateCatalog(fn func(Dict) Dict) {
	w.catalogFn = fn
}

// WriteTo writes the incremental update to path (creates or truncates the file).
// The output is: original PDF bytes + "\n" + new objects + xref + trailer.
func (w *Writer) WriteTo(path string) error {
	data, err := w.buildBytes()
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

// WriteToBytes is a convenience wrapper that returns the complete updated PDF
// bytes without writing a file.
func (w *Writer) WriteToBytes() ([]byte, error) {
	return w.buildBytes()
}

func (w *Writer) buildBytes() ([]byte, error) {
	// Determine the root reference for the new trailer.
	rootRef := w.doc.CatalogRef

	// Snapshot the objects already pending before (possibly) adding catalog.
	pendingObjects := w.objects

	// If the catalog should be updated, build and add a new catalog object.
	var extraObjects []writtenObject
	if w.catalogFn != nil {
		newCat := w.catalogFn(cloneDict(w.doc.Catalog))
		catRef := w.allocRef()
		catBody := fmt.Sprintf("%d %d obj\n%s\nendobj\n", catRef.Number, catRef.Generation, Serialize(newCat))
		extraObjects = append(extraObjects, writtenObject{ref: catRef, data: []byte(catBody)})
		rootRef = catRef
	}

	// Combine all objects in order.
	allObjects := append(pendingObjects, extraObjects...)

	// Base offset: length of original data + 1 (for the separating "\n").
	baseOffset := int64(len(w.doc.Data)) + 1

	// --- Build xref table and object bytes ---
	type xrefEntry struct {
		objNum int
		offset int64
	}
	var entries []xrefEntry
	var objBuf []byte

	cursor := baseOffset
	for _, wo := range allObjects {
		entries = append(entries, xrefEntry{objNum: wo.ref.Number, offset: cursor})
		objBuf = append(objBuf, wo.data...)
		cursor += int64(len(wo.data))
	}

	// xref section offset.
	xrefOffset := cursor

	// Build xref text.
	var xrefBuf strings.Builder
	xrefBuf.WriteString("xref\n")
	for _, e := range entries {
		fmt.Fprintf(&xrefBuf, "%d 1\n", e.objNum)
		// 20-byte entry: 10-digit offset, space, 5-digit gen, space, 'n', space, \n
		fmt.Fprintf(&xrefBuf, "%010d 00000 n \n", e.offset)
	}

	// Build new trailer dictionary.
	trailerDict := Dict{
		"Size": w.nextObjNum,
		"Root": rootRef,
		"Prev": w.doc.XRefOffset,
	}
	if info, ok := w.doc.Trailer.GetRef("Info"); ok {
		trailerDict["Info"] = info
	}

	xrefBuf.WriteString("trailer\n")
	xrefBuf.WriteString(Serialize(trailerDict))
	xrefBuf.WriteString("\n")
	fmt.Fprintf(&xrefBuf, "startxref\n%d\n%%%%EOF\n", xrefOffset)

	// Assemble final output.
	var out []byte
	out = append(out, w.doc.Data...)
	out = append(out, '\n')
	out = append(out, objBuf...)
	out = append(out, []byte(xrefBuf.String())...)

	return out, nil
}
