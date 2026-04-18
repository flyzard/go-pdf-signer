package pdf

import (
	"fmt"
	"sort"
	"strings"
)

// PlaceholderSize is the default byte capacity of the signature /Contents
// placeholder. 16 KB comfortably fits a B-B CMS blob with a short chain and
// leaves headroom for a B-T signature timestamp token (≈5-10 KB) injected
// as an unsigned attribute.
const PlaceholderSize = 16384

// MinPlaceholderSize is the smallest placeholder the CLI will accept via
// --placeholder-size. Below this the placeholder-detection heuristic in
// byterange.go may collide with regular hex literals. Chosen as 1 KB.
const MinPlaceholderSize = 1024

// MaxPlaceholderSize caps --placeholder-size to defend against accidental
// disk-bloat or DoS when the size comes from untrusted configuration. 1 MB
// is orders of magnitude above any legitimate PAdES-LTA CMS blob.
const MaxPlaceholderSize = 1 << 20

// SignaturePlaceholder returns the default-sized hex-encoded zero-filled
// /Contents placeholder including surrounding angle brackets. Callers that
// need a non-default size should use SignaturePlaceholderOfSize.
func SignaturePlaceholder() string {
	return SignaturePlaceholderOfSize(PlaceholderSize)
}

// SignaturePlaceholderOfSize returns a `<0...0>` placeholder sized to hold
// size bytes of CMS (2*size hex chars between the angle brackets).
func SignaturePlaceholderOfSize(size int) string {
	return "<" + strings.Repeat("0", size*2) + ">"
}

// writtenObject holds the byte offset (within the incremental section) and
// serialised bytes of a newly added object.
type writtenObject struct {
	ref  Ref
	data []byte
}

// Writer appends new objects to an existing PDF using incremental updates.
type Writer struct {
	doc             *Document
	objects         []writtenObject
	nextObjNum      int
	catalogFn       func(Dict) Dict
	placeholderSize int // 0 = use PlaceholderSize default
}

// NewWriter creates a Writer that will append to doc. Uses PlaceholderSize
// bytes for any signature placeholder it emits; override via
// SetPlaceholderSize.
func NewWriter(doc *Document) *Writer {
	return &Writer{
		doc:        doc,
		nextObjNum: doc.NextObjNum,
	}
}

// SetPlaceholderSize overrides the default signature placeholder capacity
// for this Writer. Must be within [MinPlaceholderSize, MaxPlaceholderSize].
// Passing 0 resets to the default. Returns an error if size is out of
// range; no error when size equals the current setting.
func (w *Writer) SetPlaceholderSize(size int) error {
	if size == 0 {
		w.placeholderSize = 0
		return nil
	}
	if size < MinPlaceholderSize || size > MaxPlaceholderSize {
		return fmt.Errorf("placeholder size %d out of range [%d..%d]", size, MinPlaceholderSize, MaxPlaceholderSize)
	}
	w.placeholderSize = size
	return nil
}

// PlaceholderSize returns the placeholder capacity this Writer will use for
// new signature objects.
func (w *Writer) PlaceholderSize() int {
	if w.placeholderSize == 0 {
		return PlaceholderSize
	}
	return w.placeholderSize
}

// NextObjectNumber returns the object number that will be assigned to the next
// object added via any Add* method.
func (w *Writer) NextObjectNumber() int {
	return w.nextObjNum
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

// ReplaceObject re-emits an existing object (same ref number, same
// generation) with a new dictionary body. Intended for incremental-update
// edits of objects that already live in the base PDF — e.g. appending a
// signature widget to a page's /Annots. The PDF reader follows the xref
// /Prev chain bottom-up, so the most recent entry (this one) wins.
func (w *Writer) ReplaceObject(ref Ref, d Dict) {
	body := fmt.Sprintf("%d %d obj\n%s\nendobj\n", ref.Number, ref.Generation, Serialize(d))
	w.addRaw(ref, []byte(body))
}

// AddStream creates a stream object whose dictionary is extraDict merged with
// /Length, assigns the next object number, and returns its reference.
func (w *Writer) AddStream(content []byte, extraDict Dict) Ref {
	ref := w.allocRef()

	d := extraDict.Clone()
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

// AddSignatureObject adds a signature dictionary object with reserved
// /ByteRange and /Contents placeholders that can be patched in-place later.
// Keys "Contents" and "ByteRange" in d are ignored; they are handled here.
func (w *Writer) AddSignatureObject(d Dict) Ref {
	ref := w.allocRef()

	var sb strings.Builder
	fmt.Fprintf(&sb, "%d %d obj\n<<", ref.Number, ref.Generation)

	// Write all keys except Contents and ByteRange (handled specially below).
	// Sort keys for deterministic output.
	keys := make([]string, 0, len(d))
	for k := range d {
		if k == "Contents" || k == "ByteRange" {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(&sb, " /%s %s", k, Serialize(d[k]))
	}

	// /ByteRange placeholder – padded to ~60 chars so real values fit.
	byteRangeLine := "/ByteRange [0 0 0 0]"
	// Pad to 60 chars total so the signer can overwrite without shifting bytes.
	for len(byteRangeLine) < 60 {
		byteRangeLine += " "
	}
	sb.WriteString(" ")
	sb.WriteString(byteRangeLine)

	// /Contents placeholder – zero hex chars sized by the writer's
	// configured placeholder capacity (default PlaceholderSize).
	sb.WriteString(" /Contents ")
	sb.WriteString(SignaturePlaceholderOfSize(w.PlaceholderSize()))

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

// WriteTo writes the incremental update to path via an atomic temp+rename so
// a crash mid-write cannot leave a truncated output. Refuses to follow a
// symlink at path. See WriteFileAtomic for details.
func (w *Writer) WriteTo(path string) error {
	data, err := w.buildBytes()
	if err != nil {
		return err
	}
	return WriteFileAtomic(path, data)
}

// WriteToBytes is a convenience wrapper that returns the complete updated PDF
// bytes without writing a file.
//
// WriteToBytes is idempotent for a frozen Writer (no Add* calls between
// successive WriteToBytes invocations). Calling Add* after WriteToBytes
// produces objects that may collide with the catalog object number from the
// previous build — don't do it. Construct a fresh Writer if you need to
// append more objects.
func (w *Writer) WriteToBytes() ([]byte, error) {
	return w.buildBytes()
}

func (w *Writer) buildBytes() ([]byte, error) {
	// Save the state of nextObjNum so we can restore it after building,
	// ensuring buildBytes is idempotent (multiple calls produce the same output).
	savedNextObjNum := w.nextObjNum

	// Determine the root reference for the new trailer.
	rootRef := w.doc.CatalogRef

	// Snapshot the objects already pending before (possibly) adding catalog.
	pendingObjects := w.objects

	// If the catalog should be updated, build and add a new catalog object.
	var extraObjects []writtenObject
	if w.catalogFn != nil {
		newCat := w.catalogFn(w.doc.Catalog.Clone())
		catRef := w.allocRef()
		catBody := fmt.Sprintf("%d %d obj\n%s\nendobj\n", catRef.Number, catRef.Generation, Serialize(newCat))
		extraObjects = append(extraObjects, writtenObject{ref: catRef, data: []byte(catBody)})
		rootRef = catRef
	}

	// Combine all objects in order.
	allObjects := make([]writtenObject, 0, len(pendingObjects)+len(extraObjects))
	allObjects = append(allObjects, pendingObjects...)
	allObjects = append(allObjects, extraObjects...)

	// Compute the correct /Size: 1 greater than the highest object number in
	// the entire file (across all incremental updates).
	// Start from the original file's Size (which covers all prior objects).
	size := savedNextObjNum
	for _, wo := range allObjects {
		if wo.ref.Number+1 > size {
			size = wo.ref.Number + 1
		}
	}

	// Restore nextObjNum so buildBytes is idempotent.
	w.nextObjNum = savedNextObjNum

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
		"Size": size,
		"Root": rootRef,
		"Prev": w.doc.XRefOffset,
	}
	if info, ok := w.doc.Trailer.GetRef("Info"); ok {
		trailerDict["Info"] = info
	}
	// Preserve the file's /ID across incremental updates. Acrobat and many
	// verifiers use /ID to correlate an update chain to the base file — Go's
	// PDF parser stores the array as []any, so we copy it through verbatim.
	if id, ok := w.doc.Trailer["ID"]; ok {
		trailerDict["ID"] = id
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
