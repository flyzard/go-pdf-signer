package pdf

import (
	"bytes"
	"compress/flate"
	"fmt"
	"testing"
)

// buildXRefStreamPDF constructs a PDF using a cross-reference stream rather
// than a traditional xref table. objects must each be a complete "N G obj ...
// endobj\n" block. The returned bytes use /W [1 3 1] and FlateDecode with no
// predictor — the simplest valid xref-stream layout.
func buildXRefStreamPDF(t *testing.T, objects []string) []byte {
	t.Helper()
	var b bytes.Buffer
	b.WriteString("%PDF-1.5\n")

	offsets := make([]int, len(objects))
	for i, o := range objects {
		offsets[i] = b.Len()
		b.WriteString(o)
	}

	// Build xref-stream binary payload: entries for obj 0 (free) + 1..N.
	totalObjs := len(objects) + 1 // object 0 is the free head
	var payload bytes.Buffer
	// object 0 — free, linked-list terminator.
	payload.Write([]byte{0, 0, 0, 0, 0xFF})
	for _, off := range offsets {
		if off > 0xFFFFFF {
			t.Fatalf("offset %d exceeds 3-byte /W[1] width; enlarge fixture", off)
		}
		payload.WriteByte(1)
		payload.WriteByte(byte(off >> 16))
		payload.WriteByte(byte(off >> 8))
		payload.WriteByte(byte(off))
		payload.WriteByte(0)
	}
	// Compress via zlib-wrapped deflate (PDF FlateDecode format).
	var zbuf bytes.Buffer
	// zlib header: CMF=0x78, FLG such that (CMF*256+FLG)%31==0. 0x78 0x9C is a safe choice.
	zbuf.Write([]byte{0x78, 0x9C})
	fw, _ := flate.NewWriter(&zbuf, flate.DefaultCompression)
	fw.Write(payload.Bytes())
	fw.Close()
	// Adler-32 checksum.
	adler := adler32Sum(payload.Bytes())
	zbuf.WriteByte(byte(adler >> 24))
	zbuf.WriteByte(byte(adler >> 16))
	zbuf.WriteByte(byte(adler >> 8))
	zbuf.WriteByte(byte(adler))
	streamData := zbuf.Bytes()

	// The xref-stream object itself takes object number len(objects)+1.
	xrefObjNum := len(objects) + 1
	xrefOffset := b.Len()
	// /Index [0 N] matches the N entries in the payload (obj 0 free + each
	// data object). /Size is the traditional trailer /Size — highest obj
	// number plus one (the xref stream included).
	entriesWritten := len(objects) + 1
	dict := fmt.Sprintf(
		"<< /Type /XRef /Size %d /W [1 3 1] /Index [0 %d] /Root 1 0 R /Filter /FlateDecode /Length %d >>\n",
		totalObjs+1, entriesWritten, len(streamData))
	fmt.Fprintf(&b, "%d 0 obj\n%sstream\n", xrefObjNum, dict)
	b.Write(streamData)
	b.WriteString("\nendstream\nendobj\n")
	fmt.Fprintf(&b, "startxref\n%d\n%%%%EOF\n", xrefOffset)
	return b.Bytes()
}

func adler32Sum(data []byte) uint32 {
	const mod = 65521
	var a, bs uint32 = 1, 0
	for _, d := range data {
		a = (a + uint32(d)) % mod
		bs = (bs + a) % mod
	}
	return (bs << 16) | a
}

func TestParseXRefStreamMinimal(t *testing.T) {
	objects := []string{
		"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n",
		"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n",
		"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\n",
	}
	data := buildXRefStreamPDF(t, objects)

	doc, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse xref-stream PDF: %v", err)
	}
	if typeName, ok := doc.Catalog.GetName("Type"); !ok || typeName != "Catalog" {
		t.Errorf("catalog /Type = %q %v, want Catalog", typeName, ok)
	}
	if _, ok := doc.Catalog.GetRef("Pages"); !ok {
		t.Errorf("catalog missing /Pages ref")
	}
	// Object 1, 2, 3 must all have xref entries.
	for _, n := range []int{1, 2, 3} {
		if _, ok := doc.XRef[n]; !ok {
			t.Errorf("object %d missing from xref", n)
		}
	}
}

func TestParseXRefStreamWithPNGPredictor(t *testing.T) {
	// Build an xref stream identical to the minimal case but with PNG-Up
	// predictor applied to the payload before Flate compression. Acrobat
	// produces this shape.
	objects := []string{
		"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n",
		"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n",
		"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\n",
	}
	var b bytes.Buffer
	b.WriteString("%PDF-1.5\n")
	offsets := make([]int, len(objects))
	for i, o := range objects {
		offsets[i] = b.Len()
		b.WriteString(o)
	}

	// Build raw payload: obj 0 free + each object (type=1, offset, gen=0).
	const cols = 5 // entry size with /W [1 3 1]
	entryCount := len(objects) + 1
	raw := make([]byte, entryCount*cols)
	// obj 0: free head
	raw[0] = 0
	raw[4] = 0xFF
	for i, off := range offsets {
		e := (i + 1) * cols
		raw[e] = 1
		raw[e+1] = byte(off >> 16)
		raw[e+2] = byte(off >> 8)
		raw[e+3] = byte(off)
		raw[e+4] = 0
	}

	// Apply PNG-Up (filter type 2) to each row: write 1 filter byte then
	// (row[i] - prev[i]) mod 256.
	rowSize := cols + 1
	withFilter := make([]byte, entryCount*rowSize)
	prev := make([]byte, cols)
	for r := 0; r < entryCount; r++ {
		rowStart := r * rowSize
		withFilter[rowStart] = 2 // PNG Up
		for i := 0; i < cols; i++ {
			withFilter[rowStart+1+i] = raw[r*cols+i] - prev[i]
		}
		copy(prev, raw[r*cols:(r+1)*cols])
	}

	// zlib-wrap + Flate.
	var zbuf bytes.Buffer
	zbuf.Write([]byte{0x78, 0x9C})
	fw, _ := flate.NewWriter(&zbuf, flate.DefaultCompression)
	fw.Write(withFilter)
	fw.Close()
	a := adler32Sum(withFilter)
	zbuf.WriteByte(byte(a >> 24))
	zbuf.WriteByte(byte(a >> 16))
	zbuf.WriteByte(byte(a >> 8))
	zbuf.WriteByte(byte(a))
	streamData := zbuf.Bytes()

	xrefObjNum := len(objects) + 1
	xrefOffset := b.Len()
	dict := fmt.Sprintf(
		"<< /Type /XRef /Size %d /W [1 3 1] /Index [0 %d] /Root 1 0 R "+
			"/Filter /FlateDecode /DecodeParms << /Predictor 12 /Columns %d >> /Length %d >>\n",
		entryCount+1, entryCount, cols, len(streamData))
	fmt.Fprintf(&b, "%d 0 obj\n%sstream\n", xrefObjNum, dict)
	b.Write(streamData)
	b.WriteString("\nendstream\nendobj\n")
	fmt.Fprintf(&b, "startxref\n%d\n%%%%EOF\n", xrefOffset)

	doc, err := Parse(b.Bytes())
	if err != nil {
		t.Fatalf("Parse PNG-predictor xref-stream PDF: %v", err)
	}
	if typeName, ok := doc.Catalog.GetName("Type"); !ok || typeName != "Catalog" {
		t.Errorf("catalog /Type = %q, want Catalog", typeName)
	}
}

func TestParseXRefStreamRejectsUnsupportedFilter(t *testing.T) {
	// Hand-build a minimal PDF whose xref stream uses /ASCII85Decode.
	obj := "1 0 obj\n<< /Type /Catalog >>\nendobj\n"
	body := []byte("%PDF-1.5\n" + obj)
	xrefOffset := len(body)
	stream := []byte("\x00\x00\x00\x00\xFF\x01\x00\x00\x00\x00")
	dict := fmt.Sprintf(
		"<< /Type /XRef /Size 2 /W [1 3 1] /Root 1 0 R /Filter /ASCII85Decode /Length %d >>\n",
		len(stream))
	body = append(body, []byte(fmt.Sprintf("2 0 obj\n%sstream\n", dict))...)
	body = append(body, stream...)
	body = append(body, []byte("\nendstream\nendobj\n")...)
	body = append(body, []byte(fmt.Sprintf("startxref\n%d\n%%%%EOF\n", xrefOffset))...)

	if _, err := Parse(body); err == nil {
		t.Fatal("expected Parse to reject unsupported xref-stream filter, got nil")
	}
}
