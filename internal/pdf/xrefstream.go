package pdf

import (
	"bytes"
	"compress/zlib"
	"fmt"
	"io"
	"math"
)

// parseXRefStream decodes a PDF 1.5+ cross-reference stream at offset. It
// populates doc.XRef with type-1 (uncompressed) entries and merges the
// stream's dict into doc.Trailer. Type-2 (compressed-in-objstream) entries
// are currently not resolvable — their object numbers are left out of
// doc.XRef so any later ReadDictObject on them fails with a clear "not found"
// rather than garbage. Returns the /Prev offset (0 if none).
func (doc *Document) parseXRefStream(offset int64) (int64, error) {
	if offset < 0 || offset >= int64(len(doc.Data)) {
		return 0, fmt.Errorf("xref stream offset %d out of range", offset)
	}

	// Locate the object header: "N G obj" then the dict and stream.
	chunk := doc.Data[offset:]
	objIdx := bytes.Index(chunk, []byte("obj"))
	if objIdx < 0 {
		return 0, fmt.Errorf("xref stream at %d missing 'obj' keyword", offset)
	}
	afterObj := chunk[objIdx+3:]
	afterObj = bytes.TrimLeft(afterObj, " \t\r\n")
	if !bytes.HasPrefix(afterObj, []byte("<<")) {
		return 0, fmt.Errorf("xref stream at %d missing dict", offset)
	}
	closeIdx := findMatchingClose(afterObj)
	if closeIdx < 0 {
		return 0, fmt.Errorf("xref stream at %d: unterminated dict", offset)
	}
	dict, err := parseDict(afterObj[:closeIdx+2])
	if err != nil {
		return 0, fmt.Errorf("xref stream at %d: parse dict: %w", offset, err)
	}

	// Stream bytes: skip dict + whitespace + "stream" + LF up to "endstream".
	afterDict := afterObj[closeIdx+2:]
	streamStart := bytes.Index(afterDict, []byte("stream"))
	if streamStart < 0 {
		return 0, fmt.Errorf("xref stream at %d: missing 'stream' keyword", offset)
	}
	body := afterDict[streamStart+len("stream"):]
	// Stream data begins after a single LF or CR+LF (PDF spec §7.3.8).
	if len(body) > 0 && body[0] == '\r' {
		body = body[1:]
	}
	if len(body) > 0 && body[0] == '\n' {
		body = body[1:]
	}
	length, ok := dict.GetInt("Length")
	if !ok || length < 0 || length > len(body) {
		return 0, fmt.Errorf("xref stream at %d: invalid /Length", offset)
	}
	raw := body[:length]

	// Decode filter chain. We support /FlateDecode (the overwhelmingly common
	// case) and no filter. Other filters are rejected with a clear error.
	decoded, err := applyStreamFilters(raw, dict)
	if err != nil {
		return 0, fmt.Errorf("xref stream at %d: %w", offset, err)
	}

	// Apply PDF predictor (PNG filter byte per row) if /DecodeParms requests it.
	decoded, err = applyPredictor(decoded, dict)
	if err != nil {
		return 0, fmt.Errorf("xref stream at %d: predictor: %w", offset, err)
	}

	// /W specifies the byte width of each of the three entry fields.
	wArr, ok := dict.GetArray("W")
	if !ok || len(wArr) != 3 {
		return 0, fmt.Errorf("xref stream at %d: /W missing or not [a b c]", offset)
	}
	var w [3]int
	for i, v := range wArr {
		n, err := coerceInt(v)
		if err != nil {
			return 0, fmt.Errorf("xref stream at %d: /W[%d]: %w", offset, i, err)
		}
		if n < 0 || n > 8 {
			return 0, fmt.Errorf("xref stream at %d: /W[%d]=%d out of range", offset, i, n)
		}
		w[i] = n
	}
	entrySize := w[0] + w[1] + w[2]
	if entrySize == 0 {
		return 0, fmt.Errorf("xref stream at %d: entry size is 0", offset)
	}
	if len(decoded)%entrySize != 0 {
		return 0, fmt.Errorf("xref stream at %d: decoded len %d not a multiple of entry size %d", offset, len(decoded), entrySize)
	}

	// /Index is a (objNum, count) pairs array; default is [0 /Size].
	type idxBlock struct{ first, count int }
	var blocks []idxBlock
	if arr, ok := dict.GetArray("Index"); ok {
		if len(arr)%2 != 0 {
			return 0, fmt.Errorf("xref stream at %d: /Index has odd length", offset)
		}
		for i := 0; i < len(arr); i += 2 {
			first, err := coerceInt(arr[i])
			if err != nil {
				return 0, fmt.Errorf("xref stream at %d: /Index[%d]: %w", offset, i, err)
			}
			count, err := coerceInt(arr[i+1])
			if err != nil {
				return 0, fmt.Errorf("xref stream at %d: /Index[%d]: %w", offset, i+1, err)
			}
			if first < 0 || count < 0 {
				return 0, fmt.Errorf("xref stream at %d: /Index has negative entry", offset)
			}
			if first > math.MaxInt-count {
				return 0, fmt.Errorf("xref stream at %d: /Index first+count overflow", offset)
			}
			blocks = append(blocks, idxBlock{first: first, count: count})
		}
	} else {
		size, _ := dict.GetInt("Size")
		if size < 0 {
			return 0, fmt.Errorf("xref stream at %d: missing /Index and invalid /Size", offset)
		}
		blocks = []idxBlock{{first: 0, count: size}}
	}

	pos := 0
	for _, b := range blocks {
		for i := 0; i < b.count; i++ {
			if pos+entrySize > len(decoded) {
				return 0, fmt.Errorf("xref stream at %d: /Index out of decoded bounds", offset)
			}
			entry := decoded[pos : pos+entrySize]
			pos += entrySize

			// Default type when /W[0] == 0 is 1 (per PDF spec).
			var typ int64
			if w[0] == 0 {
				typ = 1
			} else {
				typ = readBEUint(entry[:w[0]])
			}
			f2 := readBEUint(entry[w[0] : w[0]+w[1]])
			// f3 := readBEUint(entry[w[0]+w[1]:])   // generation or objstm index — unused for now
			objNum := b.first + i

			switch typ {
			case 0:
				// Free object — skip.
			case 1:
				// Uncompressed object at byte offset f2. Earlier (newer) entries win.
				if _, exists := doc.XRef[objNum]; !exists {
					doc.XRef[objNum] = f2
				}
			case 2:
				// Compressed inside an object stream — not yet resolvable.
				// Leaving it out of doc.XRef produces a clear "not found" later.
			}
		}
	}

	// Merge trailer entries. Newer updates parsed first win over older /Prev
	// entries, matching the traditional-xref merge semantics.
	if doc.Trailer == nil {
		doc.Trailer = make(Dict)
	}
	for k, v := range dict {
		if isXRefStreamOnlyKey(k) {
			continue
		}
		if _, exists := doc.Trailer[k]; !exists {
			doc.Trailer[k] = v
		}
	}

	if prev, ok := dict.GetInt("Prev"); ok && prev > 0 {
		return int64(prev), nil
	}
	return 0, nil
}

// isXRefStreamOnlyKey reports whether k is specific to the xref-stream object
// itself and must not leak into the merged Document trailer.
func isXRefStreamOnlyKey(k string) bool {
	switch k {
	case "Length", "Filter", "DecodeParms", "W", "Index", "Type":
		return true
	}
	return false
}

// applyStreamFilters decodes stream bytes per the /Filter entry. Supports
// /FlateDecode and no-filter; everything else is rejected.
func applyStreamFilters(data []byte, dict Dict) ([]byte, error) {
	filter, ok := dict["Filter"]
	if !ok {
		return data, nil
	}
	names, err := filterNames(filter)
	if err != nil {
		return nil, err
	}
	for _, name := range names {
		switch name {
		case "FlateDecode", "Fl":
			out, err := flateInflate(data)
			if err != nil {
				return nil, fmt.Errorf("FlateDecode: %w", err)
			}
			data = out
		default:
			return nil, fmt.Errorf("unsupported filter %q", name)
		}
	}
	return data, nil
}

func filterNames(v any) ([]string, error) {
	switch t := v.(type) {
	case Name:
		return []string{string(t)}, nil
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			n, ok := e.(Name)
			if !ok {
				return nil, fmt.Errorf("/Filter array element is not a Name: %T", e)
			}
			out = append(out, string(n))
		}
		return out, nil
	}
	return nil, fmt.Errorf("/Filter is neither Name nor array: %T", v)
}

func flateInflate(data []byte) ([]byte, error) {
	// PDF /FlateDecode is zlib-framed DEFLATE.
	r, err := zlib.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return io.ReadAll(r)
}

// applyPredictor undoes the PDF /Predictor applied during compression. Only
// PNG-family predictors (10–15) are implemented because TIFF predictor 2 is
// essentially unused on xref streams in the wild.
func applyPredictor(data []byte, dict Dict) ([]byte, error) {
	parms, ok := dict.GetDict("DecodeParms")
	if !ok {
		// DecodeParms missing → no predictor applied (Predictor=1 default).
		return data, nil
	}
	predictor, _ := parms.GetInt("Predictor")
	if predictor <= 1 {
		return data, nil
	}
	columns, _ := parms.GetInt("Columns")
	if columns <= 0 {
		columns = 1
	}

	// Predictor 2 is TIFF; leave unimplemented — not used for xref streams.
	if predictor < 10 {
		return nil, fmt.Errorf("predictor %d not supported", predictor)
	}

	// PNG predictors: data is laid out as rows of (1 filter byte + columns data bytes).
	rowSize := columns + 1
	if len(data)%rowSize != 0 {
		return nil, fmt.Errorf("predictor %d: data length %d not multiple of row %d", predictor, len(data), rowSize)
	}
	rows := len(data) / rowSize
	out := make([]byte, 0, rows*columns)
	prev := make([]byte, columns)
	cur := make([]byte, columns)
	for r := 0; r < rows; r++ {
		row := data[r*rowSize : (r+1)*rowSize]
		filterType := row[0]
		raw := row[1:]
		switch filterType {
		case 0: // None
			copy(cur, raw)
		case 1: // Sub
			for i := range raw {
				var left byte
				if i > 0 {
					left = cur[i-1]
				}
				cur[i] = raw[i] + left
			}
		case 2: // Up
			for i := range raw {
				cur[i] = raw[i] + prev[i]
			}
		case 3: // Average
			for i := range raw {
				var left byte
				if i > 0 {
					left = cur[i-1]
				}
				cur[i] = raw[i] + byte((int(left)+int(prev[i]))/2)
			}
		case 4: // Paeth
			for i := range raw {
				var left byte
				if i > 0 {
					left = cur[i-1]
				}
				upLeft := byte(0)
				if i > 0 {
					upLeft = prev[i-1]
				}
				cur[i] = raw[i] + paethPredictor(left, prev[i], upLeft)
			}
		default:
			return nil, fmt.Errorf("unknown PNG filter byte %d in row %d", filterType, r)
		}
		out = append(out, cur...)
		prev, cur = cur, prev
	}
	return out, nil
}

func paethPredictor(a, b, c byte) byte {
	p := int(a) + int(b) - int(c)
	pa := abs(p - int(a))
	pb := abs(p - int(b))
	pc := abs(p - int(c))
	switch {
	case pa <= pb && pa <= pc:
		return a
	case pb <= pc:
		return b
	}
	return c
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

func readBEUint(b []byte) int64 {
	var n int64
	for _, bb := range b {
		n = (n << 8) | int64(bb)
	}
	return n
}

// coerceInt accepts int, int64, or a non-fractional float64 in int range and
// returns a plain int. Used for dict fields that may come back as any of the
// three from the parser.
func coerceInt(v any) (int, error) {
	switch t := v.(type) {
	case int:
		return t, nil
	case int64:
		if t < math.MinInt || t > math.MaxInt {
			return 0, fmt.Errorf("int64 %d out of int range", t)
		}
		return int(t), nil
	case float64:
		if t != math.Trunc(t) || t < math.MinInt || t > math.MaxInt {
			return 0, fmt.Errorf("float %v not representable as int", t)
		}
		return int(t), nil
	}
	return 0, fmt.Errorf("not numeric: %T", v)
}
