package pdf

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// Document holds a parsed PDF file.
type Document struct {
	Data        []byte
	Version     string
	XRefOffset  int64
	Trailer     Dict
	XRef        map[int]int64 // object number -> byte offset
	NextObjNum  int
	Catalog     Dict
	CatalogRef  Ref
}

// Open reads the file at path and parses it.
func Open(path string) (*Document, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	return Parse(data)
}

// Parse parses raw PDF bytes and returns a Document.
func Parse(data []byte) (*Document, error) {
	doc := &Document{
		Data: data,
		XRef: make(map[int]int64),
	}

	// Parse version from header.
	if len(data) >= 8 {
		header := string(data[:min(20, len(data))])
		if strings.HasPrefix(header, "%PDF-") {
			end := strings.IndexAny(header[5:], "\r\n ")
			if end < 0 {
				end = len(header) - 5
			}
			doc.Version = header[5 : 5+end]
		}
	}

	// Find startxref.
	offset, err := findStartXRef(data)
	if err != nil {
		return nil, err
	}
	doc.XRefOffset = offset

	// Parse xref and trailer.
	if err := doc.parseXRef(offset); err != nil {
		return nil, err
	}

	// Determine NextObjNum from trailer /Size.
	if size, ok := doc.Trailer.GetInt("Size"); ok {
		doc.NextObjNum = size
	}

	// Read catalog.
	if catRef, ok := doc.Trailer.GetRef("Root"); ok {
		doc.CatalogRef = catRef
		cat, err := doc.ReadDictObject(catRef)
		if err != nil {
			return nil, fmt.Errorf("read catalog: %w", err)
		}
		doc.Catalog = cat
	}

	return doc, nil
}

// findStartXRef searches backward from EOF for "startxref" and returns the
// xref table offset written after it.
func findStartXRef(data []byte) (int64, error) {
	// Search in the last 1024 bytes.
	searchStart := len(data) - 1024
	if searchStart < 0 {
		searchStart = 0
	}
	tail := data[searchStart:]

	idx := bytes.LastIndex(tail, []byte("startxref"))
	if idx < 0 {
		return 0, errors.New("startxref not found")
	}

	// Skip "startxref" and whitespace to find the number.
	rest := tail[idx+len("startxref"):]
	rest = bytes.TrimLeft(rest, " \t\r\n")

	// Read the number.
	end := bytes.IndexAny(rest, " \t\r\n")
	if end < 0 {
		end = len(rest)
	}
	numStr := string(rest[:end])
	offset, err := strconv.ParseInt(numStr, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid startxref value %q: %w", numStr, err)
	}
	return offset, nil
}

// parseXRef dispatches to the appropriate xref parser.
func (doc *Document) parseXRef(offset int64) error {
	if int(offset) >= len(doc.Data) {
		return fmt.Errorf("xref offset %d out of range", offset)
	}
	chunk := doc.Data[offset:]
	chunk = bytes.TrimLeft(chunk, " \t\r\n")

	if bytes.HasPrefix(chunk, []byte("xref")) {
		return doc.parseTraditionalXRef(doc.Data, offset)
	}
	// Could be a cross-reference stream — not implemented yet.
	return errors.New("unsupported xref type (only traditional xref tables supported)")
}

// parseTraditionalXRef parses a traditional "xref ... trailer" block starting
// at offset and follows /Prev chains for incremental updates.
// Entries already present in doc.XRef (from a newer update) take priority.
func (doc *Document) parseTraditionalXRef(data []byte, offset int64) error {
	if int(offset) >= len(data) {
		return fmt.Errorf("xref offset %d out of range", offset)
	}

	sc := newScanner(data[offset:])

	// Expect "xref".
	line := sc.nextLine()
	if strings.TrimSpace(line) != "xref" {
		return fmt.Errorf("expected 'xref', got %q", line)
	}

	// Parse subsections until we hit "trailer".
	for {
		line = sc.nextLine()
		line = strings.TrimSpace(line)
		if line == "trailer" {
			break
		}
		if line == "" {
			continue
		}
		// Parse "firstObj count".
		parts := strings.Fields(line)
		if len(parts) != 2 {
			return fmt.Errorf("invalid xref subsection header: %q", line)
		}
		firstObj, err := strconv.Atoi(parts[0])
		if err != nil {
			return fmt.Errorf("invalid xref subsection first obj: %w", err)
		}
		count, err := strconv.Atoi(parts[1])
		if err != nil {
			return fmt.Errorf("invalid xref subsection count: %w", err)
		}

		for i := 0; i < count; i++ {
			entry := sc.nextLine()
			entry = strings.TrimSpace(entry)
			if len(entry) < 18 {
				return fmt.Errorf("short xref entry: %q", entry)
			}
			fields := strings.Fields(entry)
			if len(fields) < 3 {
				return fmt.Errorf("invalid xref entry: %q", entry)
			}
			objOff, err := strconv.ParseInt(fields[0], 10, 64)
			if err != nil {
				return fmt.Errorf("invalid xref entry offset: %w", err)
			}
			flag := fields[2]
			objNum := firstObj + i

			// Only store if not already present (newer updates take priority).
			if _, exists := doc.XRef[objNum]; !exists {
				if flag == "n" {
					doc.XRef[objNum] = objOff
				}
				// "f" entries (free) are ignored.
			}
		}
	}

	// Parse trailer dictionary.
	trailerData := sc.rest()
	trailerData = bytes.TrimLeft(trailerData, " \t\r\n")
	if !bytes.HasPrefix(trailerData, []byte("<<")) {
		return fmt.Errorf("expected trailer dict, got %q", string(trailerData[:min(20, len(trailerData))]))
	}

	// Find matching ">>".
	closeIdx := findMatchingClose(trailerData)
	if closeIdx < 0 {
		return errors.New("unterminated trailer dictionary")
	}
	trailerDict, err := parseDict(trailerData[:closeIdx+2])
	if err != nil {
		return fmt.Errorf("parse trailer dict: %w", err)
	}

	// Merge trailer: only set keys not already present (current update wins).
	if doc.Trailer == nil {
		doc.Trailer = trailerDict
	} else {
		for k, v := range trailerDict {
			if _, exists := doc.Trailer[k]; !exists {
				doc.Trailer[k] = v
			}
		}
	}

	// Follow /Prev chain.
	if prev, ok := trailerDict.GetInt("Prev"); ok && prev != 0 {
		return doc.parseTraditionalXRef(data, int64(prev))
	}

	return nil
}

// ReadDictObject reads the object at the given reference and returns its Dict.
func (doc *Document) ReadDictObject(ref Ref) (Dict, error) {
	offset, ok := doc.XRef[ref.Number]
	if !ok {
		return nil, fmt.Errorf("object %d not found in xref", ref.Number)
	}
	if int(offset) >= len(doc.Data) {
		return nil, fmt.Errorf("object %d offset %d out of range", ref.Number, offset)
	}

	chunk := doc.Data[offset:]

	// Find "obj" keyword — the dict may follow immediately (compact PDF)
	// or on the next line. Handle both: "13 0 obj\n<<..." and "13 0 obj<<..."
	objIdx := bytes.Index(chunk, []byte("obj"))
	if objIdx < 0 {
		return nil, fmt.Errorf("expected 'obj' keyword at object %d", ref.Number)
	}

	// Everything after "obj"
	rest := chunk[objIdx+3:]
	rest = bytes.TrimLeft(rest, " \t\r\n")

	if !bytes.HasPrefix(rest, []byte("<<")) {
		return nil, fmt.Errorf("object %d is not a dictionary", ref.Number)
	}

	closeIdx := findMatchingClose(rest)
	if closeIdx < 0 {
		return nil, fmt.Errorf("unterminated dict in object %d", ref.Number)
	}

	return parseDict(rest[:closeIdx+2])
}

// findMatchingClose finds the index of the ">>" that closes the "<<" at position 0.
// data must start with "<<". Returns the index of the closing ">>" or -1.
func findMatchingClose(data []byte) int {
	depth := 0
	i := 0
	for i < len(data) {
		if i+1 < len(data) && data[i] == '<' && data[i+1] == '<' {
			depth++
			i += 2
			continue
		}
		if i+1 < len(data) && data[i] == '>' && data[i+1] == '>' {
			depth--
			if depth == 0 {
				return i
			}
			i += 2
			continue
		}
		// Skip strings.
		if data[i] == '(' {
			i++
			nestParen := 1
			for i < len(data) && nestParen > 0 {
				if data[i] == '\\' {
					i += 2
					continue
				}
				if data[i] == '(' {
					nestParen++
				} else if data[i] == ')' {
					nestParen--
				}
				i++
			}
			continue
		}
		// Skip hex strings.
		if data[i] == '<' && (i+1 >= len(data) || data[i+1] != '<') {
			i++
			for i < len(data) && data[i] != '>' {
				i++
			}
			i++ // skip '>'
			continue
		}
		i++
	}
	return -1
}

// scanner provides line-by-line reading over a byte slice.
type scanner struct {
	data []byte
	pos  int
}

func newScanner(data []byte) *scanner {
	return &scanner{data: data}
}

// nextLine returns the next non-empty line (strips \r\n).
func (s *scanner) nextLine() string {
	for s.pos < len(s.data) {
		start := s.pos
		for s.pos < len(s.data) && s.data[s.pos] != '\n' {
			s.pos++
		}
		if s.pos < len(s.data) {
			s.pos++ // consume '\n'
		}
		line := string(bytes.TrimRight(s.data[start:s.pos], "\r\n"))
		if line != "" {
			return line
		}
	}
	return ""
}

// rest returns all remaining bytes from the current position.
func (s *scanner) rest() []byte {
	return s.data[s.pos:]
}

// parseDict is the public entry point for parsing a PDF dictionary from bytes.
// data should be the full "<<...>>" token.
func parseDict(data []byte) (Dict, error) {
	p := &parser{data: data, pos: 0}
	p.skipWhitespace()
	v, err := p.parseValue()
	if err != nil {
		return nil, err
	}
	d, ok := v.(Dict)
	if !ok {
		return nil, fmt.Errorf("expected dict, got %T", v)
	}
	return d, nil
}

// parser is a recursive-descent PDF value parser.
type parser struct {
	data []byte
	pos  int
}

func (p *parser) skipWhitespace() {
	for p.pos < len(p.data) {
		c := p.data[p.pos]
		if c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\f' {
			p.pos++
			continue
		}
		// Skip comments.
		if c == '%' {
			for p.pos < len(p.data) && p.data[p.pos] != '\n' {
				p.pos++
			}
			continue
		}
		break
	}
}

func (p *parser) parseValue() (any, error) {
	p.skipWhitespace()
	if p.pos >= len(p.data) {
		return nil, errors.New("unexpected end of input")
	}

	c := p.data[p.pos]

	switch {
	case c == '<' && p.pos+1 < len(p.data) && p.data[p.pos+1] == '<':
		return p.parseDict()
	case c == '<':
		return p.parseHexString()
	case c == '/':
		return p.parseName()
	case c == '(':
		return p.parseString()
	case c == '[':
		return p.parseArray()
	case c == 't' && bytes.HasPrefix(p.data[p.pos:], []byte("true")):
		p.pos += 4
		return true, nil
	case c == 'f' && bytes.HasPrefix(p.data[p.pos:], []byte("false")):
		p.pos += 5
		return false, nil
	case c == 'n' && bytes.HasPrefix(p.data[p.pos:], []byte("null")):
		p.pos += 4
		return nil, nil
	case c == '-' || c == '+' || (c >= '0' && c <= '9') || c == '.':
		return p.parseNumberOrRef()
	default:
		return nil, fmt.Errorf("unexpected character %q at position %d", c, p.pos)
	}
}

func (p *parser) parseDict() (Dict, error) {
	// Consume "<<".
	p.pos += 2
	d := make(Dict)

	for {
		p.skipWhitespace()
		if p.pos+1 < len(p.data) && p.data[p.pos] == '>' && p.data[p.pos+1] == '>' {
			p.pos += 2
			return d, nil
		}
		if p.pos >= len(p.data) {
			return nil, errors.New("unterminated dictionary")
		}

		// Key must be a Name.
		if p.data[p.pos] != '/' {
			return nil, fmt.Errorf("expected name key in dict at pos %d, got %q", p.pos, p.data[p.pos])
		}
		keyName, err := p.parseName()
		if err != nil {
			return nil, err
		}

		// Value.
		p.skipWhitespace()
		val, err := p.parseValue()
		if err != nil {
			return nil, fmt.Errorf("parsing value for key %q: %w", keyName, err)
		}
		d[string(keyName)] = val
	}
}

func (p *parser) parseName() (Name, error) {
	if p.pos >= len(p.data) || p.data[p.pos] != '/' {
		return "", errors.New("expected '/'")
	}
	p.pos++ // skip '/'
	start := p.pos
	for p.pos < len(p.data) {
		c := p.data[p.pos]
		if c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\f' ||
			c == '/' || c == '<' || c == '>' || c == '[' || c == ']' ||
			c == '(' || c == ')' || c == '{' || c == '}' || c == '%' {
			break
		}
		p.pos++
	}
	return Name(p.data[start:p.pos]), nil
}

func (p *parser) parseString() (string, error) {
	if p.pos >= len(p.data) || p.data[p.pos] != '(' {
		return "", errors.New("expected '('")
	}
	p.pos++ // skip '('
	var sb strings.Builder
	depth := 1
	for p.pos < len(p.data) && depth > 0 {
		c := p.data[p.pos]
		if c == '\\' && p.pos+1 < len(p.data) {
			p.pos++
			switch p.data[p.pos] {
			case 'n':
				sb.WriteByte('\n')
			case 'r':
				sb.WriteByte('\r')
			case 't':
				sb.WriteByte('\t')
			case 'b':
				sb.WriteByte('\b')
			case 'f':
				sb.WriteByte('\f')
			case '(':
				sb.WriteByte('(')
			case ')':
				sb.WriteByte(')')
			case '\\':
				sb.WriteByte('\\')
			default:
				sb.WriteByte(p.data[p.pos])
			}
			p.pos++
			continue
		}
		if c == '(' {
			depth++
		} else if c == ')' {
			depth--
			if depth == 0 {
				p.pos++
				break
			}
		}
		sb.WriteByte(c)
		p.pos++
	}
	return sb.String(), nil
}

func (p *parser) parseHexString() ([]byte, error) {
	if p.pos >= len(p.data) || p.data[p.pos] != '<' {
		return nil, errors.New("expected '<'")
	}
	p.pos++ // skip '<'
	start := p.pos
	for p.pos < len(p.data) && p.data[p.pos] != '>' {
		p.pos++
	}
	hexStr := strings.ReplaceAll(string(p.data[start:p.pos]), " ", "")
	hexStr = strings.ReplaceAll(hexStr, "\n", "")
	hexStr = strings.ReplaceAll(hexStr, "\r", "")
	if len(hexStr)%2 != 0 {
		hexStr += "0"
	}
	if p.pos < len(p.data) {
		p.pos++ // skip '>'
	}
	b, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, fmt.Errorf("invalid hex string: %w", err)
	}
	return b, nil
}

func (p *parser) parseArray() ([]any, error) {
	if p.pos >= len(p.data) || p.data[p.pos] != '[' {
		return nil, errors.New("expected '['")
	}
	p.pos++ // skip '['
	var arr []any
	for {
		p.skipWhitespace()
		if p.pos >= len(p.data) {
			return nil, errors.New("unterminated array")
		}
		if p.data[p.pos] == ']' {
			p.pos++
			return arr, nil
		}
		v, err := p.parseValue()
		if err != nil {
			return nil, err
		}
		arr = append(arr, v)
	}
}

// parseNumberOrRef handles the ambiguity between a plain number and an indirect
// reference "N G R". It uses lookahead: if two integers followed by "R" are
// found, it returns a Ref; otherwise it returns the first number.
func (p *parser) parseNumberOrRef() (any, error) {
	startPos := p.pos

	// Parse first number.
	n1Str, isFloat1 := p.readNumber()
	if n1Str == "" {
		return nil, fmt.Errorf("expected number at pos %d", startPos)
	}

	if isFloat1 {
		f, err := strconv.ParseFloat(n1Str, 64)
		if err != nil {
			return nil, err
		}
		return f, nil
	}

	// Save position after first integer.
	afterN1 := p.pos

	// Lookahead: skip whitespace, try to read second integer.
	p.skipWhitespace()
	if p.pos >= len(p.data) {
		// End of input — just a number.
		n1, err := strconv.ParseInt(n1Str, 10, 64)
		if err != nil {
			return nil, err
		}
		if n1 >= -2147483648 && n1 <= 2147483647 {
			return int(n1), nil
		}
		return n1, nil
	}

	c := p.data[p.pos]
	if c < '0' || c > '9' {
		// Not a second integer — restore and return first number.
		p.pos = afterN1
		n1, err := strconv.ParseInt(n1Str, 10, 64)
		if err != nil {
			return nil, err
		}
		if n1 >= -2147483648 && n1 <= 2147483647 {
			return int(n1), nil
		}
		return n1, nil
	}

	n2Str, isFloat2 := p.readNumber()
	if isFloat2 || n2Str == "" {
		// Not a valid generation number — restore and return.
		p.pos = afterN1
		n1, _ := strconv.ParseInt(n1Str, 10, 64)
		if n1 >= -2147483648 && n1 <= 2147483647 {
			return int(n1), nil
		}
		return n1, nil
	}

	afterN2 := p.pos
	p.skipWhitespace()

	if p.pos < len(p.data) && p.data[p.pos] == 'R' {
		// Check it's not part of a keyword like "Root".
		afterR := p.pos + 1
		if afterR >= len(p.data) ||
			p.data[afterR] == ' ' || p.data[afterR] == '\t' ||
			p.data[afterR] == '\r' || p.data[afterR] == '\n' ||
			p.data[afterR] == '>' || p.data[afterR] == ']' ||
			p.data[afterR] == '/' {
			p.pos++ // consume 'R'
			n1, _ := strconv.Atoi(n1Str)
			n2, _ := strconv.Atoi(n2Str)
			return Ref{Number: n1, Generation: n2}, nil
		}
	}

	// Not a reference — restore to after first number.
	p.pos = afterN2
	_ = afterN2
	p.pos = afterN1
	n1, err := strconv.ParseInt(n1Str, 10, 64)
	if err != nil {
		return nil, err
	}
	if n1 >= -2147483648 && n1 <= 2147483647 {
		return int(n1), nil
	}
	return n1, nil
}

// readNumber reads a number token (integer or float) from the current position.
// Returns the string and whether it contains a decimal point.
func (p *parser) readNumber() (string, bool) {
	start := p.pos
	isFloat := false
	if p.pos < len(p.data) && (p.data[p.pos] == '-' || p.data[p.pos] == '+') {
		p.pos++
	}
	for p.pos < len(p.data) {
		c := p.data[p.pos]
		if c >= '0' && c <= '9' {
			p.pos++
		} else if c == '.' && !isFloat {
			isFloat = true
			p.pos++
		} else {
			break
		}
	}
	if p.pos == start {
		return "", false
	}
	return string(p.data[start:p.pos]), isFloat
}

