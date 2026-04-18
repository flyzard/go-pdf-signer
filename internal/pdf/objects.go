package pdf

import (
	"encoding/hex"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
)

// Ref is a PDF indirect reference (object number + generation).
type Ref struct {
	Number     int
	Generation int
}

// String returns the PDF reference notation "N G R".
func (r Ref) String() string {
	return fmt.Sprintf("%d %d R", r.Number, r.Generation)
}

// Name is a PDF name object (e.g. /Type).
type Name string

// String returns the PDF serialisation "/Name".
func (n Name) String() string {
	return "/" + string(n)
}

// Dict is a PDF dictionary.
type Dict map[string]any

// Clone returns a shallow copy of d. Callers that mutate an existing
// catalog/AcroForm/Perms dict should Clone first so the original parsed
// document stays untouched.
func (d Dict) Clone() Dict {
	if d == nil {
		return nil
	}
	out := make(Dict, len(d))
	for k, v := range d {
		out[k] = v
	}
	return out
}

// GetInt returns the integer value for key, ok=false if missing or wrong type.
// For float64 values, the caller is refused unless the value is finite, has
// no fractional part, and fits in a Go int — silent truncation of 1e20 or
// NaN is worse than a missing value.
func (d Dict) GetInt(key string) (int, bool) {
	v, ok := d[key]
	if !ok {
		return 0, false
	}
	switch t := v.(type) {
	case int:
		return t, true
	case int64:
		if t < math.MinInt || t > math.MaxInt {
			return 0, false
		}
		return int(t), true
	case float64:
		if math.IsNaN(t) || math.IsInf(t, 0) {
			return 0, false
		}
		if t != math.Trunc(t) {
			return 0, false
		}
		if t < math.MinInt || t > math.MaxInt {
			return 0, false
		}
		return int(t), true
	}
	return 0, false
}

// GetRef returns the Ref value for key, ok=false if missing or wrong type.
func (d Dict) GetRef(key string) (Ref, bool) {
	v, ok := d[key]
	if !ok {
		return Ref{}, false
	}
	r, ok := v.(Ref)
	return r, ok
}

// GetDict returns the nested Dict value for key.
func (d Dict) GetDict(key string) (Dict, bool) {
	v, ok := d[key]
	if !ok {
		return nil, false
	}
	nd, ok := v.(Dict)
	return nd, ok
}

// GetArray returns the []any value for key.
func (d Dict) GetArray(key string) ([]any, bool) {
	v, ok := d[key]
	if !ok {
		return nil, false
	}
	a, ok := v.([]any)
	return a, ok
}

// GetName returns the Name value for key.
func (d Dict) GetName(key string) (Name, bool) {
	v, ok := d[key]
	if !ok {
		return "", false
	}
	n, ok := v.(Name)
	return n, ok
}

// Stream is a PDF stream object.
type Stream struct {
	Dict Dict
	Data []byte
}

// Serialize converts a Go value to its PDF text representation.
func Serialize(v any) string {
	if v == nil {
		return "null"
	}
	switch t := v.(type) {
	case bool:
		if t {
			return "true"
		}
		return "false"
	case int:
		return fmt.Sprintf("%d", t)
	case int64:
		return fmt.Sprintf("%d", t)
	case float64:
		// PDF disallows scientific notation in numeric literals.
		return strconv.FormatFloat(t, 'f', -1, 64)
	case string:
		return serializeText(t)
	case Name:
		return t.String()
	case Ref:
		return t.String()
	case Dict:
		return serializeDict(t)
	case []any:
		return serializeArray(t)
	case []byte:
		return "<" + hex.EncodeToString(t) + ">"
	default:
		panic(fmt.Sprintf("pdf.Serialize: unsupported value type %T (value: %v)", v, v))
	}
}

func serializeDict(d Dict) string {
	keys := make([]string, 0, len(d))
	for k := range d {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var sb strings.Builder
	sb.WriteString("<<")
	for _, k := range keys {
		sb.WriteString(" /")
		sb.WriteString(k)
		sb.WriteString(" ")
		sb.WriteString(Serialize(d[k]))
	}
	sb.WriteString(" >>")
	return sb.String()
}

// serializeArray emits "[A B C]" with single-space separators and no leading/
// trailing space inside the brackets — accepted by the PDF spec. No current
// caller can produce an element whose serialized form starts with '[' or '<',
// which would otherwise be ambiguous against the brackets.
func serializeArray(a []any) string {
	var sb strings.Builder
	sb.WriteString("[")
	for i, v := range a {
		if i > 0 {
			sb.WriteString(" ")
		}
		sb.WriteString(Serialize(v))
	}
	sb.WriteString("]")
	return sb.String()
}

// serializeText emits a PDF string literal for the given Go string. If the
// string is pure ASCII it is written as a parenthesised literal with the
// usual escapes; otherwise it is emitted as a hex string of the UTF-16BE
// encoding with a 0xFEFF BOM. Readers default to PDFDocEncoding on bare
// literals, which would render Portuguese (and any non-Latin) signer names
// as mojibake.
func serializeText(s string) string {
	if isASCII(s) {
		return "(" + escapeString(s) + ")"
	}
	var sb strings.Builder
	sb.WriteByte('<')
	sb.WriteString("FEFF")
	for _, r := range s {
		if r > 0xFFFF {
			// Outside BMP — emit surrogate pair.
			r -= 0x10000
			hi := 0xD800 + (r >> 10)
			lo := 0xDC00 + (r & 0x3FF)
			fmt.Fprintf(&sb, "%04X%04X", hi, lo)
			continue
		}
		fmt.Fprintf(&sb, "%04X", r)
	}
	sb.WriteByte('>')
	return sb.String()
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] > 0x7E || s[i] < 0x20 && s[i] != '\t' && s[i] != '\r' && s[i] != '\n' {
			return false
		}
	}
	return true
}

func escapeString(s string) string {
	var sb strings.Builder
	for _, c := range s {
		switch c {
		case '(':
			sb.WriteString(`\(`)
		case ')':
			sb.WriteString(`\)`)
		case '\\':
			sb.WriteString(`\\`)
		case '\r':
			sb.WriteString(`\r`)
		case '\n':
			sb.WriteString(`\n`)
		case '\t':
			sb.WriteString(`\t`)
		default:
			sb.WriteRune(c)
		}
	}
	return sb.String()
}
