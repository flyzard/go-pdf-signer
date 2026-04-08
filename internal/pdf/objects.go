package pdf

import (
	"encoding/hex"
	"fmt"
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

// GetInt returns the integer value for key, ok=false if missing or wrong type.
func (d Dict) GetInt(key string) (int, bool) {
	v, ok := d[key]
	if !ok {
		return 0, false
	}
	switch t := v.(type) {
	case int:
		return t, true
	case int64:
		return int(t), true
	case float64:
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
		return fmt.Sprintf("%g", t)
	case string:
		return "(" + escapeString(t) + ")"
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
		return "null"
	}
}

func serializeDict(d Dict) string {
	var sb strings.Builder
	sb.WriteString("<<")
	for k, v := range d {
		sb.WriteString(" /")
		sb.WriteString(k)
		sb.WriteString(" ")
		sb.WriteString(Serialize(v))
	}
	sb.WriteString(" >>")
	return sb.String()
}

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
