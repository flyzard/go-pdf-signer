package appearance

import (
	"fmt"
	"strings"

	"github.com/flyzard/pdf-signer/internal/pdf"
)

// SignerInfo holds the signer identity for the visible stamp.
type SignerInfo struct {
	Name          string
	NIC           string
	SigningMethod string // "cmd" or "cc"
	DateTime      string
}

// Position describes where the signature stamp is placed on the page.
type Position struct {
	Page   int // -1 = last page
	X      float64
	Y      float64
	Width  float64
	Height float64
}

// DefaultPosition returns a bottom-left position for the given signature index.
// Stamps are stacked horizontally, 3 per row, with 210pt horizontal spacing.
func DefaultPosition(signatureIndex int) Position {
	col := signatureIndex % 3
	row := signatureIndex / 3
	return Position{
		Page:   -1,
		X:      20 + float64(col)*210,
		Y:      20 + float64(row)*80,
		Width:  200,
		Height: 70,
	}
}

// methodLabel maps the signing method code to a human-readable Portuguese label.
func methodLabel(method string) string {
	switch strings.ToLower(method) {
	case "cmd":
		return "Chave Movel Digital"
	case "cc":
		return "Cartao de Cidadao"
	default:
		return method
	}
}

// CreateAppearanceXObject builds a PDF Form XObject for the visible signature
// stamp. It returns the content stream bytes and the XObject dictionary.
func CreateAppearanceXObject(info SignerInfo, pos Position) (content []byte, dict pdf.Dict) {
	label := methodLabel(info.SigningMethod)

	var sb strings.Builder
	// Gray border rectangle.
	sb.WriteString("q\n")
	sb.WriteString("0.8 0.8 0.8 RG\n") // gray stroke
	sb.WriteString("0.5 w\n")          // line width
	fmt.Fprintf(&sb, "0 0 %.4f %.4f re S\n", pos.Width, pos.Height)
	sb.WriteString("Q\n")

	// Text block with Helvetica 7pt.
	sb.WriteString("BT\n")
	sb.WriteString("/F1 7 Tf\n")
	sb.WriteString("0 0 0 rg\n") // black text

	// Position text inside the box with some padding.
	lineHeight := 10.0
	startY := pos.Height - 14

	// Rough per-line character budget: usable width is box width minus
	// left+right padding (~12pt), divided by average Helvetica 7pt glyph
	// width (~3.5pt). Never go below 4 so a tiny box still prints something
	// sensible.
	maxChars := int((pos.Width - 12) / 3.5)
	if maxChars < 4 {
		maxChars = 4
	}

	fmt.Fprintf(&sb, "6 %.4f Td\n", startY)
	sb.WriteString("(Assinado digitalmente por) Tj\n")

	fmt.Fprintf(&sb, "0 -%.4f Td\n", lineHeight)
	fmt.Fprintf(&sb, "(%s) Tj\n", encodePDFString(truncateForStamp(strings.ToUpper(info.Name), maxChars)))

	if info.NIC != "" {
		fmt.Fprintf(&sb, "0 -%.4f Td\n", lineHeight)
		fmt.Fprintf(&sb, "(NIC: %s) Tj\n", encodePDFString(truncateForStamp(info.NIC, maxChars-5)))
	}

	fmt.Fprintf(&sb, "0 -%.4f Td\n", lineHeight)
	fmt.Fprintf(&sb, "(Data: %s) Tj\n", encodePDFString(info.DateTime))

	fmt.Fprintf(&sb, "0 -%.4f Td\n", lineHeight)
	fmt.Fprintf(&sb, "(Metodo: %s) Tj\n", encodePDFString(truncateForStamp(label, maxChars-8)))

	sb.WriteString("ET\n")

	content = []byte(sb.String())

	dict = pdf.Dict{
		"Type":    pdf.Name("XObject"),
		"Subtype": pdf.Name("Form"),
		"BBox":    []any{0, 0, pos.Width, pos.Height},
		"Matrix":  []any{1, 0, 0, 1, 0, 0},
		"Resources": pdf.Dict{
			"Font": pdf.Dict{
				"F1": pdf.Dict{
					"Type":     pdf.Name("Font"),
					"Subtype":  pdf.Name("Type1"),
					"BaseFont": pdf.Name("Helvetica"),
					"Encoding": pdf.Name("WinAnsiEncoding"),
				},
			},
		},
	}

	return content, dict
}

// truncateForStamp clips s to at most maxChars runes, appending "..." if the
// clip actually trimmed. Operates on runes so multi-byte names (e.g.
// Portuguese accents) are cut on rune boundaries, not mid-codepoint.
func truncateForStamp(s string, maxChars int) string {
	if maxChars < 1 {
		return ""
	}
	runes := []rune(s)
	if len(runes) <= maxChars {
		return s
	}
	if maxChars <= 3 {
		return string(runes[:maxChars])
	}
	return string(runes[:maxChars-3]) + "..."
}

// encodePDFString converts a UTF-8 string to a CP1252 (WinAnsi) byte sequence
// and applies PDF literal-string escaping. Characters that have no CP1252
// representation are replaced with '?' so we never emit malformed bytes.
func encodePDFString(s string) string {
	var sb strings.Builder
	for _, r := range s {
		b, ok := utf8ToCP1252[r]
		if !ok {
			b = '?'
		}
		switch b {
		case '(':
			sb.WriteString(`\(`)
		case ')':
			sb.WriteString(`\)`)
		case '\\':
			sb.WriteString(`\\`)
		default:
			sb.WriteByte(b)
		}
	}
	return sb.String()
}

// utf8ToCP1252 maps Unicode code points to their CP1252 byte. Built from the
// Latin-1 range (U+0000..U+00FF, identity mapping) plus the CP1252 0x80..0x9F
// extensions (Euro sign, smart quotes, etc.).
var utf8ToCP1252 = func() map[rune]byte {
	m := make(map[rune]byte, 256)
	for i := 0; i < 0x80; i++ {
		m[rune(i)] = byte(i)
	}
	for i := 0xA0; i <= 0xFF; i++ {
		m[rune(i)] = byte(i)
	}
	for r, b := range map[rune]byte{
		'€': 0x80, '‚': 0x82, 'ƒ': 0x83, '„': 0x84, '…': 0x85, '†': 0x86, '‡': 0x87,
		'ˆ': 0x88, '‰': 0x89, 'Š': 0x8A, '‹': 0x8B, 'Œ': 0x8C, 'Ž': 0x8E,
		'‘': 0x91, '’': 0x92, '“': 0x93, '”': 0x94, '•': 0x95, '–': 0x96, '—': 0x97,
		'˜': 0x98, '™': 0x99, 'š': 0x9A, '›': 0x9B, 'œ': 0x9C, 'ž': 0x9E, 'Ÿ': 0x9F,
	} {
		m[r] = b
	}
	return m
}()
