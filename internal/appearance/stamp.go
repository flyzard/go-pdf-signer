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
	fmt.Fprintf(&sb, "0 0 %g %g re S\n", pos.Width, pos.Height)
	sb.WriteString("Q\n")

	// Text block with Helvetica 7pt.
	sb.WriteString("BT\n")
	sb.WriteString("/F1 7 Tf\n")
	sb.WriteString("0 0 0 rg\n") // black text

	// Position text inside the box with some padding.
	lineHeight := 10.0
	startY := pos.Height - 14

	fmt.Fprintf(&sb, "6 %g Td\n", startY)
	sb.WriteString("(Assinado digitalmente por) Tj\n")

	fmt.Fprintf(&sb, "0 -%g Td\n", lineHeight)
	fmt.Fprintf(&sb, "(%s) Tj\n", escapePDFString(strings.ToUpper(info.Name)))

	if info.NIC != "" {
		fmt.Fprintf(&sb, "0 -%g Td\n", lineHeight)
		fmt.Fprintf(&sb, "(NIC: %s) Tj\n", escapePDFString(info.NIC))
	}

	fmt.Fprintf(&sb, "0 -%g Td\n", lineHeight)
	fmt.Fprintf(&sb, "(Data: %s) Tj\n", escapePDFString(info.DateTime))

	fmt.Fprintf(&sb, "0 -%g Td\n", lineHeight)
	fmt.Fprintf(&sb, "(Metodo: %s) Tj\n", escapePDFString(label))

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
				},
			},
		},
	}

	return content, dict
}

// escapePDFString escapes characters that are special in PDF string literals.
func escapePDFString(s string) string {
	r := strings.NewReplacer(
		`\`, `\\`,
		`(`, `\(`,
		`)`, `\)`,
	)
	return r.Replace(s)
}
