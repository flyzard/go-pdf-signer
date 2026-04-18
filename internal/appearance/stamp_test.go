package appearance

import (
	"bytes"
	"testing"

	"github.com/flyzard/pdf-signer/internal/pdf"
)

func TestStampDeclaresWinAnsiEncoding(t *testing.T) {
	_, dict := CreateAppearanceXObject(SignerInfo{
		Name: "João da Silva", DateTime: "2026-04-16",
	}, Position{Width: 200, Height: 70})

	res, ok := dict["Resources"].(pdf.Dict)
	if !ok {
		t.Fatalf("Resources not a pdf.Dict, got %T", dict["Resources"])
	}
	fonts, ok := res["Font"].(pdf.Dict)
	if !ok {
		t.Fatal("Resources/Font missing")
	}
	f1, ok := fonts["F1"].(pdf.Dict)
	if !ok {
		t.Fatal("F1 font missing")
	}
	if _, ok := f1["Encoding"]; !ok {
		t.Error("F1 must declare /Encoding for non-ASCII text rendering")
	}
}

func TestStampConvertsAccentedNamesToCP1252(t *testing.T) {
	content, _ := CreateAppearanceXObject(SignerInfo{
		Name: "João", DateTime: "2026-04-16",
	}, Position{Width: 200, Height: 70})

	// CP1252 byte for 'Ã' (uppercased João -> JOÃO) is 0xC3.
	if !bytes.Contains(content, []byte{0xC3}) {
		t.Errorf("expected CP1252 byte 0xC3 for 'Ã' in content, got %q", content)
	}
}
