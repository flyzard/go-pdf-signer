package pdf

import (
	"strings"
	"testing"
)

func TestSerializeASCIIStringUsesLiteral(t *testing.T) {
	got := Serialize("Hello")
	if got != "(Hello)" {
		t.Errorf("Serialize(\"Hello\") = %q, want (Hello)", got)
	}
}

func TestSerializeNonASCIIEncodesUTF16BE(t *testing.T) {
	// "João" → UTF-16BE with BOM: FE FF 00 4A 00 6F 00 E3 00 6F
	got := Serialize("João")
	want := "<FEFF004A006F00E3006F>"
	if !strings.EqualFold(got, want) {
		t.Errorf("Serialize(\"João\") = %q, want %q", got, want)
	}
}

func TestSerializeMixedContainsBOM(t *testing.T) {
	got := Serialize("Olá Mundo")
	if !strings.HasPrefix(got, "<FEFF") {
		t.Errorf("non-ASCII string should be UTF-16BE-hex with BOM, got %q", got)
	}
	if !strings.HasSuffix(got, ">") {
		t.Errorf("should be hex string, got %q", got)
	}
}
