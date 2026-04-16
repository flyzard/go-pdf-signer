package pdf

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestOpenPDF(t *testing.T) {
	path := createTestPDF(t)

	doc, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	if doc.NextObjNum < 4 {
		t.Errorf("NextObjNum = %d, want >= 4", doc.NextObjNum)
	}

	typeName, ok := doc.Catalog.GetName("Type")
	if !ok {
		t.Errorf("Catalog missing /Type")
	} else if typeName != "Catalog" {
		t.Errorf("Catalog /Type = %q, want Catalog", typeName)
	}

	pagesRef, ok := doc.Catalog.GetRef("Pages")
	if !ok {
		t.Errorf("Catalog missing /Pages ref")
	} else if pagesRef.Number == 0 {
		t.Errorf("Catalog /Pages ref has number 0")
	}
}

func TestFindStartXRef(t *testing.T) {
	path := createTestPDF(t)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	offset, err := findStartXRef(data)
	if err != nil {
		t.Fatalf("findStartXRef: %v", err)
	}
	if offset == 0 {
		t.Errorf("startxref offset is 0")
	}

	// The bytes at that offset must start with "xref".
	if int(offset) >= len(data) {
		t.Fatalf("offset %d out of range (len=%d)", offset, len(data))
	}
	chunk := data[offset:]
	if len(chunk) < 4 || string(chunk[:4]) != "xref" {
		t.Errorf("data at startxref offset does not start with 'xref', got %q", string(chunk[:min(10, len(chunk))]))
	}
}

func TestParseDict(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
		check   func(t *testing.T, d Dict)
	}{
		{
			name:  "simple dict",
			input: "<< /Type /Catalog /Size 42 >>",
			check: func(t *testing.T, d Dict) {
				if n, ok := d.GetName("Type"); !ok || n != "Catalog" {
					t.Errorf("Type = %v %v, want Catalog", n, ok)
				}
				if s, ok := d.GetInt("Size"); !ok || s != 42 {
					t.Errorf("Size = %v %v, want 42", s, ok)
				}
			},
		},
		{
			name:  "nested dict",
			input: "<< /Outer << /Inner /Value >> >>",
			check: func(t *testing.T, d Dict) {
				inner, ok := d.GetDict("Outer")
				if !ok {
					t.Fatal("missing Outer")
				}
				n, ok := inner.GetName("Inner")
				if !ok || n != "Value" {
					t.Errorf("Inner = %v %v, want Value", n, ok)
				}
			},
		},
		{
			name:  "dict with array",
			input: "<< /Kids [1 0 R 2 0 R] /Count 2 >>",
			check: func(t *testing.T, d Dict) {
				arr, ok := d.GetArray("Kids")
				if !ok {
					t.Fatal("missing Kids")
				}
				if len(arr) != 2 {
					t.Errorf("Kids len = %d, want 2", len(arr))
				}
				r, ok := arr[0].(Ref)
				if !ok || r.Number != 1 {
					t.Errorf("Kids[0] = %v, want Ref{1,0}", arr[0])
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d, err := parseDict([]byte(tc.input))
			if tc.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("parseDict: %v", err)
			}
			if tc.check != nil {
				tc.check(t, d)
			}
		})
	}
}

func TestSerialize(t *testing.T) {
	tests := []struct {
		name  string
		input any
		want  string
	}{
		{"name", Name("Type"), "/Type"},
		{"int", 42, "42"},
		{"ref", Ref{Number: 5, Generation: 0}, "5 0 R"},
		{"string", "hello", "(hello)"},
		{"bool true", true, "true"},
		{"bool false", false, "false"},
		{"array", []any{Name("A"), 1, Ref{2, 0}}, "[/A 1 2 0 R]"},
		{"nil", nil, "null"},
		{"bytes", []byte{0xDE, 0xAD}, "<dead>"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := Serialize(tc.input)
			if got != tc.want {
				t.Errorf("Serialize(%v) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestSerializeDictDeterministic(t *testing.T) {
	d := Dict{
		"Type":  Name("Catalog"),
		"Pages": Ref{2, 0},
		"Size":  42,
	}

	first := Serialize(d)
	for i := 0; i < 100; i++ {
		got := Serialize(d)
		if got != first {
			t.Fatalf("non-deterministic serialization on iteration %d:\n  first: %s\n  got:   %s", i, first, got)
		}
	}
}

func TestRealPDF(t *testing.T) {
	// Skip if wkhtmltopdf is not available.
	if _, err := exec.LookPath("wkhtmltopdf"); err != nil {
		t.Skip("wkhtmltopdf not available")
	}

	dir := t.TempDir()
	pdfPath := filepath.Join(dir, "real.pdf")

	cmd := exec.Command("wkhtmltopdf", "-", pdfPath)
	cmd.Stdin = strings.NewReader("<html><body><p>Hello PDF</p></body></html>")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("wkhtmltopdf: %v\n%s", err, out)
	}

	doc, err := Open(pdfPath)
	if err != nil {
		t.Fatalf("Open real PDF: %v", err)
	}
	if doc.NextObjNum == 0 {
		t.Error("NextObjNum is 0 for real PDF")
	}
	if doc.Catalog == nil {
		t.Error("Catalog is nil for real PDF")
	}
	t.Logf("Real PDF: version=%s, objects=%d, catalog=%v", doc.Version, doc.NextObjNum, doc.Catalog)
}
