package pdf

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// createTestPDF writes a minimal valid PDF to a temp directory and returns the path.
// Byte offsets have been hand-verified:
//
//	%PDF-1.7\n              => 9 bytes  (offset 0)
//	1 0 obj\n               => 8 bytes  (offset 9)
//	<< /Type /Catalog /Pages 2 0 R >>\n  => 34 bytes  (offset 17)
//	endobj\n                => 7 bytes  (offset 51)
//	2 0 obj\n               => 8 bytes  (offset 58)   ← obj2
//	<< /Type /Pages /Kids [3 0 R] /Count 1 >>\n => 43 bytes (offset 66)
//	endobj\n                => 7 bytes  (offset 109) [wait — let me note actual: 58+8+43+7=116? no]
//
// Verified by python: obj1=9, obj2=58, obj3=115, xref=186.
func createTestPDF(t *testing.T) string {
	t.Helper()

	// This content is byte-exact. Offsets:
	//   obj 1 → 9
	//   obj 2 → 58
	//   obj 3 → 115
	//   xref  → 186
	// Each xref entry is exactly 20 bytes: "NNNNNNNNNN GGGGG F \n"
	// where F is 'n' or 'f', and there is a space before \n (PDF spec requirement).
	content := "" +
		"%PDF-1.7\n" +
		"1 0 obj\n" +
		"<< /Type /Catalog /Pages 2 0 R >>\n" +
		"endobj\n" +
		"2 0 obj\n" +
		"<< /Type /Pages /Kids [3 0 R] /Count 1 >>\n" +
		"endobj\n" +
		"3 0 obj\n" +
		"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\n" +
		"endobj\n" +
		"xref\n" +
		"0 4\n" +
		"0000000000 65535 f \n" +
		"0000000009 00000 n \n" +
		"0000000058 00000 n \n" +
		"0000000115 00000 n \n" +
		"trailer\n" +
		"<< /Size 4 /Root 1 0 R >>\n" +
		"startxref\n" +
		"186\n" +
		"%%EOF\n"

	dir := t.TempDir()
	path := filepath.Join(dir, "test.pdf")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("createTestPDF: %v", err)
	}
	return path
}

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
