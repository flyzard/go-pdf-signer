package pdf

import (
	"os"
	"path/filepath"
	"testing"
)

// createTestPDF writes a minimal valid PDF to a temp directory and returns the path.
// Byte offsets: obj1=9, obj2=58, obj3=115, xref=186.
func createTestPDF(t *testing.T) string {
	t.Helper()

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
