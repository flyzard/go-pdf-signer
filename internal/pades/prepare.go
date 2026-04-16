package pades

import (
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/flyzard/pdf-signer/internal/appearance"
	"github.com/flyzard/pdf-signer/internal/pdf"
)

// PrepareOptions configures the prepare step.
type PrepareOptions struct {
	InputPath     string
	OutputPath    string
	SignerName    string
	SignerNIC     string
	SigningMethod string
	SignaturePos  appearance.Position
}

// PrepareResult contains the output of the prepare step.
type PrepareResult struct {
	Hash          string `json:"hash"`           // Base64-encoded SHA-256
	HashAlgorithm string `json:"hash_algorithm"` // "SHA-256"
	FieldName     string `json:"field_name"`     // "Sig_1", "Sig_2", etc.
}

// Prepare opens the input PDF, adds a signature placeholder with visible stamp,
// computes the ByteRange hash, and writes the prepared PDF to output.
func Prepare(opts PrepareOptions) (*PrepareResult, error) {
	// 1. Open the input PDF.
	doc, err := pdf.Open(opts.InputPath)
	if err != nil {
		return nil, fmt.Errorf("open input PDF: %w", err)
	}

	// 2. Count existing signatures from AcroForm /Fields to determine index.
	sigIndex := countExistingSignatures(doc)
	fieldName := fmt.Sprintf("Sig_%d", sigIndex+1)

	// 3. Create writer.
	w := pdf.NewWriter(doc)

	// 4. Create appearance XObject.
	now := time.Now().UTC()
	dateStr := now.Format("2006-01-02 15:04:05 UTC")

	info := appearance.SignerInfo{
		Name:          opts.SignerName,
		NIC:           opts.SignerNIC,
		SigningMethod: opts.SigningMethod,
		DateTime:      dateStr,
	}
	apContent, apDict := appearance.CreateAppearanceXObject(info, opts.SignaturePos)
	apRef := w.AddStream(apContent, apDict)

	// 5. Create signature dictionary.
	pdfDate := now.Format("D:20060102150405+00'00'")
	sigDict := pdf.Dict{
		"Type":      pdf.Name("Sig"),
		"Filter":    pdf.Name("Adobe.PPKLite"),
		"SubFilter": pdf.Name("ETSI.CAdES.detached"),
		"Reason":    "Assinatura digital de ata",
		"Location":  "Portugal",
		"M":         pdfDate,
		"Name":      opts.SignerName,
	}
	sigRef := w.AddSignatureObject(sigDict)

	// 6. Create widget annotation.
	pos := opts.SignaturePos
	rect := []any{pos.X, pos.Y, pos.X + pos.Width, pos.Y + pos.Height}
	widgetDict := pdf.Dict{
		"Type":    pdf.Name("Annot"),
		"Subtype": pdf.Name("Widget"),
		"FT":      pdf.Name("Sig"),
		"T":       fieldName,
		"V":       sigRef,
		"Rect":    rect,
		"F":       132,
		"AP": pdf.Dict{
			"N": apRef,
		},
	}
	widgetRef := w.AddObject(widgetDict)

	// 7. Update catalog with AcroForm.
	w.UpdateCatalog(func(cat pdf.Dict) pdf.Dict {
		// Build the fields array, preserving any existing fields.
		var fields []any
		if existingAcroForm, ok := cat.GetDict("AcroForm"); ok {
			if existingFields, ok := existingAcroForm.GetArray("Fields"); ok {
				fields = append(fields, existingFields...)
			}
		}
		fields = append(fields, widgetRef)

		cat["AcroForm"] = pdf.Dict{
			"SigFlags": 3,
			"Fields":   fields,
		}
		return cat
	})

	// 8. Build the PDF bytes in memory.
	data, err := w.WriteToBytes()
	if err != nil {
		return nil, fmt.Errorf("build PDF bytes: %w", err)
	}

	// 9. Find placeholder to get ByteRange.
	br, err := pdf.FindPlaceholder(data)
	if err != nil {
		return nil, fmt.Errorf("find placeholder: %w", err)
	}

	// 10. Patch the ByteRange in memory.
	data, err = patchByteRange(data, br)
	if err != nil {
		return nil, fmt.Errorf("patch byte range: %w", err)
	}

	// 11. Re-find placeholder and hash the final bytes.
	br, err = pdf.FindPlaceholder(data)
	if err != nil {
		return nil, fmt.Errorf("find placeholder after patch: %w", err)
	}

	hash := pdf.HashByteRanges(data, br)

	// 12. Write final result to disk once.
	if err := os.WriteFile(opts.OutputPath, data, 0600); err != nil {
		return nil, fmt.Errorf("write output PDF: %w", err)
	}

	// 13. Return result.
	return &PrepareResult{
		Hash:          base64.StdEncoding.EncodeToString(hash),
		HashAlgorithm: "SHA-256",
		FieldName:     fieldName,
	}, nil
}

// patchByteRange finds "/ByteRange [0 0 0 0]" (with trailing padding spaces)
// in data, replaces it with the actual byte range values, and pads with spaces
// to maintain the same total length.
func patchByteRange(data []byte, br pdf.ByteRange) ([]byte, error) {
	// Find the padded ByteRange placeholder.
	placeholder := "/ByteRange [0 0 0 0]"
	idx := strings.Index(string(data), placeholder)
	if idx < 0 {
		return nil, fmt.Errorf("ByteRange placeholder not found in PDF data")
	}

	// Find the full extent of the placeholder (including trailing padding spaces).
	// The writer pads to 60 chars total.
	endIdx := idx + len(placeholder)
	for endIdx < len(data) && data[endIdx] == ' ' {
		endIdx++
	}
	totalLen := endIdx - idx

	// Build the replacement string with actual values.
	replacement := fmt.Sprintf("/ByteRange %s", br.String())

	// Pad with spaces to fill the same total length.
	for len(replacement) < totalLen {
		replacement += " "
	}

	if len(replacement) != totalLen {
		return nil, fmt.Errorf("ByteRange replacement (%d bytes) does not fit in placeholder (%d bytes)", len(replacement), totalLen)
	}

	// Patch in place.
	result := make([]byte, len(data))
	copy(result, data)
	copy(result[idx:idx+totalLen], []byte(replacement))

	return result, nil
}

// countExistingSignatures inspects the catalog's AcroForm /Fields for existing
// signature fields. Returns 0 if no AcroForm or no signatures found.
func countExistingSignatures(doc *pdf.Document) int {
	acroForm, ok := doc.Catalog.GetDict("AcroForm")
	if !ok {
		return 0
	}
	fields, ok := acroForm.GetArray("Fields")
	if !ok {
		return 0
	}

	count := 0
	for _, f := range fields {
		ref, ok := f.(pdf.Ref)
		if !ok {
			continue
		}
		fieldDict, err := doc.ReadDictObject(ref)
		if err != nil {
			continue
		}
		ft, ok := fieldDict.GetName("FT")
		if ok && ft == "Sig" {
			count++
		}
	}
	return count
}
