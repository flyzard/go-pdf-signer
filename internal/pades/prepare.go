package pades

import (
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/flyzard/pdf-signer/internal/appearance"
	"github.com/flyzard/pdf-signer/internal/pdf"
)

// CertificationLevel enumerates the DocMDP permission levels per
// ISO 32000-1 §12.8.2.2. Level 0 means "no DocMDP entry emitted" — plain
// approval signature. Only the FIRST signature in a document may assert a
// certification level; subsequent approval signatures must leave it
// untouched or Adobe flags the document.
type CertificationLevel int

const (
	CertLevelNone         CertificationLevel = 0 // no /Perms /DocMDP emitted
	CertLevelNoChanges    CertificationLevel = 1 // any change invalidates the signature
	CertLevelFormFilling  CertificationLevel = 2 // form fill + signatures allowed
	CertLevelAnnotations  CertificationLevel = 3 // + annotations allowed
)

// PrepareOptions configures the prepare step.
type PrepareOptions struct {
	InputPath     string
	OutputPath    string
	SignerName    string
	SignerNIC     string
	SigningMethod string
	SignaturePos  appearance.Position
	// PlaceholderSize overrides the in-PDF /Contents placeholder capacity in
	// bytes. Zero means use pdf.PlaceholderSize (16 KB) — the right default
	// for B-B / B-LT without a signature-TS. Bump to 32+ KB when callers know
	// the CMS will carry a timestamp token or a long cert chain.
	PlaceholderSize int
	// Reason / Location / Name populate the corresponding /Reason /Location
	// /Name entries in the signature dict. Empty → sensible PT defaults
	// ("Assinatura digital de ata" / "Portugal" / SignerName).
	Reason   string
	Location string
	Name     string
	// Invisible suppresses the visible stamp: widget /Rect is [0 0 0 0] and
	// no appearance XObject is emitted. Use for workflows that sign
	// programmatically without any visual mark.
	Invisible bool
	// CertificationLevel writes /Perms /DocMDP on the catalog, marking this
	// signature as a certification (DocMDP) signature. Must be the FIRST
	// signature in the document. CertLevelNone (default) emits a plain
	// approval signature.
	CertificationLevel CertificationLevel
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
	doc, err := pdf.Open(opts.InputPath)
	if err != nil {
		return nil, fmt.Errorf("open input PDF: %w", err)
	}

	sigIndex := countExistingSignatures(doc)
	fieldName := fmt.Sprintf("Sig_%d", sigIndex+1)

	w := pdf.NewWriter(doc)
	if opts.PlaceholderSize > 0 {
		if err := w.SetPlaceholderSize(opts.PlaceholderSize); err != nil {
			return nil, fmt.Errorf("set placeholder size: %w", err)
		}
	}

	now := time.Now().UTC()
	dateStr := now.Format("2006-01-02 15:04:05 UTC")

	// Appearance XObject is skipped when --invisible is set (R-5.4.5 /
	// R-1.1.11). The widget uses /Rect [0 0 0 0] in that case.
	var apRef pdf.Ref
	if !opts.Invisible {
		info := appearance.SignerInfo{
			Name:          opts.SignerName,
			NIC:           opts.SignerNIC,
			SigningMethod: opts.SigningMethod,
			DateTime:      dateStr,
		}
		apContent, apDict := appearance.CreateAppearanceXObject(info, opts.SignaturePos)
		apRef = w.AddStream(apContent, apDict)
	}

	// pdfDate hard-codes "+00'00'" because we use UTC above. If you ever
	// change `now` to local time, this format string will misreport the offset.
	pdfDate := now.Format("D:20060102150405+00'00'")
	reason := opts.Reason
	if reason == "" {
		reason = "Assinatura digital de ata"
	}
	location := opts.Location
	if location == "" {
		location = "Portugal"
	}
	name := opts.Name
	if name == "" {
		name = opts.SignerName
	}
	sigDict := pdf.Dict{
		"Type":      pdf.Name("Sig"),
		"Filter":    pdf.Name("Adobe.PPKLite"),
		"SubFilter": pdf.Name("ETSI.CAdES.detached"),
		"Reason":    reason,
		"Location":  location,
		"M":         pdfDate,
		"Name":      name,
	}
	if opts.CertificationLevel != CertLevelNone {
		if sigIndex != 0 {
			return nil, fmt.Errorf("--certification-level is only valid on the FIRST signature (this would be #%d)", sigIndex+1)
		}
		sigDict["Reference"] = []any{buildDocMDPSigRef(opts.CertificationLevel)}
	}
	sigRef := w.AddSignatureObject(sigDict)

	pos := opts.SignaturePos
	rect := []any{pos.X, pos.Y, pos.X + pos.Width, pos.Y + pos.Height}
	if opts.Invisible {
		rect = []any{0, 0, 0, 0}
	}

	// Resolve the target page BEFORE building the widget so /P can point
	// at it. Without /P + page-/Annots membership the widget exists only
	// in AcroForm.Fields and Adobe Reader will list the signature in the
	// Signatures panel but paint nothing on the page.
	pageRef, err := doc.FindPageRef(pos.Page)
	if err != nil {
		return nil, fmt.Errorf("resolve signature page (index %d): %w", pos.Page, err)
	}

	widgetDict := pdf.Dict{
		"Type":    pdf.Name("Annot"),
		"Subtype": pdf.Name("Widget"),
		"FT":      pdf.Name("Sig"),
		"T":       fieldName,
		"V":       sigRef,
		"Rect":    rect,
		"F":       132,
		"P":       pageRef,
	}
	if !opts.Invisible {
		widgetDict["AP"] = pdf.Dict{"N": apRef}
	}
	widgetRef := w.AddObject(widgetDict)

	// Append widgetRef to the target page's /Annots. Without this step
	// the widget is invisible in every PDF viewer — the signature is
	// cryptographically valid but the user sees no stamp on the page.
	pageDict, err := doc.PageDict(pageRef)
	if err != nil {
		return nil, fmt.Errorf("read page dict for /Annots update: %w", err)
	}
	existing, _ := pageDict.GetArray("Annots")
	pageAnnots := make([]any, 0, len(existing)+1)
	pageAnnots = append(pageAnnots, existing...)
	pageAnnots = append(pageAnnots, widgetRef)
	pageDict["Annots"] = pageAnnots
	w.ReplaceObject(pageRef, pageDict)

	// Update catalog with AcroForm — preserve every existing key, just
	// merge the new sig field into /Fields and ensure /SigFlags includes
	// AppendOnly|SignaturesExist.
	w.UpdateCatalog(func(cat pdf.Dict) pdf.Dict {
		acro, _ := doc.ResolveDict(cat["AcroForm"])
		if acro == nil {
			acro = pdf.Dict{}
		} else {
			acro = acro.Clone()
		}

		var fields []any
		if existing, ok := acro.GetArray("Fields"); ok {
			fields = append(fields, existing...)
		}
		fields = append(fields, widgetRef)
		acro["Fields"] = fields

		existingFlags, _ := acro.GetInt("SigFlags")
		acro["SigFlags"] = existingFlags | 3

		cat["AcroForm"] = acro

		// DocMDP: the catalog's /Perms /DocMDP points at the signature
		// asserting certification semantics. Only one certification
		// signature per document (ISO 32000-1 §12.8.2.2); we already
		// refuse sigIndex != 0 above.
		if opts.CertificationLevel != CertLevelNone {
			perms, _ := doc.ResolveDict(cat["Perms"])
			if perms == nil {
				perms = pdf.Dict{}
			} else {
				perms = perms.Clone()
			}
			perms["DocMDP"] = sigRef
			cat["Perms"] = perms
		}

		return cat
	})

	data, err := w.WriteToBytes()
	if err != nil {
		return nil, fmt.Errorf("build PDF bytes: %w", err)
	}

	br, err := pdf.FindPlaceholder(data)
	if err != nil {
		return nil, fmt.Errorf("find placeholder: %w", err)
	}

	data, err = patchByteRange(data, br)
	if err != nil {
		return nil, fmt.Errorf("patch byte range: %w", err)
	}

	// br is byte-stable across the in-place ByteRange patch (length preserved
	// by padding), so no re-find is needed.
	hash, err := pdf.HashByteRanges(data, br)
	if err != nil {
		return nil, fmt.Errorf("hash byte ranges: %w", err)
	}

	if err := pdf.WriteFileAtomic(opts.OutputPath, data); err != nil {
		return nil, fmt.Errorf("write output PDF %s: %w", opts.OutputPath, err)
	}

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

// countExistingSignatures counts AcroForm leaf fields whose /FT is /Sig.
func countExistingSignatures(doc *pdf.Document) int {
	acroForm, ok := doc.ResolveDict(doc.Catalog["AcroForm"])
	if !ok {
		return 0
	}
	fields, ok := acroForm.GetArray("Fields")
	if !ok {
		return 0
	}
	count := 0
	walkFieldTree(doc, fields, func(fd pdf.Dict) {
		if ft, ok := fd.GetName("FT"); ok && ft == "Sig" {
			count++
		}
	})
	return count
}
