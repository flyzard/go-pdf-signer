package pades

import (
	"context"
	"crypto"
	"crypto/x509"
	"fmt"

	pdcrypto "github.com/flyzard/pdf-signer/internal/crypto"
	"github.com/flyzard/pdf-signer/internal/pdf"
)

// AppendDocTimeStampOptions configures the PAdES-LTA DocTimeStamp pass.
type AppendDocTimeStampOptions struct {
	// PDFBytes is the document as it stands after the signer's CMS is
	// embedded AND the DSS incremental update has been written.
	// AppendDocTimeStamp adds a further incremental update over this state.
	PDFBytes []byte
	// TSAURL is the RFC 3161 TSA to call for the document timestamp. For
	// eIDAS LTA signatures this MUST resolve — there is no meaningful
	// degraded mode.
	TSAURL string
	// TSAPool is the cert pool the embedded TSA signer cert must chain
	// through. Split from signer roots (R-3.1.5).
	TSAPool *x509.CertPool
	// DigestAlgorithm is the hash used for the TimeStampReq's
	// messageImprint. SHA-256 is the universally accepted default; use
	// SHA-384 / SHA-512 only when the TSA's policy specifically requires.
	DigestAlgorithm crypto.Hash
	// PlaceholderSize sizes the inline TSA-token placeholder in the
	// DocTimeStamp signature dict. Typical PT TSA tokens are 6-10 KB;
	// 16 KB is the default and leaves headroom. Overridable for callers
	// that know their TSA's token size profile.
	PlaceholderSize int
	// FieldName is the AcroForm field name assigned to the DocTimeStamp
	// widget. Leaving it empty auto-generates based on prior signature
	// count ("DocTS_N").
	FieldName string
}

// AppendDocTimeStamp writes an RFC 3161 DocTimeStamp signature as a new
// incremental update on top of the input PDF, raising the signature from
// PAdES-B-LT to PAdES-B-LTA (ETSI EN 319 142-1 §5.6).
//
// The DocTimeStamp is invisible (/Rect [0 0 0 0]), carries a raw TSA
// token in /Contents (SubFilter ETSI.RFC3161), and covers the entire
// prior document state via its ByteRange. Verifiers treat the genTime as
// the authoritative anchor for long-term validity. Re-anchoring before
// prior hash algorithms weaken is an `augment` operation, out of scope
// for v1.
//
// Returns the full PDF bytes (input + increment) ready to persist via
// pdf.WriteFileAtomic.
func AppendDocTimeStamp(ctx context.Context, opts AppendDocTimeStampOptions) ([]byte, error) {
	if len(opts.PDFBytes) == 0 {
		return nil, fmt.Errorf("doctimestamp: PDFBytes is empty")
	}
	if opts.TSAURL == "" {
		return nil, fmt.Errorf("doctimestamp: TSAURL is empty (required for B-LTA)")
	}
	if opts.TSAPool == nil {
		return nil, fmt.Errorf("doctimestamp: TSAPool is nil (required for trust check)")
	}
	hashAlg := opts.DigestAlgorithm
	if hashAlg == 0 {
		hashAlg = crypto.SHA256
	}

	doc, err := pdf.Parse(opts.PDFBytes)
	if err != nil {
		return nil, fmt.Errorf("doctimestamp: parse base PDF: %w", err)
	}
	w := pdf.NewWriter(doc)
	if opts.PlaceholderSize > 0 {
		if err := w.SetPlaceholderSize(opts.PlaceholderSize); err != nil {
			return nil, fmt.Errorf("doctimestamp: %w", err)
		}
	}

	fieldName := opts.FieldName
	if fieldName == "" {
		fieldName = fmt.Sprintf("DocTS_%d", countExistingSignatures(doc)+1)
	}

	dtsDict := pdf.Dict{
		"Type":      pdf.Name("DocTimeStamp"),
		"Filter":    pdf.Name("Adobe.PPKLite"),
		"SubFilter": pdf.Name("ETSI.RFC3161"),
	}
	dtsRef := w.AddSignatureObject(dtsDict)

	// Invisible widget — /Rect [0 0 0 0] per ISO 32000-1 §12.5.6.19 so no
	// visible mark appears on the page.
	widgetRef := w.AddObject(pdf.Dict{
		"Type":    pdf.Name("Annot"),
		"Subtype": pdf.Name("Widget"),
		"FT":      pdf.Name("Sig"),
		"T":       fieldName,
		"V":       dtsRef,
		"Rect":    []any{0, 0, 0, 0},
		"F":       132,
	})

	w.UpdateCatalog(func(cat pdf.Dict) pdf.Dict {
		acro, _ := doc.ResolveDict(cat["AcroForm"])
		if acro == nil {
			acro = pdf.Dict{}
		} else {
			cloned := make(pdf.Dict, len(acro))
			for k, v := range acro {
				cloned[k] = v
			}
			acro = cloned
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
		return cat
	})

	data, err := w.WriteToBytes()
	if err != nil {
		return nil, fmt.Errorf("doctimestamp: build increment: %w", err)
	}

	br, err := pdf.FindPlaceholder(data)
	if err != nil {
		return nil, fmt.Errorf("doctimestamp: find placeholder: %w", err)
	}
	data, err = patchByteRange(data, br)
	if err != nil {
		return nil, fmt.Errorf("doctimestamp: patch byte range: %w", err)
	}

	digest, err := pdf.HashByteRanges(data, br)
	if err != nil {
		return nil, fmt.Errorf("doctimestamp: hash byte range: %w", err)
	}
	// HashByteRanges is SHA-256 by construction; the TSA imprint hash
	// follows suit. DigestAlgorithm is honoured once HashByteRanges gains
	// algorithm agility.
	// includeNonce=false: see timestamp.go — free TSAs don't reliably echo
	// nonces; flip back once AMA qualified TSA is configured.
	reqDER, nonce, err := pdcrypto.BuildTimeStampReq(digest, crypto.SHA256, false, true)
	if err != nil {
		return nil, fmt.Errorf("doctimestamp: build TS req: %w", err)
	}
	token, err := pdcrypto.FetchTimeStampToken(ctx, opts.TSAURL, reqDER, nonce)
	if err != nil {
		return nil, fmt.Errorf("doctimestamp: fetch TS token: %w", err)
	}
	if _, err := ValidateTSAToken(token, digest, opts.TSAPool); err != nil {
		return nil, fmt.Errorf("doctimestamp: validate TS token: %w", err)
	}

	// DocTimeStamp /Contents carries the raw RFC 3161 TimeStampToken (a
	// CMS SignedData DER) — no additional CMS wrapping, unlike an approval
	// signature. EmbedCMS just hex-embeds whatever bytes we pass.
	return pdf.EmbedCMS(data, token)
}

