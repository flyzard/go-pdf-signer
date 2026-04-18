package pades

import (
	"github.com/flyzard/pdf-signer/internal/pdf"
)

// signatureBundle ties together the three pieces the verify path needs for
// one signature: the signature dict itself, its /Contents CMS blob (trimmed
// to the ASN.1 outer length), and its parsed /ByteRange. ByteRangeErr is
// non-nil if the dict's /ByteRange was missing or malformed — kept around so
// the verifier can surface the specific failure rather than dropping the
// signature silently.
type signatureBundle struct {
	SigDict      pdf.Dict
	Contents     []byte
	ByteRange    pdf.ByteRange
	ByteRangeErr error
}

// extractSignatureBundles walks AcroForm /Fields (including /Kids subtrees)
// and collects one bundle per signature field whose /V resolves to a
// signature dict with a non-empty /Contents.
func extractSignatureBundles(doc *pdf.Document) ([]signatureBundle, error) {
	acro, ok := doc.ResolveDict(doc.Catalog["AcroForm"])
	if !ok {
		return nil, nil
	}
	fields, ok := acro.GetArray("Fields")
	if !ok {
		return nil, nil
	}

	var out []signatureBundle
	walkFieldTree(doc, fields, func(f pdf.Dict) {
		v, ok := f["V"]
		if !ok {
			return
		}
		sig, ok := doc.ResolveDict(v)
		if !ok {
			return
		}
		if ft, _ := sig.GetName("Type"); ft != "" && ft != "Sig" {
			return
		}
		raw, ok := sigContentsBytes(sig)
		if !ok {
			return
		}
		if trimmed, err := trimToASN1Length(raw); err == nil {
			raw = trimmed
		}
		if len(raw) == 0 {
			return
		}

		b := signatureBundle{SigDict: sig, Contents: raw}
		br, err := parseSigByteRange(sig)
		if err != nil {
			b.ByteRangeErr = err
		} else {
			b.ByteRange = br
		}
		out = append(out, b)
	})
	return out, nil
}
