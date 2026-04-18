package pades

import (
	"github.com/flyzard/pdf-signer/internal/pdf"
)

// DocMDP (Document Modification Detection and Prevention) transform OID
// per ISO 32000-1 §12.8.2.2. Identifies the signature as a certification
// signature; the /P parameter inside TransformParams encodes the
// CertificationLevel.
//
// Only the first signature in a document may be a certification signature;
// subsequent approval signatures coexist with but cannot alter the MDP
// permissions. The writer side only emits the dict when the caller opts in
// via --certification-level; the detector on verify surfaces presence so
// callers can audit.

// buildDocMDPSigRef emits a SigRef dict (ISO 32000-1 §12.8.2) binding the
// DocMDP transform to the signature. Emitted under /Reference on the
// signature dict.
func buildDocMDPSigRef(level CertificationLevel) pdf.Dict {
	return pdf.Dict{
		"Type":            pdf.Name("SigRef"),
		"TransformMethod": pdf.Name("DocMDP"),
		"TransformParams": pdf.Dict{
			"Type": pdf.Name("TransformParams"),
			"P":    int(level),
			"V":    pdf.Name("1.2"),
		},
		"DigestMethod": pdf.Name("SHA256"),
	}
}

// HasDocMDP reports whether the document's /Perms entry contains a
// DocMDP reference. Surfaces as the `doc_mdp_present` verify gate so
// callers can see the signature is asserting certification semantics.
func HasDocMDP(doc *pdf.Document) bool {
	if doc == nil {
		return false
	}
	perms, ok := doc.ResolveDict(doc.Catalog["Perms"])
	if !ok {
		return false
	}
	_, has := perms["DocMDP"]
	return has
}
