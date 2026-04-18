package pades

import (
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"

	pdcrypto "github.com/flyzard/pdf-signer/internal/crypto"
	"github.com/flyzard/pdf-signer/internal/pdf"
)

// DSSData holds all validation data to embed in the PDF's DSS dictionary.
type DSSData struct {
	Certs          [][]byte // DER-encoded certificates
	OCSPs          [][]byte // DER-encoded OCSP responses
	CRLs           [][]byte // DER-encoded CRLs
	VRIEntries     []VRIEntry
	Warnings       []string // human-readable notes about partial / stale validation data
	ChainsComplete bool     // true only when every signer chain reached a trusted root
}

// VRIEntry holds validation-related information for a single signature.
type VRIEntry struct {
	SignatureHash string // SHA-1 hex of signature /Contents (uppercase)
	CertIndices   []int
	OCSPIndices   []int
	CRLIndices    []int
}

// fetchRevocationData fetches OCSP responses for every consecutive cert pair
// in chain and the leaf's CRL, in parallel. OCSP responses are returned in
// chain-pair order with nil entries dropped; per-fetch failures return as
// warnings so finalize can surface them. len(chain) < 2 is safe — the
// function refuses early with a warning.
func fetchRevocationData(ctx context.Context, leaf *x509.Certificate, chain []*x509.Certificate) ([][]byte, []byte, []string) {
	if len(chain) < 2 {
		return nil, nil, []string{fmt.Sprintf("chain for %q has <2 certs — no OCSP/CRL fetched", certLabel(leaf))}
	}

	ocspResults := make([][]byte, len(chain)-1)
	ocspErrs := make([]error, len(chain)-1)
	var crl []byte
	var crlErr error
	var wg sync.WaitGroup

	for j := range len(chain) - 1 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, err := pdcrypto.FetchOCSP(ctx, chain[j], chain[j+1])
			if err != nil {
				ocspErrs[j] = err
				return
			}
			if res != nil {
				ocspResults[j] = res.RawResponse
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		crlRes, err := pdcrypto.FetchCRL(ctx, leaf, chain[1])
		if err != nil {
			crlErr = err
			return
		}
		if crlRes != nil {
			crl = crlRes.RawCRL
		}
	}()
	wg.Wait()

	var ocsps [][]byte
	for _, raw := range ocspResults {
		if raw != nil {
			ocsps = append(ocsps, raw)
		}
	}

	var warns []string
	for j, err := range ocspErrs {
		if err != nil {
			warns = append(warns, fmt.Sprintf("OCSP for %q/%q: %v", certLabel(chain[j]), certLabel(chain[j+1]), err))
		}
	}
	if crlErr != nil {
		warns = append(warns, fmt.Sprintf("CRL for %q: %v", certLabel(leaf), crlErr))
	}
	return ocsps, crl, warns
}

// certLabel returns a short human-readable name for a cert, falling back to
// the serial number if CommonName is empty.
func certLabel(c *x509.Certificate) string {
	if c == nil {
		return "<nil>"
	}
	if c.Subject.CommonName != "" {
		return c.Subject.CommonName
	}
	if c.SerialNumber != nil {
		return "serial=" + c.SerialNumber.String()
	}
	return "<unnamed>"
}

// dedupAppender returns a closure that appends raw to *items if its SHA-256
// fingerprint hasn't been seen before, and returns the slice index of the
// (possibly already-present) entry.
func dedupAppender(index map[[32]byte]int, items *[][]byte) func([]byte) int {
	return func(raw []byte) int {
		fp := sha256.Sum256(raw)
		if i, ok := index[fp]; ok {
			return i
		}
		i := len(*items)
		index[fp] = i
		*items = append(*items, raw)
		return i
	}
}

// AddTSACerts folds TSA signer cert and intermediates into an existing
// DSSData. Bytes deduplicate against what's already in dss.Certs. OCSP/CRL
// for TSA certs is a future revocation-hardening step; the TSA cert chain
// being present is sufficient for Adobe's LTV check and for EU DSS to
// follow the chain historically.
//
// sigHash is the uppercase SHA-1 hex of the approval signature's /Contents
// whose TSA certs we're adding. When non-empty, the TSA cert indices are
// appended to the matching VRIEntry so per-signature validation data
// stays cleanly partitioned per ISO 32000-2 §12.8.4.3.
func AddTSACerts(dss *DSSData, tsaCerts []*x509.Certificate, sigHash string) {
	if dss == nil || len(tsaCerts) == 0 {
		return
	}
	// Rebuild the dedup index for dss.Certs so new additions cross-check
	// against previously added signer-chain certs.
	certIndex := make(map[[32]byte]int, len(dss.Certs))
	for i, raw := range dss.Certs {
		certIndex[sha256.Sum256(raw)] = i
	}
	addCert := dedupAppender(certIndex, &dss.Certs)

	var tsaCertIdx []int
	for _, c := range tsaCerts {
		if c == nil {
			continue
		}
		tsaCertIdx = append(tsaCertIdx, addCert(c.Raw))
	}
	if sigHash == "" || len(tsaCertIdx) == 0 {
		return
	}
	for i := range dss.VRIEntries {
		if dss.VRIEntries[i].SignatureHash == sigHash {
			dss.VRIEntries[i].CertIndices = append(dss.VRIEntries[i].CertIndices, tsaCertIdx...)
			return
		}
	}
}

// CollectValidationData gathers certificates, OCSP responses, and CRLs for
// all signer certificates. Bytes are deduplicated across signers (same cert
// in two chains is embedded once). OCSP/CRL failures are non-fatal.
func CollectValidationData(ctx context.Context, signerCerts []*x509.Certificate, signatureContents [][]byte) (*DSSData, error) {
	dss := &DSSData{}

	certIndex, ocspIndex, crlIndex := map[[32]byte]int{}, map[[32]byte]int{}, map[[32]byte]int{}
	addCert := dedupAppender(certIndex, &dss.Certs)
	addOCSP := dedupAppender(ocspIndex, &dss.OCSPs)
	addCRL := dedupAppender(crlIndex, &dss.CRLs)

	now := time.Now()
	allChainsComplete := len(signerCerts) > 0
	for i, leaf := range signerCerts {
		var sigCertIdx, sigOCSPIdx, sigCRLIdx []int

		if leaf == nil {
			allChainsComplete = false
		} else {
			// Warn on a leaf cert that is outside its validity window at
			// finalize time. We don't fail — with a TSA anchor the signature
			// may still be cryptographically sound, and without TSA the best
			// we can do is flag it. (The fully-strict path belongs with the
			// future TSA implementation.)
			if leaf.NotAfter.Before(now) {
				dss.Warnings = append(dss.Warnings,
					fmt.Sprintf("signer %q expired at %s", leaf.Subject.CommonName, leaf.NotAfter.Format(time.RFC3339)))
			}
			if leaf.NotBefore.After(now) {
				dss.Warnings = append(dss.Warnings,
					fmt.Sprintf("signer %q not yet valid (NotBefore=%s)", leaf.Subject.CommonName, leaf.NotBefore.Format(time.RFC3339)))
			}

			chain, chainErr := pdcrypto.BuildChain(ctx, leaf)
			if chainErr != nil {
				dss.Warnings = append(dss.Warnings,
					fmt.Sprintf("chain build for %q: %v", certLabel(leaf), chainErr))
			}
			if chain == nil {
				allChainsComplete = false
				sigCertIdx = append(sigCertIdx, addCert(leaf.Raw))
			} else {
				if !chain.IsComplete {
					allChainsComplete = false
					dss.Warnings = append(dss.Warnings,
						fmt.Sprintf("chain for %q incomplete — no trusted root reached", certLabel(leaf)))
				}
				for _, cert := range chain.Certificates {
					sigCertIdx = append(sigCertIdx, addCert(cert.Raw))
				}
				if len(chain.Certificates) >= 2 {
					ocspBlobs, crlBlob, fetchWarns := fetchRevocationData(ctx, leaf, chain.Certificates)
					dss.Warnings = append(dss.Warnings, fetchWarns...)
					for _, raw := range ocspBlobs {
						sigOCSPIdx = append(sigOCSPIdx, addOCSP(raw))
					}
					if crlBlob != nil {
						sigCRLIdx = append(sigCRLIdx, addCRL(crlBlob))
					}
				}
			}
		}

		if i < len(signatureContents) && len(signatureContents[i]) > 0 {
			h := sha1.Sum(signatureContents[i])
			dss.VRIEntries = append(dss.VRIEntries, VRIEntry{
				SignatureHash: strings.ToUpper(hex.EncodeToString(h[:])),
				CertIndices:   sigCertIdx,
				OCSPIndices:   sigOCSPIdx,
				CRLIndices:    sigCRLIdx,
			})
		}
	}

	dss.ChainsComplete = allChainsComplete
	return dss, nil
}

// WriteDSS writes the DSS dictionary as an incremental update to the PDF.
func WriteDSS(doc *pdf.Document, dss *DSSData, outputPath string) error {
	w := pdf.NewWriter(doc)

	// 1. Add each cert, OCSP, CRL as a stream object.
	certRefs := make([]pdf.Ref, len(dss.Certs))
	for i, cert := range dss.Certs {
		certRefs[i] = w.AddStream(cert, pdf.Dict{})
	}

	ocspRefs := make([]pdf.Ref, len(dss.OCSPs))
	for i, ocspData := range dss.OCSPs {
		ocspRefs[i] = w.AddStream(ocspData, pdf.Dict{})
	}

	crlRefs := make([]pdf.Ref, len(dss.CRLs))
	for i, crlData := range dss.CRLs {
		crlRefs[i] = w.AddStream(crlData, pdf.Dict{})
	}

	// 2. Build /VRI dictionary.
	vriDict := pdf.Dict{}
	for _, entry := range dss.VRIEntries {
		innerDict := pdf.Dict{}

		if len(entry.CertIndices) > 0 {
			innerDict["Cert"] = indexRefsToAny(certRefs, entry.CertIndices)
		}
		if len(entry.OCSPIndices) > 0 {
			innerDict["OCSP"] = indexRefsToAny(ocspRefs, entry.OCSPIndices)
		}
		if len(entry.CRLIndices) > 0 {
			innerDict["CRL"] = indexRefsToAny(crlRefs, entry.CRLIndices)
		}

		vriDict[entry.SignatureHash] = innerDict
	}

	// 3. Build /DSS dictionary.
	dssDict := pdf.Dict{
		"Type": pdf.Name("DSS"),
	}

	if len(certRefs) > 0 {
		dssDict["Certs"] = refsToAny(certRefs)
	}
	if len(ocspRefs) > 0 {
		dssDict["OCSPs"] = refsToAny(ocspRefs)
	}
	if len(crlRefs) > 0 {
		dssDict["CRLs"] = refsToAny(crlRefs)
	}

	if len(vriDict) > 0 {
		dssDict["VRI"] = vriDict
	}

	// 4. Add DSS as an object and update catalog.
	dssRef := w.AddObject(dssDict)

	w.UpdateCatalog(func(cat pdf.Dict) pdf.Dict {
		cat["DSS"] = dssRef
		return cat
	})

	// 5. Write to output.
	return w.WriteTo(outputPath)
}

// refsToAny converts a slice of Refs to []any for PDF serialization.
func refsToAny(refs []pdf.Ref) []any {
	arr := make([]any, len(refs))
	for i, r := range refs {
		arr[i] = r
	}
	return arr
}

// indexRefsToAny selects refs at the given indices and returns them as []any.
func indexRefsToAny(refs []pdf.Ref, indices []int) []any {
	out := make([]any, len(indices))
	for i, idx := range indices {
		out[i] = refs[idx]
	}
	return out
}

// extractSignatureContents walks the catalog's AcroForm /Fields tree and
// returns the raw DER bytes of every signature dictionary's /Contents. The
// trailing zero padding from EmbedCMS is trimmed via the outer ASN.1 length
// so real CMS payloads that end in 0x00 are preserved.
func extractSignatureContents(doc *pdf.Document) ([][]byte, error) {
	acro, ok := doc.ResolveDict(doc.Catalog["AcroForm"])
	if !ok {
		return nil, nil
	}
	fields, ok := acro.GetArray("Fields")
	if !ok {
		return nil, nil
	}

	var out [][]byte
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
		if len(raw) > 0 {
			out = append(out, raw)
		}
	})
	return out, nil
}

// maxFieldTreeDepth bounds AcroForm /Kids recursion depth.
// maxFieldTreeNodes bounds the total number of unique field dicts visited.
// Both exist so a crafted PDF can't force unbounded work via a wide or deep
// /Kids tree.
const (
	maxFieldTreeDepth = 32
	maxFieldTreeNodes = 10_000
)

// walkFieldTree visits every leaf field dict reachable from the given /Fields
// or /Kids array, calling visit on each. Accepts both indirect (pdf.Ref) and
// inline (pdf.Dict) entries — the PDF spec allows either form in /Fields and
// /Kids, and some producers use inline dicts for small form trees. Guarded
// against cycles, depth blowup, and wide-tree blowup.
func walkFieldTree(doc *pdf.Document, fields []any, visit func(pdf.Dict)) {
	seen := make(map[pdf.Ref]bool)
	nodesVisited := 0
	var walk func([]any, int)
	walk = func(fields []any, depth int) {
		if depth > maxFieldTreeDepth {
			return
		}
		for _, f := range fields {
			if nodesVisited >= maxFieldTreeNodes {
				return
			}
			nodesVisited++
			var fd pdf.Dict
			switch v := f.(type) {
			case pdf.Ref:
				if seen[v] {
					continue
				}
				seen[v] = true
				d, err := doc.ReadDictObject(v)
				if err != nil {
					continue
				}
				fd = d
			case pdf.Dict:
				fd = v
			default:
				continue
			}
			if kids, ok := fd.GetArray("Kids"); ok {
				walk(kids, depth+1)
				continue
			}
			visit(fd)
		}
	}
	walk(fields, 0)
}

// sigContentsBytes extracts the raw bytes of /Contents from a sig dict.
// The PDF parser stores hex-string values as []byte already.
func sigContentsBytes(sig pdf.Dict) ([]byte, bool) {
	v, ok := sig["Contents"]
	if !ok {
		return nil, false
	}
	switch t := v.(type) {
	case []byte:
		return t, true
	case string:
		return []byte(t), true
	}
	return nil, false
}

// extractCertsFromCMS returns the certificates embedded in a CMS SignedData
// blob. Thin wrapper around parseCMS so the callers that only need certs
// don't carry around the full parsedCMS struct.
func extractCertsFromCMS(cmsData []byte) ([]*x509.Certificate, error) {
	p, err := parseCMS(cmsData)
	if err != nil {
		return nil, err
	}
	return p.Certificates, nil
}

// trimToASN1Length returns the prefix of buf covering exactly the outer
// ASN.1 TLV (header + content), discarding any trailing padding (typically
// the zero bytes EmbedCMS appends after the real CMS DER).
func trimToASN1Length(buf []byte) ([]byte, error) {
	var raw asn1.RawValue
	if _, err := asn1.Unmarshal(buf, &raw); err != nil {
		return nil, err
	}
	return raw.FullBytes, nil
}
