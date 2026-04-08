package pades

import (
	"bytes"
	"crypto/sha1"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"strings"

	pdcrypto "github.com/flyzard/pdf-signer/internal/crypto"
	"github.com/flyzard/pdf-signer/internal/pdf"
)

// DSSData holds all validation data to embed in the PDF's DSS dictionary.
type DSSData struct {
	Certs      [][]byte // DER-encoded certificates
	OCSPs      [][]byte // DER-encoded OCSP responses
	CRLs       [][]byte // DER-encoded CRLs
	VRIEntries []VRIEntry
}

// VRIEntry holds validation-related information for a single signature.
type VRIEntry struct {
	SignatureHash string // SHA-1 hex of signature /Contents (uppercase)
	CertIndices   []int
	OCSPIndices   []int
	CRLIndices    []int
}

// CollectValidationData gathers certificates, OCSP responses, and CRLs
// for all signer certificates. OCSP/CRL failures are non-fatal.
func CollectValidationData(signerCerts []*x509.Certificate, signatureContents [][]byte) (*DSSData, error) {
	dss := &DSSData{}

	for i, leaf := range signerCerts {
		certStartIdx := len(dss.Certs)
		ocspStartIdx := len(dss.OCSPs)
		crlStartIdx := len(dss.CRLs)

		if leaf != nil {
			// 1. Build certificate chain.
			chain, err := pdcrypto.BuildChain(leaf)
			if err != nil {
				dss.Certs = append(dss.Certs, leaf.Raw)
			} else {
				for _, cert := range chain.Certificates {
					dss.Certs = append(dss.Certs, cert.Raw)
				}
			}

			// 2. Fetch OCSP for consecutive certificate pairs in the chain.
			if chain != nil && len(chain.Certificates) >= 2 {
				for j := 0; j < len(chain.Certificates)-1; j++ {
					cert := chain.Certificates[j]
					issuer := chain.Certificates[j+1]
					ocspResult, err := pdcrypto.FetchOCSP(cert, issuer)
					if err == nil && ocspResult != nil {
						dss.OCSPs = append(dss.OCSPs, ocspResult.RawResponse)
					}
				}
			}

			// 3. Fetch CRL for the leaf certificate.
			crlResult, err := pdcrypto.FetchCRL(leaf)
			if err == nil && crlResult != nil {
				dss.CRLs = append(dss.CRLs, crlResult.RawCRL)
			}
		}

		// 4. Build VRI entry (works for both nil and non-nil certs).
		if i < len(signatureContents) && len(signatureContents[i]) > 0 {
			h := sha1.Sum(signatureContents[i])
			dss.VRIEntries = append(dss.VRIEntries, VRIEntry{
				SignatureHash: strings.ToUpper(hex.EncodeToString(h[:])),
				CertIndices:   makeRange(certStartIdx, len(dss.Certs)),
				OCSPIndices:   makeRange(ocspStartIdx, len(dss.OCSPs)),
				CRLIndices:    makeRange(crlStartIdx, len(dss.CRLs)),
			})
		}
	}

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

// makeRange returns a slice [start, start+1, ..., end-1].
func makeRange(start, end int) []int {
	if start >= end {
		return nil
	}
	result := make([]int, end-start)
	for i := range result {
		result[i] = start + i
	}
	return result
}

// extractSignatureContents finds all signature /Contents hex values in the PDF.
// Returns the raw DER bytes of each signature (for VRI key computation).
func extractSignatureContents(doc *pdf.Document) ([][]byte, error) {
	data := doc.Data

	var results [][]byte

	// Search for /Contents <hex> patterns where hex is NOT all zeros.
	// We scan the raw bytes for the pattern.
	needle := []byte("/Contents <")
	searchFrom := 0

	for searchFrom < len(data) {
		idx := bytes.Index(data[searchFrom:], needle)
		if idx < 0 {
			break
		}
		idx += searchFrom

		// Find the '<' after /Contents
		hexStart := idx + len("/Contents ")
		if hexStart >= len(data) || data[hexStart] != '<' {
			searchFrom = idx + 1
			continue
		}
		hexStart++ // skip '<'

		// Find the closing '>'
		hexEnd := hexStart
		for hexEnd < len(data) && data[hexEnd] != '>' {
			hexEnd++
		}
		if hexEnd >= len(data) {
			break
		}

		hexStr := string(data[hexStart:hexEnd])

		// Skip if all zeros (unfilled placeholder).
		if isAllZeros(hexStr) {
			searchFrom = hexEnd + 1
			continue
		}

		// Hex decode the contents.
		// Remove any whitespace from hex string.
		hexStr = strings.ReplaceAll(hexStr, " ", "")
		hexStr = strings.ReplaceAll(hexStr, "\n", "")
		hexStr = strings.ReplaceAll(hexStr, "\r", "")

		// Decode hex and strip trailing zero bytes (padding from EmbedCMS).
		decoded, err := hex.DecodeString(hexStr)
		if err != nil {
			searchFrom = hexEnd + 1
			continue
		}
		for len(decoded) > 0 && decoded[len(decoded)-1] == 0 {
			decoded = decoded[:len(decoded)-1]
		}

		if len(decoded) > 0 {
			results = append(results, decoded)
		}

		searchFrom = hexEnd + 1
	}

	return results, nil
}

// extractCertsFromCMS does minimal ASN.1 parsing to extract certificates
// from a CMS SignedData structure without needing a full PKCS#7 library.
//
// CMS SignedData structure (RFC 5652):
//
//	ContentInfo ::= SEQUENCE {
//	  contentType OID,
//	  content [0] EXPLICIT ANY
//	}
//
//	SignedData ::= SEQUENCE {
//	  version INTEGER,
//	  digestAlgorithms SET,
//	  encapContentInfo SEQUENCE,
//	  certificates [0] IMPLICIT SET OF Certificate  <-- we want these
//	  ...
//	}
func extractCertsFromCMS(cmsData []byte) ([]*x509.Certificate, error) {
	// Parse the outer ContentInfo SEQUENCE.
	var contentInfo struct {
		ContentType asn1.ObjectIdentifier
		Content     asn1.RawValue `asn1:"explicit,tag:0"`
	}
	_, err := asn1.Unmarshal(cmsData, &contentInfo)
	if err != nil {
		return nil, fmt.Errorf("unmarshal ContentInfo: %w", err)
	}

	// Parse the inner SignedData SEQUENCE.
	// We need to manually walk it because the certificates field is optional
	// and uses implicit tagging.
	var inner asn1.RawValue
	rest, err := asn1.Unmarshal(contentInfo.Content.Bytes, &inner)
	if err != nil {
		return nil, fmt.Errorf("unmarshal SignedData outer: %w", err)
	}
	_ = rest

	// inner.Bytes contains the SignedData SEQUENCE contents.
	// Walk through: version (INTEGER), digestAlgorithms (SET), encapContentInfo (SEQUENCE),
	// then look for [0] IMPLICIT (tag 0xa0) for certificates.
	remaining := inner.Bytes

	// Skip version (INTEGER).
	var version asn1.RawValue
	remaining, err = asn1.Unmarshal(remaining, &version)
	if err != nil {
		return nil, fmt.Errorf("skip version: %w", err)
	}

	// Skip digestAlgorithms (SET).
	var digestAlgs asn1.RawValue
	remaining, err = asn1.Unmarshal(remaining, &digestAlgs)
	if err != nil {
		return nil, fmt.Errorf("skip digestAlgorithms: %w", err)
	}

	// Skip encapContentInfo (SEQUENCE).
	var encapContent asn1.RawValue
	remaining, err = asn1.Unmarshal(remaining, &encapContent)
	if err != nil {
		return nil, fmt.Errorf("skip encapContentInfo: %w", err)
	}

	// Now look for the optional [0] IMPLICIT certificates field.
	// Its tag byte is 0xa0 (context class, constructed, tag 0).
	if len(remaining) == 0 {
		return nil, nil // No certificates field.
	}

	var certsRaw asn1.RawValue
	remaining, err = asn1.Unmarshal(remaining, &certsRaw)
	if err != nil {
		return nil, fmt.Errorf("unmarshal certificates field: %w", err)
	}

	// Check if this is the certificates [0] field (tag 0, class context-specific).
	if certsRaw.Tag != 0 || certsRaw.Class != asn1.ClassContextSpecific {
		// Not the certificates field — might be something else.
		return nil, nil
	}

	// Parse individual certificates from the SET contents.
	var certs []*x509.Certificate
	certBytes := certsRaw.Bytes
	for len(certBytes) > 0 {
		var raw asn1.RawValue
		certBytes, err = asn1.Unmarshal(certBytes, &raw)
		if err != nil {
			break
		}
		cert, err := x509.ParseCertificate(raw.FullBytes)
		if err != nil {
			continue // Skip unparseable certificates.
		}
		certs = append(certs, cert)
	}

	return certs, nil
}

// isAllZeros returns true if s contains only '0' characters.
func isAllZeros(s string) bool {
	for _, c := range s {
		if c != '0' {
			return false
		}
	}
	return true
}
