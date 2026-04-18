package pades

import (
	"context"
	"crypto/x509"
	"fmt"

	"github.com/flyzard/pdf-signer/internal/pdf"
)

// TSA status values surfaced in JSON output.
const (
	TSAStatusNotImplemented = "not_implemented"
)

// FinalizeOptions configures the finalize step.
type FinalizeOptions struct {
	InputPath  string
	OutputPath string
	TSAUrl     string // Optional — empty = skip timestamp
}

// FinalizeResult contains the output of the finalize step.
type FinalizeResult struct {
	LTVStatus string   `json:"ltv_status"`
	Timestamp string   `json:"timestamp,omitempty"`
	TSAStatus string   `json:"tsa_status,omitempty"`
	Warnings  []string `json:"warnings,omitempty"`
}

// Finalize reads a signed PDF, collects validation data (certificates, OCSP, CRL),
// writes a DSS dictionary as an incremental update, and optionally adds a document
// timestamp.
func Finalize(ctx context.Context, opts FinalizeOptions) (*FinalizeResult, error) {
	doc, err := pdf.Open(opts.InputPath)
	if err != nil {
		return nil, fmt.Errorf("open input PDF: %w", err)
	}

	signerCerts, sigContents, err := extractSignatureData(doc)
	if err != nil {
		return nil, fmt.Errorf("extract signature data: %w", err)
	}

	if len(sigContents) == 0 {
		return nil, fmt.Errorf("no signatures found in PDF")
	}

	dss, err := CollectValidationData(ctx, signerCerts, sigContents)
	if err != nil {
		return nil, fmt.Errorf("collect validation data: %w", err)
	}

	ltvStatus := determineLTVStatus(dss, signerCerts)

	if err := WriteDSS(doc, dss, opts.OutputPath); err != nil {
		return nil, fmt.Errorf("write DSS: %w", err)
	}

	result := &FinalizeResult{
		LTVStatus: ltvStatus,
		Warnings:  dss.Warnings,
	}

	if opts.TSAUrl != "" {
		result.TSAStatus = TSAStatusNotImplemented
		result.Warnings = append(result.Warnings,
			fmt.Sprintf("document timestamp not yet implemented (TSA URL: %s)", opts.TSAUrl))
	}

	return result, nil
}

// extractSignatureData extracts signer certificates and raw /Contents blobs
// from all signatures in the PDF.
func extractSignatureData(doc *pdf.Document) ([]*x509.Certificate, [][]byte, error) {
	// Extract raw signature contents (DER-encoded CMS blobs).
	sigContents, err := extractSignatureContents(doc)
	if err != nil {
		return nil, nil, fmt.Errorf("extract signature contents: %w", err)
	}

	if len(sigContents) == 0 {
		return nil, nil, nil
	}

	// Extract certificates from each CMS blob.
	var signerCerts []*x509.Certificate
	for _, cms := range sigContents {
		certs, err := extractCertsFromCMS(cms)
		if err != nil || len(certs) == 0 {
			// If we can't parse certs from this CMS, add nil as placeholder
			// so indices stay aligned with sigContents.
			signerCerts = append(signerCerts, nil)
			continue
		}
		// The first certificate in the CMS is typically the signer's leaf cert.
		signerCerts = append(signerCerts, certs[0])
	}

	return signerCerts, sigContents, nil
}

// determineLTVStatus returns valid only when every signer chain reached a
// trusted root, some revocation data was collected, and no warning was
// recorded. Any soft failure drops the result to partial.
func determineLTVStatus(dss *DSSData, signerCerts []*x509.Certificate) string {
	if dss == nil {
		return LTVStatusNone
	}

	hasOCSP := len(dss.OCSPs) > 0
	hasCRL := len(dss.CRLs) > 0
	hasChainCerts := len(dss.Certs) > len(signerCerts)

	if dss.ChainsComplete && (hasOCSP || hasCRL) && len(dss.Warnings) == 0 {
		return LTVStatusValid
	}
	if hasOCSP || hasCRL || hasChainCerts {
		return LTVStatusPartial
	}
	return LTVStatusNone
}
