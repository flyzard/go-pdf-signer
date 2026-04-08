package pades

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"

	"github.com/flyzard/pdf-signer/internal/pdf"
)

// VerifyOptions configures the verify step.
type VerifyOptions struct {
	InputPath string
}

// VerifyResult contains the output of the verify step.
type VerifyResult struct {
	Valid             bool                    `json:"valid"`
	Signatures        []SignatureVerification `json:"signatures"`
	DocumentTimestamp string                  `json:"document_timestamp,omitempty"`
	LTVStatus         string                  `json:"ltv_status"`
}

// SignatureVerification holds per-signature verification results.
type SignatureVerification struct {
	Signer                string `json:"signer"`
	NIC                   string `json:"nic,omitempty"`
	SignedAt              string `json:"signed_at"`
	CertificateIssuer     string `json:"certificate_issuer"`
	CertificateThumbprint string `json:"certificate_thumbprint"`
	Level                 string `json:"level"` // "PAdES-LT", "PAdES-B-T", "PAdES-B-B"
	LTVValid              bool   `json:"ltv_valid"`
	TimestampValid        bool   `json:"timestamp_valid"`
}

// Verify opens a PDF and inspects its signatures and DSS dictionary.
func Verify(opts VerifyOptions) (*VerifyResult, error) {
	doc, err := pdf.Open(opts.InputPath)
	if err != nil {
		return nil, fmt.Errorf("open PDF: %w", err)
	}

	_, hasDSS := doc.Catalog["DSS"]
	ltvStatus := "none"
	ltvValidCerts := false
	if hasDSS {
		ltvStatus = "partial" // DSS present at minimum
		dssRef, ok := doc.Catalog.GetRef("DSS")
		if ok {
			dssDict, err := doc.ReadDictObject(dssRef)
			if err == nil {
				_, hasCerts := dssDict["Certs"]
				_, hasOCSPs := dssDict["OCSPs"]
				if hasCerts {
					ltvValidCerts = true
				}
				if hasCerts && hasOCSPs {
					ltvStatus = "valid"
				}
				// else: stays "partial"
			}
		}
	}

	sigContents, err := extractSignatureContents(doc)
	if err != nil {
		return nil, fmt.Errorf("extract signature contents: %w", err)
	}

	result := &VerifyResult{
		LTVStatus: ltvStatus,
	}

	for _, blob := range sigContents {
		sv := SignatureVerification{
			LTVValid: ltvValidCerts,
			Level:    "PAdES-B-B",
		}

		if hasDSS {
			sv.Level = "PAdES-LT"
		}

		certs, err := extractCertsFromCMS(blob)
		if err == nil && len(certs) > 0 {
			leaf := certs[0]
			sv.Signer = leaf.Subject.CommonName
			sv.CertificateIssuer = leaf.Issuer.CommonName
			thumb := sha1.Sum(leaf.Raw)
			sv.CertificateThumbprint = hex.EncodeToString(thumb[:])
		}

		result.Signatures = append(result.Signatures, sv)
	}

	result.Valid = len(result.Signatures) > 0

	return result, nil
}
