package pades

import (
	"bytes"
	"crypto/sha1"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/flyzard/pdf-signer/internal/certs"
	pdcrypto "github.com/flyzard/pdf-signer/internal/crypto"
	"github.com/flyzard/pdf-signer/internal/pdf"
)

// LTV status values surfaced in JSON output.
const (
	LTVStatusNone    = "none"
	LTVStatusPartial = "partial"
	LTVStatusValid   = "valid"
)

// PAdES signature levels surfaced in JSON output.
const (
	LevelPAdESBB = "PAdES-B-B"
	LevelPAdESBT = "PAdES-B-T"
	LevelPAdESLT = "PAdES-LT"
)

// VerifyOptions configures the verify step.
type VerifyOptions struct {
	InputPath string
}

// VerifyResult contains the output of the verify step.
type VerifyResult struct {
	HasSignatures     bool                    `json:"has_signatures"`
	Signatures        []SignatureVerification `json:"signatures"`
	DocumentTimestamp string                  `json:"document_timestamp,omitempty"`
	LTVStatus         string                  `json:"ltv_status"`
	// DocMDPPresent reports whether the document's catalog /Perms /DocMDP
	// points at a certification signature (ISO 32000-1 §12.8.2.2). Does
	// not classify subsequent-update conformance — that requires a deeper
	// incremental-update walk which is a follow-up.
	DocMDPPresent bool `json:"doc_mdp_present"`
}

// SignatureVerification holds per-signature verification results. The
// cryptographic gates are separate booleans so callers can tell exactly
// which check failed: a signed PDF with a valid CMS over the wrong byte
// range will surface as ByteRangeValid=false while SignatureValid is true.
type SignatureVerification struct {
	Signer                string `json:"signer"`
	NIC                   string `json:"nic,omitempty"`
	SignedAt              string `json:"signed_at"`
	CertificateIssuer     string `json:"certificate_issuer"`
	CertificateThumbprint string `json:"certificate_thumbprint_sha1"`
	Level                 string `json:"level"`
	LTVValid              bool   `json:"ltv_valid"`
	TimestampValid        bool   `json:"timestamp_valid"`

	ByteRangeValid       bool `json:"byte_range_valid"`
	HashMatch            bool `json:"hash_match"`
	SignatureValid       bool `json:"signature_valid"`
	CertValid            bool `json:"cert_valid"`
	ESSBindingValid      bool `json:"ess_v2_binding_valid"`
	HashAlgConsistencyOK bool `json:"hash_alg_consistency_valid"`
	CertPolicyValid      bool `json:"cert_policy_valid"`
	ChainToRootValid     bool `json:"chain_to_root_valid"`

	// ETSI qualified-signature indicators (empty/false when the cert does
	// not assert any qcStatement — common for test certs).
	Qualified    bool   `json:"qualified,omitempty"`
	QSCD         bool   `json:"qscd,omitempty"`
	ProfileType  string `json:"profile_type,omitempty"` // "esign" | "eseal" | "eweb" | ""

	VerifyError string `json:"verify_error,omitempty"`
}

// Verify opens a PDF and runs cryptographic verification on every signature
// it finds: CMS signature over signedAttrs, messageDigest against the byte
// range hash, byte range covers the whole file, and signer cert validity
// window. DSS/VRI presence controls the Level/LTV fields.
func Verify(opts VerifyOptions) (*VerifyResult, error) {
	doc, err := pdf.Open(opts.InputPath)
	if err != nil {
		return nil, fmt.Errorf("open PDF: %w", err)
	}

	dssDict, err := resolveDSS(doc)
	if err != nil {
		return nil, fmt.Errorf("resolve DSS: %w", err)
	}
	ltvStatus := LTVStatusNone
	vriEntries := map[string]pdf.Dict{}
	if dssDict != nil {
		ltvStatus = LTVStatusPartial
		_, hasCerts := dssDict["Certs"]
		_, hasOCSPs := dssDict["OCSPs"]
		if hasCerts && hasOCSPs {
			ltvStatus = LTVStatusValid
		}
		if vri, ok := doc.ResolveDict(dssDict["VRI"]); ok {
			for k, v := range vri {
				inner, ok := doc.ResolveDict(v)
				if ok {
					vriEntries[strings.ToUpper(k)] = inner
				}
			}
		}
	}

	bundles, err := extractSignatureBundles(doc)
	if err != nil {
		return nil, fmt.Errorf("extract signature bundles: %w", err)
	}

	result := &VerifyResult{
		LTVStatus:     ltvStatus,
		Signatures:    []SignatureVerification{},
		DocMDPPresent: HasDocMDP(doc),
	}
	for _, b := range bundles {
		sv := verifyOneSignature(doc.Data, b, vriEntries, dssDict != nil)
		result.Signatures = append(result.Signatures, sv)
	}
	result.HasSignatures = len(result.Signatures) > 0
	return result, nil
}

// verifyOneSignature runs every verification step against a single signature
// bundle and returns a populated SignatureVerification. The first failure is
// recorded in VerifyError; subsequent booleans remain false.
func verifyOneSignature(data []byte, b signatureBundle, vriEntries map[string]pdf.Dict, hasDSS bool) SignatureVerification {
	sv := SignatureVerification{Level: LevelPAdESBB}

	// VRI-based level / LTV hint (independent of crypto checks).
	blobSHA1 := sha1.Sum(b.Contents)
	thumbForVRI := strings.ToUpper(hex.EncodeToString(blobSHA1[:]))
	if entry, ok := vriEntries[thumbForVRI]; ok {
		sv.Level = LevelPAdESLT
		if _, has := entry["Cert"]; has {
			sv.LTVValid = true
		}
	} else if hasDSS {
		sv.Level = LevelPAdESLT
	}

	if b.ByteRangeErr != nil {
		return verifyFail(sv, "byte range", b.ByteRangeErr)
	}
	if err := validateByteRangeCoversEntireFile(b.ByteRange, int64(len(data))); err != nil {
		return verifyFail(sv, "byte range", err)
	}
	sv.ByteRangeValid = true

	parsed, err := parseCMS(b.Contents)
	if err != nil {
		return verifyFail(sv, "cms", err)
	}
	if len(parsed.SignerInfos) == 0 {
		return verifyFail(sv, "cms", errors.New("no signerInfos"))
	}
	si := parsed.SignerInfos[0]

	// Populate identity fields up front — useful even when verification fails.
	signer, sigErr := si.findSignerCert(parsed.Certificates)
	if signer != nil {
		sv.Signer = subjectDisplay(signer.Subject.CommonName, signer.Subject.String())
		sv.CertificateIssuer = subjectDisplay(signer.Issuer.CommonName, signer.Issuer.String())
		thumb := sha1.Sum(signer.Raw)
		sv.CertificateThumbprint = hex.EncodeToString(thumb[:])
		now := time.Now()
		if !now.Before(signer.NotBefore) && !now.After(signer.NotAfter) {
			sv.CertValid = true
		}
		// Surface ETSI QC indicators regardless of whether the signature
		// itself verifies; verifier consumers (UI, audit log) want to show
		// these even on failure so the reader understands *what* was being
		// claimed.
		if id, err := certs.ExtractIdentity(signer); err == nil {
			sv.Qualified = id.QCProfile.Qualified
			sv.QSCD = id.QCProfile.QSCD
			sv.ProfileType = id.QCProfile.Type
		}
		// Cert-policy gate. A reject does NOT abort verify — the cryptographic
		// check can still pass — but we flag it so the caller can see the
		// signature was produced by a cert outside the accepted profile.
		if err := pdcrypto.ValidateSignerCert(signer); err == nil {
			sv.CertPolicyValid = true
		}
	}

	expectedDigest, err := si.MessageDigest()
	if err != nil {
		return verifyFail(sv, "messageDigest", err)
	}
	computed, err := hashPDFRanges(si, data, b.ByteRange)
	if err != nil {
		return verifyFail(sv, "hash byte range", err)
	}
	if !bytes.Equal(computed, expectedDigest) {
		return verifyFail(sv, "messageDigest", errors.New("does not match byte-range hash"))
	}
	sv.HashMatch = true

	// contentType signed attribute must equal id-data (RFC 5652 § 11.1).
	ct, err := si.ContentType()
	if err != nil {
		return verifyFail(sv, "contentType", err)
	}
	if !ct.Equal(oidContentTypeData) {
		return verifyFail(sv, "contentType", fmt.Errorf("is %v, want id-data", ct))
	}

	if sigErr != nil {
		return verifyFail(sv, "signer cert", sigErr)
	}
	if err := si.verifySignature(signer); err != nil {
		return verifyFail(sv, "signature", err)
	}
	sv.SignatureValid = true

	// ESS binding check — must match the signer cert. A missing attribute
	// is reported via the bool rather than a hard error because some
	// legacy emitters omit signingCertificateV2 entirely; mandatory-presence
	// is a follow-up policy decision, not a structural gate.
	if err := ValidateESSBinding(si, signer); err == nil {
		sv.ESSBindingValid = true
	} else if sv.VerifyError == "" {
		sv.VerifyError = "ess binding: " + err.Error()
	}
	if err := HashAlgConsistency(parsed, si); err == nil {
		sv.HashAlgConsistencyOK = true
	} else if sv.VerifyError == "" {
		sv.VerifyError = "hash alg consistency: " + err.Error()
	}

	// Chain-to-root check: CMS-embedded certs as intermediates,
	// SignerRoots() as anchors, and the signing time from the signingTime
	// signed attribute (falling back to "now" when absent).
	signingTime := signerSigningTime(si)
	if verifyChainToRoot(signer, parsed.Certificates, signingTime) {
		sv.ChainToRootValid = true
	}

	return sv
}

// signerSigningTime returns the time carried in the signingTime signed
// attribute, or time.Now() when the attribute is absent. A signature
// timestamp is a stronger anchor but verify does not yet cross-check it.
func signerSigningTime(si *cmsSignerInfo) time.Time {
	a := si.findAttr(oidAttrSigningTime)
	if a == nil || len(a.Values) == 0 {
		return time.Now()
	}
	var t time.Time
	if _, err := asn1.Unmarshal(a.Values[0].FullBytes, &t); err != nil {
		return time.Now()
	}
	return t
}

// verifyChainToRoot runs x509.Verify against SignerRoots() using the CMS-
// embedded certs as intermediates. Returns true only when a full path to a
// trusted root exists at checkTime. DSS-only intermediates aren't pulled
// in yet — most emitters ship the full chain inside CMS so this catches
// the happy path.
func verifyChainToRoot(leaf *x509.Certificate, cmsCerts []*x509.Certificate, checkTime time.Time) bool {
	if leaf == nil {
		return false
	}
	intermediates := x509.NewCertPool()
	for _, c := range cmsCerts {
		if c != nil && !c.Equal(leaf) {
			intermediates.AddCert(c)
		}
	}
	_, err := leaf.Verify(x509.VerifyOptions{
		Roots:         certs.SignerRoots(),
		Intermediates: intermediates,
		CurrentTime:   checkTime,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	return err == nil
}


// verifyFail records stage+err into VerifyError and returns sv. Centralising
// this keeps the hot verify loop readable and stops a future editor from
// forgetting to bail out early (e.g. by accidentally flipping a bool after
// the error is set).
func verifyFail(sv SignatureVerification, stage string, err error) SignatureVerification {
	sv.VerifyError = stage + ": " + err.Error()
	return sv
}

// subjectDisplay falls back to the full DN when CommonName is empty.
func subjectDisplay(cn, fullDN string) string {
	if cn != "" {
		return cn
	}
	return fullDN
}

// hashPDFRanges streams data's byte range into the CMS-declared digest hash.
func hashPDFRanges(si *cmsSignerInfo, data []byte, br pdf.ByteRange) ([]byte, error) {
	hfunc, err := si.digestHash()
	if err != nil {
		return nil, err
	}
	h := hfunc.New()
	h.Write(data[:br.Length1])
	h.Write(data[br.Offset2 : br.Offset2+br.Length2])
	return h.Sum(nil), nil
}

// resolveDSS returns the DSS dict (resolving Ref) or (nil, nil) if absent.
// Returns an error only when /DSS is present but cannot be resolved (corrupt).
func resolveDSS(doc *pdf.Document) (pdf.Dict, error) {
	v, ok := doc.Catalog["DSS"]
	if !ok {
		return nil, nil
	}
	d, ok := doc.ResolveDict(v)
	if !ok {
		return nil, fmt.Errorf("/DSS in catalog is not a resolvable dict (got %T)", v)
	}
	return d, nil
}
