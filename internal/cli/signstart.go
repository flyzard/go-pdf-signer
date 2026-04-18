package cli

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/flyzard/pdf-signer/internal/appearance"
	"github.com/flyzard/pdf-signer/internal/certs"
	pdcrypto "github.com/flyzard/pdf-signer/internal/crypto"
	"github.com/flyzard/pdf-signer/internal/pades"
	"github.com/flyzard/pdf-signer/internal/pdf"
)

// RunSignStart implements the sign-start subcommand per R-8.4.1: parses
// the signer cert, prepares the PDF (placeholder + visual stamp), builds
// the CMS signedAttributes, and writes the state token. Emits the digest
// the external signer consumes plus a state-token handle.
func RunSignStart(args []string) {
	fs := flag.NewFlagSet("sign-start", flag.ContinueOnError)

	input := fs.String("input", "", "Input PDF file path (required)")
	signerCertPath := fs.String("signer-cert", "", "Path to signer certificate (DER or PEM) (required)")
	signingMethod := fs.String("signing-method", "cmd", "Signing method: cmd or cc")
	padesLevel := fs.String("pades-level", "B-LT", "PAdES level: B-B | B-T | B-LT | B-LTA")
	nameOverride := fs.String("signer-name-override", "", "Override the cert-derived signer name on the stamp (optional)")
	nicOverride := fs.String("signer-nic-override", "", "Override the cert-derived NIC on the stamp (optional)")
	stateOut := fs.String("state-out", "", "Path to write the state token (required)")
	digestAlg := fs.String("digest-algorithm", "SHA-256", "Digest algorithm: SHA-256 | SHA-384 | SHA-512")
	sigAlg := fs.String("signature-algorithm", pades.SigAlgStrRSAPKCS1v15,
		"Signature algorithm: RSA-PKCS1-v1_5 | RSA-PSS | ECDSA | Ed25519")
	placeholderSize := fs.Int("placeholder-size", 0, "Signature /Contents placeholder capacity in bytes (default: 16384)")
	tsaURL := fs.String("tsa-url", "", "RFC 3161 TSA URL (used by sign-finish when pades-level >= B-T)")
	stateTTL := fs.Duration("state-ttl", 0, "State token TTL (default: 24h)")
	sigPos := fs.String("signature-position", "", "Signature position: page,x,y,w,h (default: auto)")
	maxInputSize := fs.Int64("max-input-size", 0, "Maximum --input PDF size in bytes (0 = default 500MB)")
	reasonFlag := fs.String("reason", "", "Override /Reason on the signature dict (default: Portuguese atas)")
	locationFlag := fs.String("location", "", "Override /Location on the signature dict (default: Portugal)")
	nameFlag := fs.String("name", "", "Override /Name on the signature dict (default: cert CN)")
	invisibleFlag := fs.Bool("invisible", false, "Skip the visible stamp; emit /Rect [0 0 0 0]")
	certLevelFlag := fs.String("certification-level", "none",
		"DocMDP certification: none | no-changes | form-fill | annotations. First signature only.")
	sigPolicyOID := fs.String("signature-policy-oid", "",
		"Signature policy OID to embed in signedAttributes (e.g. 2.16.620.2.1.2.2.1 for AMA CMD)")
	commitmentTypeOID := fs.String("commitment-type-oid", "",
		"Commitment type OID (e.g. 1.2.840.113549.1.9.16.6.5 for proof-of-approval)")

	if err := fs.Parse(args); err != nil {
		Fatalf("INVALID_ARGS", "failed to parse arguments: %v", err)
	}
	if *input == "" {
		Fatalf("INVALID_ARGS", "missing required flag: --input")
	}
	if *maxInputSize > 0 {
		if err := pdf.SetMaxInputSize(*maxInputSize); err != nil {
			Fatalf("INVALID_ARGS", "%v", err)
		}
	}
	certLevel, err := parseCertificationLevel(*certLevelFlag)
	if err != nil {
		Fatalf("INVALID_ARGS", "%v", err)
	}
	if *signerCertPath == "" {
		Fatalf("INVALID_ARGS", "missing required flag: --signer-cert")
	}
	if *stateOut == "" {
		Fatalf("INVALID_ARGS", "missing required flag: --state-out")
	}

	cert, err := loadSignerCert(*signerCertPath)
	if err != nil {
		Fatalf("CERT_PARSE_FAILED", "load signer cert: %v", err)
	}
	if cert.Subject.CommonName == "" {
		Fatalf("CERT_CN_EMPTY", "signer certificate has empty CommonName")
	}
	if err := pdcrypto.ValidateSignerCert(cert); err != nil {
		var pe *pdcrypto.CertPolicyError
		if errors.As(err, &pe) {
			Fatalf(pe.Code, "%s", pe.Msg)
		}
		Fatalf("CERT_INVALID", "signer cert: %v", err)
	}
	identity, err := certs.ExtractIdentity(cert)
	if err != nil {
		Fatalf("CERT_PARSE_FAILED", "extract identity: %v", err)
	}

	hashAlg, err := parseDigestAlgorithm(*digestAlg)
	if err != nil {
		Fatalf("INVALID_ARGS", "%v", err)
	}
	if err := validateSignatureAlgorithm(*sigAlg); err != nil {
		Fatalf("INVALID_ARGS", "%v", err)
	}
	if _, err := pades.ParseLevel(*padesLevel); err != nil {
		Fatalf("INVALID_ARGS", "%v", err)
	}

	pos := appearance.DefaultPosition(0)
	if *sigPos != "" {
		p, err := parsePosition(*sigPos)
		if err != nil {
			Fatalf("INVALID_ARGS", "invalid --signature-position: %v", err)
		}
		pos = p
	}

	// Prepare writes the placeholder + stamp + ByteRange digest to a temp
	// PDF; we read it back so we can embed it inline in the state token.
	tmpPDF, err := os.CreateTemp("", "pdf-signer-prepare-*.pdf")
	if err != nil {
		Fatalf("IO_ERROR", "create temp PDF: %v", err)
	}
	tmpPDFPath := tmpPDF.Name()
	_ = tmpPDF.Close()
	defer os.Remove(tmpPDFPath)

	// Cert-derived name/NIC is the default; CLI flags override only when
	// explicitly set (R-5.1.1 — identity sourced from cert, flags become
	// display-only overrides).
	signerName := identity.CN
	if *nameOverride != "" {
		signerName = *nameOverride
	}
	nic := identity.NIC
	if *nicOverride != "" {
		nic = *nicOverride
	}

	prepareResult, err := pades.Prepare(pades.PrepareOptions{
		InputPath:          *input,
		OutputPath:         tmpPDFPath,
		SignerName:         signerName,
		SignerNIC:          nic,
		SigningMethod:      *signingMethod,
		SignaturePos:       pos,
		PlaceholderSize:    *placeholderSize,
		Reason:             *reasonFlag,
		Location:           *locationFlag,
		Name:               *nameFlag,
		Invisible:          *invisibleFlag,
		CertificationLevel: certLevel,
	})
	if err != nil {
		Fatalf("PREPARE_FAILED", "prepare: %v", err)
	}

	preparedBytes, err := os.ReadFile(tmpPDFPath)
	if err != nil {
		Fatalf("IO_ERROR", "read prepared PDF: %v", err)
	}

	// The digest returned by Prepare is ALREADY the ByteRange SHA-256 (per
	// pades.PrepareResult). Decode and feed it to BuildSignedAttrs as the
	// messageDigest attribute.
	docDigest, err := base64.StdEncoding.DecodeString(prepareResult.Hash)
	if err != nil {
		Fatalf("PREPARE_FAILED", "decode byte-range hash: %v", err)
	}

	cmsOpts := pades.BuildSignedAttrsOptions{
		DigestAlgorithm: hashAlg,
		SigningTime:     time.Now().UTC(),
	}
	if *sigPolicyOID != "" {
		oid, err := parseOIDString(*sigPolicyOID)
		if err != nil {
			Fatalf("INVALID_ARGS", "invalid --signature-policy-oid: %v", err)
		}
		cmsOpts.SignaturePolicyOID = oid
	}
	if *commitmentTypeOID != "" {
		oid, err := parseOIDString(*commitmentTypeOID)
		if err != nil {
			Fatalf("INVALID_ARGS", "invalid --commitment-type-oid: %v", err)
		}
		cmsOpts.CommitmentTypeOID = oid
	}

	signedAttrs, hashToSign, err := pades.BuildSignedAttrs(docDigest, cert, cmsOpts)
	if err != nil {
		Fatalf("CMS_BUILD_FAILED", "build signedAttrs: %v", err)
	}

	stateID, err := pades.NewStateID()
	if err != nil {
		Fatalf("IO_ERROR", "state id: %v", err)
	}

	if len(preparedBytes) > pades.InlinePDFMaxBytes {
		Fatalf("INVALID_ARGS", "prepared PDF (%d bytes) exceeds inline state limit (%d bytes); use legacy prepare/embed/finalize flow",
			len(preparedBytes), pades.InlinePDFMaxBytes)
	}

	effectivePlaceholder := *placeholderSize
	if effectivePlaceholder == 0 {
		effectivePlaceholder = pdf.PlaceholderSize
	}

	state, err := pades.NewState(pades.NewStateOptions{
		StateID:            stateID,
		PreparedPDF:        preparedBytes,
		SignedAttrsDER:     signedAttrs,
		SignerCertDER:      cert.Raw,
		PlaceholderSize:    effectivePlaceholder,
		FieldName:          prepareResult.FieldName,
		PAdESLevel:         *padesLevel,
		TSAURL:             *tsaURL,
		DigestAlgorithm:    *digestAlg,
		SignatureAlgorithm: *sigAlg,
		TTL:                *stateTTL,
	})
	if err != nil {
		Fatalf("STATE_BUILD_FAILED", "build state: %v", err)
	}
	if err := state.Write(*stateOut); err != nil {
		Fatalf("IO_ERROR", "write state: %v", err)
	}

	PrintJSON(signStartOutput{
		HashToSign:         base64.StdEncoding.EncodeToString(hashToSign),
		DigestAlgorithm:    *digestAlg,
		SignatureAlgorithm: *sigAlg,
		StateToken:         stateID,
		StatePath:          absOrAsIs(*stateOut),
	})
}

type signStartOutput struct {
	HashToSign         string `json:"hash_to_sign"`
	DigestAlgorithm    string `json:"digest_algorithm"`
	SignatureAlgorithm string `json:"signature_algorithm"`
	StateToken         string `json:"state_token"`
	StatePath          string `json:"state_path"`
}

func absOrAsIs(p string) string {
	if abs, err := filepath.Abs(p); err == nil {
		return abs
	}
	return p
}

// loadSignerCert accepts either DER or PEM and returns the parsed leaf
// cert. Detection is by PEM armour-header prefix; anything else is DER.
func loadSignerCert(path string) (*x509.Certificate, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if bytes.HasPrefix(raw, []byte("-----BEGIN ")) {
		block, _ := pem.Decode(raw)
		if block == nil || block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("PEM block not a CERTIFICATE")
		}
		return x509.ParseCertificate(block.Bytes)
	}
	return x509.ParseCertificate(raw)
}

// parseDigestAlgorithm maps the CLI string to a crypto.Hash. SHA-1 is
// refused outright — eIDAS / ETSI TS 119 312.
func parseDigestAlgorithm(s string) (crypto.Hash, error) {
	switch strings.ToUpper(s) {
	case "SHA-256", "SHA256":
		return crypto.SHA256, nil
	case "SHA-384", "SHA384":
		return crypto.SHA384, nil
	case "SHA-512", "SHA512":
		return crypto.SHA512, nil
	case "SHA-1", "SHA1":
		return 0, fmt.Errorf("SHA-1 refused (eIDAS forbids it)")
	}
	return 0, fmt.Errorf("unknown digest algorithm %q", s)
}

func validateSignatureAlgorithm(s string) error {
	switch s {
	case pades.SigAlgStrRSAPKCS1v15, pades.SigAlgStrRSAPSS, pades.SigAlgStrECDSA, pades.SigAlgStrEd25519:
		return nil
	}
	return fmt.Errorf("unknown signature algorithm %q", s)
}


// parseOIDString converts a dotted-decimal OID string (e.g. "2.16.620.2.1.2.2.1")
// to an asn1.ObjectIdentifier. Rejects empty strings and non-numeric arcs.
func parseOIDString(s string) (asn1.ObjectIdentifier, error) {
	if s == "" {
		return nil, fmt.Errorf("empty OID")
	}
	parts := strings.Split(s, ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("OID needs at least two arcs, got %q", s)
	}
	oid := make(asn1.ObjectIdentifier, len(parts))
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return nil, fmt.Errorf("invalid arc %q in OID %q", p, s)
		}
		oid[i] = n
	}
	return oid, nil
}

// parseCertificationLevel maps the --certification-level string to the
// pades.CertificationLevel enum. "none" → 0 means the catalog is left
// untouched (plain approval signature).
func parseCertificationLevel(s string) (pades.CertificationLevel, error) {
	switch s {
	case "none", "":
		return pades.CertLevelNone, nil
	case "no-changes":
		return pades.CertLevelNoChanges, nil
	case "form-fill":
		return pades.CertLevelFormFilling, nil
	case "annotations":
		return pades.CertLevelAnnotations, nil
	}
	return 0, fmt.Errorf("unknown --certification-level %q (want none|no-changes|form-fill|annotations)", s)
}

