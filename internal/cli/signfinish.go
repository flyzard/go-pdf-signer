package cli

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/flyzard/pdf-signer/internal/certs"
	"github.com/flyzard/pdf-signer/internal/pades"
	"github.com/flyzard/pdf-signer/internal/pdf"
)

// newSignalContext returns a cancellable background context that also
// cancels on SIGINT / SIGTERM. The returned cancel MUST be called — it
// releases the signal subscription registered with the runtime.
func newSignalContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
}

// RunSignFinish implements the sign-finish subcommand per R-8.4.2: loads
// the state token, mathematically verifies the external signature,
// assembles the CMS SignedData, embeds it in the prepared PDF, writes
// the output. When the state carries pades_level >= B-T the external
// signature is timestamped; >= B-LT runs post-embed Finalize for DSS;
// = B-LTA appends a DocTimeStamp.
func RunSignFinish(args []string) {
	fs := flag.NewFlagSet("sign-finish", flag.ContinueOnError)

	statePath := fs.String("state", "", "Path to sign-start state token (required)")
	signaturePath := fs.String("signature", "", "Path to raw signature bytes from external signer (required)")
	output := fs.String("output", "", "Output signed PDF file path (required)")
	chainPath := fs.String("cert-chain", "", "Optional path to additional cert chain (PEM or DER-concat)")
	tsaURLOverride := fs.String("tsa-url", "", "Override state's TSA URL (used when pades_level >= B-T)")

	if err := fs.Parse(args); err != nil {
		Fatalf("INVALID_ARGS", "failed to parse arguments: %v", err)
	}

	ctx, cancel := newSignalContext()
	defer cancel()
	if *statePath == "" {
		Fatalf("INVALID_ARGS", "missing required flag: --state")
	}
	if *signaturePath == "" {
		Fatalf("INVALID_ARGS", "missing required flag: --signature")
	}
	if *output == "" {
		Fatalf("INVALID_ARGS", "missing required flag: --output")
	}

	state, err := pades.LoadState(*statePath)
	if err != nil {
		Fatalf("STATE_INVALID", "load state: %v", err)
	}

	signatureBytes, err := os.ReadFile(*signaturePath)
	if err != nil {
		Fatalf("IO_ERROR", "read signature: %v", err)
	}
	if len(signatureBytes) == 0 {
		Fatalf("INVALID_ARGS", "signature file is empty")
	}

	signerCertDER, err := base64.StdEncoding.DecodeString(state.SignerCertDERB64)
	if err != nil {
		Fatalf("STATE_INVALID", "decode signer cert: %v", err)
	}
	cert, err := x509.ParseCertificate(signerCertDER)
	if err != nil {
		Fatalf("CERT_PARSE_FAILED", "parse signer cert: %v", err)
	}
	signedAttrs, err := state.DecodeSignedAttrs()
	if err != nil {
		Fatalf("STATE_INVALID", "decode signed attrs: %v", err)
	}

	digestAlg, err := parseDigestAlgorithm(state.DigestAlgorithm)
	if err != nil {
		Fatalf("STATE_INVALID", "%v", err)
	}

	// R-8.4.2.2 — math-verify BEFORE touching CMS. Re-hash the signedAttrs
	// SET and verify signature against cert.PublicKey. Garbage signatures
	// never propagate into a CMS blob.
	if err := verifyExternalSignature(cert, digestAlg, state.SignatureAlgorithm, signedAttrs, signatureBytes); err != nil {
		finishFail(state, *statePath, "SIGNATURE_INVALID", "pre-CMS signature verify failed: %v", err)
	}

	sigAlgConst, err := signatureAlgorithmFromString(state.SignatureAlgorithm)
	if err != nil {
		finishFail(state, *statePath, "STATE_INVALID", "%v", err)
	}

	var chain []*x509.Certificate
	if *chainPath != "" {
		chain, err = loadChain(*chainPath)
		if err != nil {
			finishFail(state, *statePath, "CERT_PARSE_FAILED", "load chain: %v", err)
		}
	}

	// Levels >= B-T need a signature timestamp in unsignedAttrs. Fetch
	// the token, validate its CMS signature + TSA cert chain + EKU BEFORE
	// embedding — a malicious TSA URL could otherwise poison the CMS.
	var unsignedAttrs []byte
	timestampStatus := "skipped"
	if pades.PAdESLevel(state.PAdESLevel).NeedsTSA() {
		tsaURL := state.TSAURL
		if *tsaURLOverride != "" {
			tsaURL = *tsaURLOverride
		}
		if tsaURL == "" {
			finishFail(state, *statePath, "INVALID_ARGS",
				"pades_level=%s requires --tsa-url (or state.tsa_url)", state.PAdESLevel)
		}
		attrs, token, tsErr := pades.FetchSignatureTimestamp(
			ctx, tsaURL, signatureBytes, digestAlg)
		if tsErr != nil {
			finishFail(state, *statePath, "TSA_FETCH_FAILED", "fetch signature timestamp: %v", tsErr)
		}
		// Compute the imprint we asked the TSA to stamp; validation
		// re-checks the token declares the same imprint (stops a
		// compromised TSA from stamping a substituted digest).
		imprint := digestAlg.New()
		imprint.Write(signatureBytes)
		if _, vErr := pades.ValidateTSAToken(token, imprint.Sum(nil), certs.TSARoots()); vErr != nil {
			finishFail(state, *statePath, "TSA_FETCH_FAILED", "validate TSA token: %v", vErr)
		}
		unsignedAttrs = attrs
		timestampStatus = "ok"
	}

	cmsDER, err := pades.AssembleSignedData(pades.AssembleSignedDataOptions{
		SignedAttrs:   signedAttrs,
		Signature:     signatureBytes,
		SignerCert:    cert,
		Chain:         chain,
		DigestAlg:     digestAlg,
		SignatureAlg:  sigAlgConst,
		UnsignedAttrs: unsignedAttrs,
	})
	if err != nil {
		finishFail(state, *statePath, "CMS_BUILD_FAILED", "assemble CMS: %v", err)
	}

	preparedBytes, err := state.LoadPreparedPDF()
	if err != nil {
		finishFail(state, *statePath, "STATE_INVALID", "load prepared PDF: %v", err)
	}

	signedPDF, err := pdf.EmbedCMS(preparedBytes, cmsDER)
	if err != nil {
		if errors.Is(err, pdf.ErrPlaceholderTooSmall) {
			finishFail(state, *statePath, "PLACEHOLDER_TOO_SMALL",
				"CMS (%d bytes) does not fit placeholder (%d bytes); re-run sign-start with --placeholder-size",
				len(cmsDER), state.PlaceholderSize)
		}
		finishFail(state, *statePath, "EMBED_FAILED", "embed CMS: %v", err)
	}

	// Sanity: no zero-filled placeholder should remain in the output (same
	// guarantee Embed has enforced since before sign-start/finish existed).
	if _, err := pdf.FindPlaceholder(signedPDF); err == nil {
		finishFail(state, *statePath, "EMBED_FAILED", "placeholder still present in output")
	}

	warnings := []string{}
	achieved := "B-B"
	if timestampStatus == "ok" {
		achieved = "B-T"
	}
	ltvStatus := "none"

	// B-LT: after CMS embed, collect validation data and write DSS as a
	// separate incremental update so the verifier has everything offline.
	if pades.PAdESLevel(state.PAdESLevel).NeedsDSS() {
		// Persist the post-embed PDF first so pades.Finalize can operate
		// on a real file (it re-parses, walks signatures, fetches OCSP/CRL,
		// writes DSS via another incremental update).
		if err := pdf.WriteFileAtomic(*output, signedPDF); err != nil {
			finishFail(state, *statePath, "IO_ERROR", "write post-embed PDF: %v", err)
		}
		fin, err := pades.Finalize(ctx, pades.FinalizeOptions{
			InputPath:  *output,
			OutputPath: *output,
		})
		if err != nil {
			finishFail(state, *statePath, "FINALIZE_FAILED", "collect validation data: %v", err)
		}
		warnings = append(warnings, fin.Warnings...)
		achieved = "B-LT"
		ltvStatus = fin.LTVStatus
	} else {
		if err := pdf.WriteFileAtomic(*output, signedPDF); err != nil {
			finishFail(state, *statePath, "IO_ERROR", "write output: %v", err)
		}
	}

	// B-LTA: further incremental update adding a DocTimeStamp signature
	// over the whole post-DSS state. Invisible; carries a raw RFC 3161
	// token in /Contents; SubFilter ETSI.RFC3161.
	if pades.PAdESLevel(state.PAdESLevel).NeedsDocTimeStamp() {
		tsaURL := state.TSAURL
		if *tsaURLOverride != "" {
			tsaURL = *tsaURLOverride
		}
		if tsaURL == "" {
			finishFail(state, *statePath, "INVALID_ARGS",
				"pades_level=B-LTA requires --tsa-url (or state.tsa_url)")
		}
		priorBytes, err := os.ReadFile(*output)
		if err != nil {
			finishFail(state, *statePath, "IO_ERROR", "read post-DSS PDF: %v", err)
		}
		updated, err := pades.AppendDocTimeStamp(ctx, pades.AppendDocTimeStampOptions{
			PDFBytes: priorBytes,
			TSAURL:   tsaURL,
			TSAPool:  certs.TSARoots(),
		})
		if err != nil {
			finishFail(state, *statePath, "TSA_FETCH_FAILED", "append DocTimeStamp: %v", err)
		}
		if err := pdf.WriteFileAtomic(*output, updated); err != nil {
			finishFail(state, *statePath, "IO_ERROR", "write DocTimeStamp PDF: %v", err)
		}
		achieved = "B-LTA"
	}

	// Success: remove state file per R-8.4.2.10.
	_ = os.Remove(*statePath)

	PrintJSON(signFinishOutput{
		Output:             *output,
		FieldName:          state.FieldName,
		PAdESLevelAchieved: achieved,
		TimestampStatus:    timestampStatus,
		LTVStatus:          ltvStatus,
		Warnings:           warnings,
	})
}


type signFinishOutput struct {
	Output             string   `json:"output"`
	FieldName          string   `json:"field_name"`
	PAdESLevelAchieved string   `json:"pades_level_achieved"`
	TimestampStatus    string   `json:"timestamp_status,omitempty"`
	LTVStatus          string   `json:"ltv_status,omitempty"`
	Warnings           []string `json:"warnings,omitempty"`
}

// finishFail renames the state file to <state>.failed so operators can
// inspect it, then exits via Fatalf. Keeping the evidence on disk is worth
// more than tidy cleanup when diagnosing a production signing failure.
func finishFail(state *pades.State, statePath, code, format string, args ...any) {
	if state != nil && statePath != "" {
		_ = os.Rename(statePath, statePath+".failed")
	}
	Fatalf(code, format, args...)
}

// verifyExternalSignature hashes the signedAttrs-as-SET and runs the
// appropriate Verify* for the declared signature algorithm. This is the
// R-8.4.2.2 gate — we refuse to wrap a signature that doesn't actually
// match the cert's public key over the committed bytes.
func verifyExternalSignature(cert *x509.Certificate, hashAlg crypto.Hash, sigAlgStr string, signedAttrsImplicit, signature []byte) error {
	// signedAttrsImplicit starts with 0xA0 (context [0] IMPLICIT). RFC 5652
	// §5.4 says the hash input uses the universal SET (0x31) tag — rewrite
	// the first byte before hashing.
	if len(signedAttrsImplicit) == 0 || signedAttrsImplicit[0] != 0xA0 {
		return fmt.Errorf("signedAttrs must start with [0] IMPLICIT (0xA0)")
	}
	toHash := make([]byte, len(signedAttrsImplicit))
	copy(toHash, signedAttrsImplicit)
	toHash[0] = 0x31

	h := hashAlg.New()
	h.Write(toHash)
	digest := h.Sum(nil)

	switch sigAlgStr {
	case pades.SigAlgStrRSAPKCS1v15:
		pub, ok := cert.PublicKey.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("RSA-PKCS1-v1_5 requires RSA public key, got %T", cert.PublicKey)
		}
		return rsa.VerifyPKCS1v15(pub, hashAlg, digest, signature)
	case pades.SigAlgStrRSAPSS:
		pub, ok := cert.PublicKey.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("RSA-PSS requires RSA public key, got %T", cert.PublicKey)
		}
		return rsa.VerifyPSS(pub, hashAlg, digest, signature, &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
			Hash:       hashAlg,
		})
	case pades.SigAlgStrECDSA:
		pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("ECDSA requires ECDSA public key, got %T", cert.PublicKey)
		}
		if !ecdsa.VerifyASN1(pub, digest, signature) {
			return fmt.Errorf("ECDSA signature check failed")
		}
		return nil
	case pades.SigAlgStrEd25519:
		pub, ok := cert.PublicKey.(ed25519.PublicKey)
		if !ok {
			return fmt.Errorf("Ed25519 requires Ed25519 public key, got %T", cert.PublicKey)
		}
		// Ed25519 operates on the message, not the hash.
		if !ed25519.Verify(pub, toHash, signature) {
			return fmt.Errorf("Ed25519 signature check failed")
		}
		return nil
	}
	return fmt.Errorf("unknown signature algorithm %q", sigAlgStr)
}

func signatureAlgorithmFromString(s string) (pades.SignatureAlgorithm, error) {
	switch s {
	case pades.SigAlgStrRSAPKCS1v15:
		return pades.SigAlgRSAPKCS1v15, nil
	case pades.SigAlgStrRSAPSS:
		return pades.SigAlgRSAPSS, nil
	case pades.SigAlgStrECDSA:
		return pades.SigAlgECDSA, nil
	case pades.SigAlgStrEd25519:
		return pades.SigAlgEd25519, nil
	}
	return 0, fmt.Errorf("unknown signature algorithm %q", s)
}

func loadChain(path string) ([]*x509.Certificate, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if bytes.HasPrefix(raw, []byte("-----BEGIN ")) {
		var out []*x509.Certificate
		rest := raw
		for {
			block, remaining := pem.Decode(rest)
			if block == nil {
				return out, nil
			}
			rest = remaining
			if block.Type != "CERTIFICATE" {
				continue
			}
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("parse chain PEM cert: %w", err)
			}
			out = append(out, cert)
		}
	}
	certs, err := x509.ParseCertificates(raw)
	if err != nil {
		return nil, fmt.Errorf("parse DER chain: %w", err)
	}
	return certs, nil
}
