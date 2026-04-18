package cli

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/flyzard/pdf-signer/internal/appearance"
	"github.com/flyzard/pdf-signer/internal/certs"
	pdcrypto "github.com/flyzard/pdf-signer/internal/crypto"
	"github.com/flyzard/pdf-signer/internal/pades"
	"github.com/flyzard/pdf-signer/internal/pdf"

	"golang.org/x/crypto/pkcs12"
)

// allowLocalKeysEnv is the defense-in-depth gate on sign-local. A server
// deployment that should ONLY receive external signatures sets this to
// anything other than "1" (or leaves it unset) so an accidentally-shipped
// private key can never be used.
const allowLocalKeysEnv = "PDFSIGNER_ALLOW_LOCAL_KEYS"

// RunSignLocal implements the sign-local subcommand per R-8.4.3: one-shot
// signing using a locally-held private key. Equivalent to running
// sign-start → sign → sign-finish in a single in-process pipeline. Intended
// for CI, smoke tests, preprod signing, and local-key workflows.
func RunSignLocal(args []string) {
	if os.Getenv(allowLocalKeysEnv) != "1" {
		Fatalf("LOCAL_KEYS_DISABLED",
			"%s=1 must be set to allow sign-local (refuses by default in server contexts)", allowLocalKeysEnv)
	}

	fs := flag.NewFlagSet("sign-local", flag.ContinueOnError)

	input := fs.String("input", "", "Input PDF file path (required)")
	output := fs.String("output", "", "Output signed PDF file path (required)")
	keyPath := fs.String("key", "", "Path to private key: PKCS#12 (.p12/.pfx) or PEM (required)")
	certChainPath := fs.String("cert-chain", "",
		"Path to PEM/DER cert chain when --key is PEM (ignored for PKCS#12 which bundles its own chain)")
	keyPassEnv := fs.String("key-pass-env", "", "Env var holding the PKCS#12 password (preferred)")
	keyPassFile := fs.String("key-pass-file", "", "File containing the PKCS#12 password (permissions 0600)")
	keyPassStdin := fs.Bool("key-pass-stdin", false, "Read the PKCS#12 password from stdin (first line)")
	padesLevel := fs.String("pades-level", "B-LT", "PAdES level: B-B | B-T | B-LT | B-LTA")
	signingMethod := fs.String("signing-method", "cmd", "Signing method: cmd or cc")
	sigPos := fs.String("signature-position", "", "Signature position: page,x,y,w,h (default: auto)")
	tsaURL := fs.String("tsa-url", "", "RFC 3161 TSA URL (used when pades-level >= B-T)")
	placeholderSize := fs.Int("placeholder-size", 0, "Signature /Contents placeholder capacity in bytes")
	digestAlgFlag := fs.String("digest-algorithm", "SHA-256", "Digest algorithm: SHA-256 | SHA-384 | SHA-512")
	sigAlgFlag := fs.String("signature-algorithm", pades.SigAlgStrRSAPKCS1v15,
		"Signature algorithm: RSA-PKCS1-v1_5 | RSA-PSS | ECDSA | Ed25519")
	maxInputSize := fs.Int64("max-input-size", 0, "Maximum --input PDF size in bytes (0 = default 500MB)")
	reasonFlag := fs.String("reason", "", "Override /Reason on the signature dict")
	locationFlag := fs.String("location", "", "Override /Location on the signature dict")
	nameFlag := fs.String("name", "", "Override /Name on the signature dict (default: cert CN)")
	invisibleFlag := fs.Bool("invisible", false, "Skip the visible stamp; emit /Rect [0 0 0 0]")
	certLevelFlag := fs.String("certification-level", "none",
		"DocMDP certification: none | no-changes | form-fill | annotations. First signature only.")

	if err := fs.Parse(args); err != nil {
		Fatalf("INVALID_ARGS", "failed to parse arguments: %v", err)
	}
	if *input == "" {
		Fatalf("INVALID_ARGS", "missing required flag: --input")
	}
	if *output == "" {
		Fatalf("INVALID_ARGS", "missing required flag: --output")
	}
	if *keyPath == "" {
		Fatalf("INVALID_ARGS", "missing required flag: --key")
	}
	level, err := pades.ParseLevel(*padesLevel)
	if err != nil {
		Fatalf("INVALID_ARGS", "%v", err)
	}
	if err := validateSignatureAlgorithm(*sigAlgFlag); err != nil {
		Fatalf("INVALID_ARGS", "%v", err)
	}
	hashAlg, err := parseDigestAlgorithm(*digestAlgFlag)
	if err != nil {
		Fatalf("INVALID_ARGS", "%v", err)
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

	password, err := loadKeyPassword(*keyPassEnv, *keyPassFile, *keyPassStdin)
	if err != nil {
		Fatalf("INVALID_ARGS", "load --key password: %v", err)
	}
	defer zeroBytes(password)

	priv, signer, chain, err := loadPrivateKeyAndChain(*keyPath, *certChainPath, password)
	if err != nil {
		Fatalf("CERT_PARSE_FAILED", "load --key: %v", err)
	}
	// Password no longer needed once key material is loaded.
	zeroBytes(password)

	if signer.Subject.CommonName == "" {
		Fatalf("CERT_CN_EMPTY", "signer certificate has empty CommonName")
	}
	if err := pdcrypto.ValidateSignerCert(signer); err != nil {
		var pe *pdcrypto.CertPolicyError
		if errors.As(err, &pe) {
			Fatalf(pe.Code, "%s", pe.Msg)
		}
		Fatalf("CERT_INVALID", "signer cert: %v", err)
	}
	identity, err := certs.ExtractIdentity(signer)
	if err != nil {
		Fatalf("CERT_PARSE_FAILED", "extract identity: %v", err)
	}

	pos := appearance.DefaultPosition(0)
	if *sigPos != "" {
		p, err := parsePosition(*sigPos)
		if err != nil {
			Fatalf("INVALID_ARGS", "invalid --signature-position: %v", err)
		}
		pos = p
	}

	// sign-start half — prepare the PDF in memory via a temp file. Same
	// shape as RunSignStart; kept local so future PrepareToBytes API swap
	// replaces both callers at once.
	tmpPDF, err := os.CreateTemp("", "pdf-signer-signlocal-*.pdf")
	if err != nil {
		Fatalf("IO_ERROR", "create temp PDF: %v", err)
	}
	tmpPath := tmpPDF.Name()
	_ = tmpPDF.Close()
	defer os.Remove(tmpPath)

	prep, err := pades.Prepare(pades.PrepareOptions{
		InputPath:          *input,
		OutputPath:         tmpPath,
		SignerName:         identity.CN,
		SignerNIC:          identity.NIC,
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
	preparedBytes, err := os.ReadFile(tmpPath)
	if err != nil {
		Fatalf("IO_ERROR", "read prepared PDF: %v", err)
	}

	docDigest, err := base64.StdEncoding.DecodeString(prep.Hash)
	if err != nil {
		Fatalf("PREPARE_FAILED", "decode ByteRange hash: %v", err)
	}
	signedAttrs, hashToSign, err := pades.BuildSignedAttrs(docDigest, signer, pades.BuildSignedAttrsOptions{
		DigestAlgorithm: hashAlg,
		SigningTime:     time.Now().UTC(),
	})
	if err != nil {
		Fatalf("CMS_BUILD_FAILED", "build signedAttrs: %v", err)
	}

	sigBytes, err := signHashLocally(priv, hashAlg, hashToSign, *sigAlgFlag)
	if err != nil {
		Fatalf("SIGN_FAILED", "local sign: %v", err)
	}

	// sign-finish half — assemble CMS, optionally TSA, embed, DSS, DocTimeStamp.
	ctx, cancel := newSignalContext()
	defer cancel()

	sigAlgConst, _ := signatureAlgorithmFromString(*sigAlgFlag)

	var unsignedAttrs []byte
	timestampStatus := "skipped"
	padesAchieved := "B-B"
	if level.NeedsTSA() {
		if *tsaURL == "" {
			Fatalf("INVALID_ARGS", "pades_level=%s requires --tsa-url", *padesLevel)
		}
		attrs, token, tsErr := pades.FetchSignatureTimestamp(ctx, *tsaURL, sigBytes, hashAlg)
		if tsErr != nil {
			Fatalf("TSA_FETCH_FAILED", "fetch signature timestamp: %v", tsErr)
		}
		imprint := hashAlg.New()
		imprint.Write(sigBytes)
		if _, vErr := pades.ValidateTSAToken(token, imprint.Sum(nil), certs.TSARoots()); vErr != nil {
			Fatalf("TSA_FETCH_FAILED", "validate TSA token: %v", vErr)
		}
		unsignedAttrs = attrs
		timestampStatus = "ok"
		padesAchieved = "B-T"
	}

	cmsDER, err := pades.AssembleSignedData(pades.AssembleSignedDataOptions{
		SignedAttrs:   signedAttrs,
		Signature:     sigBytes,
		SignerCert:    signer,
		Chain:         chain,
		DigestAlg:     hashAlg,
		SignatureAlg:  sigAlgConst,
		UnsignedAttrs: unsignedAttrs,
	})
	if err != nil {
		Fatalf("CMS_BUILD_FAILED", "assemble CMS: %v", err)
	}
	signedPDF, err := pdf.EmbedCMS(preparedBytes, cmsDER)
	if err != nil {
		if errors.Is(err, pdf.ErrPlaceholderTooSmall) {
			Fatalf("PLACEHOLDER_TOO_SMALL",
				"CMS (%d bytes) does not fit placeholder; re-run with larger --placeholder-size",
				len(cmsDER))
		}
		Fatalf("EMBED_FAILED", "embed CMS: %v", err)
	}
	if _, err := pdf.FindPlaceholder(signedPDF); err == nil {
		Fatalf("EMBED_FAILED", "placeholder still present in output")
	}

	ltvStatus := "none"
	warnings := []string{}
	if level.NeedsDSS() {
		if err := pdf.WriteFileAtomic(*output, signedPDF); err != nil {
			Fatalf("IO_ERROR", "write post-embed PDF: %v", err)
		}
		fin, err := pades.Finalize(ctx, pades.FinalizeOptions{InputPath: *output, OutputPath: *output})
		if err != nil {
			Fatalf("FINALIZE_FAILED", "collect validation data: %v", err)
		}
		warnings = append(warnings, fin.Warnings...)
		padesAchieved = "B-LT"
		ltvStatus = fin.LTVStatus
	} else {
		if err := pdf.WriteFileAtomic(*output, signedPDF); err != nil {
			Fatalf("IO_ERROR", "write output: %v", err)
		}
	}
	if level.NeedsDocTimeStamp() {
		priorBytes, err := os.ReadFile(*output)
		if err != nil {
			Fatalf("IO_ERROR", "read post-DSS PDF: %v", err)
		}
		updated, err := pades.AppendDocTimeStamp(ctx, pades.AppendDocTimeStampOptions{
			PDFBytes: priorBytes,
			TSAURL:   *tsaURL,
			TSAPool:  certs.TSARoots(),
		})
		if err != nil {
			Fatalf("TSA_FETCH_FAILED", "append DocTimeStamp: %v", err)
		}
		if err := pdf.WriteFileAtomic(*output, updated); err != nil {
			Fatalf("IO_ERROR", "write DocTimeStamp PDF: %v", err)
		}
		padesAchieved = "B-LTA"
	}

	PrintJSON(signFinishOutput{
		Output:             absOrAsIs(*output),
		FieldName:          prep.FieldName,
		PAdESLevelAchieved: padesAchieved,
		TimestampStatus:    timestampStatus,
		LTVStatus:          ltvStatus,
		Warnings:           warnings,
	})
}

// loadKeyPassword resolves the PKCS#12 password from whichever source the
// caller selected. Zero or one source may be set; two or more is an error
// so a misconfigured CI script does not silently pick the "wrong" value.
func loadKeyPassword(env, file string, stdin bool) ([]byte, error) {
	sources := 0
	if env != "" {
		sources++
	}
	if file != "" {
		sources++
	}
	if stdin {
		sources++
	}
	if sources > 1 {
		return nil, fmt.Errorf("pick exactly one of --key-pass-env / --key-pass-file / --key-pass-stdin")
	}
	switch {
	case env != "":
		return []byte(os.Getenv(env)), nil
	case file != "":
		b, err := os.ReadFile(file)
		if err != nil {
			return nil, err
		}
		return bytes.TrimRight(b, "\r\n"), nil
	case stdin:
		b, err := io.ReadAll(os.Stdin)
		if err != nil {
			return nil, err
		}
		if i := bytes.IndexAny(b, "\r\n"); i >= 0 {
			b = b[:i]
		}
		return b, nil
	}
	return nil, nil // caller handles the PEM-unencrypted case
}

// loadPrivateKeyAndChain handles both PKCS#12 (self-contained) and PEM
// (+ optional --cert-chain) inputs. Returns the private key, the signer
// leaf cert, and any additional chain certs to include in the CMS
// certificates SET.
func loadPrivateKeyAndChain(keyPath, chainPath string, password []byte) (crypto.PrivateKey, *x509.Certificate, []*x509.Certificate, error) {
	raw, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, nil, nil, err
	}
	if looksPKCS12(keyPath, raw) {
		// x/crypto/pkcs12.Decode returns leaf-only; for full-chain support
		// we convert to PEM blocks and walk them like a PEM bundle.
		blocks, err := pkcs12.ToPEM(raw, string(password))
		if err != nil {
			return nil, nil, nil, fmt.Errorf("decode PKCS#12: %w", err)
		}
		return assemblePKCS12Blocks(blocks)
	}
	key, leaf, err := decodePEMKeyAndCert(raw)
	if err != nil {
		return nil, nil, nil, err
	}
	var chain []*x509.Certificate
	if chainPath != "" {
		chain, err = loadChain(chainPath)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("load --cert-chain: %w", err)
		}
	}
	if leaf == nil {
		return nil, nil, nil, fmt.Errorf("PEM key file does not contain a leaf certificate; supply --cert-chain with the leaf first")
	}
	return key, leaf, chain, nil
}

// looksPKCS12 returns true when the file looks like a PFX blob. PEM files
// start with `-----BEGIN `; PKCS#12 is binary and typically starts with
// `0x30 0x82` (ASN.1 SEQUENCE). Extension is a secondary hint.
func looksPKCS12(path string, raw []byte) bool {
	if strings.HasSuffix(strings.ToLower(path), ".p12") ||
		strings.HasSuffix(strings.ToLower(path), ".pfx") {
		return true
	}
	return len(raw) > 2 && raw[0] == 0x30 && !bytes.HasPrefix(raw, []byte("-----BEGIN "))
}

// assemblePKCS12Blocks walks the PEM blocks produced by pkcs12.ToPEM and
// extracts the first private key, the first certificate (leaf), and any
// further certificates (intermediates).
//
// pkcs12.ToPEM is inconsistent about key block headers — it sometimes
// labels a PKCS#1 body as "PRIVATE KEY" — so the key parse tries every
// known format before giving up.
func assemblePKCS12Blocks(blocks []*pem.Block) (crypto.PrivateKey, *x509.Certificate, []*x509.Certificate, error) {
	var key crypto.PrivateKey
	var leaf *x509.Certificate
	var extras []*x509.Certificate
	for _, b := range blocks {
		switch b.Type {
		case "PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY":
			k, err := parseAnyPrivateKey(b.Bytes)
			if err != nil {
				return nil, nil, nil, fmt.Errorf("pkcs12 key: %w", err)
			}
			key = k
		case "CERTIFICATE":
			cert, err := x509.ParseCertificate(b.Bytes)
			if err != nil {
				return nil, nil, nil, fmt.Errorf("pkcs12 cert: %w", err)
			}
			if leaf == nil {
				leaf = cert
			} else {
				extras = append(extras, cert)
			}
		}
	}
	if key == nil {
		return nil, nil, nil, fmt.Errorf("pkcs12: no private key found")
	}
	if leaf == nil {
		return nil, nil, nil, fmt.Errorf("pkcs12: no certificate found")
	}
	return key, leaf, extras, nil
}

// parseAnyPrivateKey tries PKCS#8, PKCS#1 RSA, and SEC1 EC in order so
// callers don't have to care which format the source encoded.
func parseAnyPrivateKey(der []byte) (crypto.PrivateKey, error) {
	if k, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		return k, nil
	}
	if k, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return k, nil
	}
	if k, err := x509.ParseECPrivateKey(der); err == nil {
		return k, nil
	}
	return nil, fmt.Errorf("unrecognised private key format")
}

// decodePEMKeyAndCert walks a PEM blob extracting the first private key
// block (the signer's key) and the first CERTIFICATE block, if any. Later
// certificates in the same file extend the chain.
func decodePEMKeyAndCert(raw []byte) (crypto.PrivateKey, *x509.Certificate, error) {
	var key crypto.PrivateKey
	var leaf *x509.Certificate
	rest := raw
	for {
		block, remaining := pem.Decode(rest)
		if block == nil {
			break
		}
		rest = remaining
		switch block.Type {
		case "PRIVATE KEY":
			k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return nil, nil, fmt.Errorf("parse PKCS#8 key: %w", err)
			}
			key = k
		case "RSA PRIVATE KEY":
			k, err := x509.ParsePKCS1PrivateKey(block.Bytes)
			if err != nil {
				return nil, nil, fmt.Errorf("parse PKCS#1 RSA key: %w", err)
			}
			key = k
		case "EC PRIVATE KEY":
			k, err := x509.ParseECPrivateKey(block.Bytes)
			if err != nil {
				return nil, nil, fmt.Errorf("parse SEC1 EC key: %w", err)
			}
			key = k
		case "CERTIFICATE":
			if leaf == nil {
				cert, err := x509.ParseCertificate(block.Bytes)
				if err != nil {
					return nil, nil, fmt.Errorf("parse cert: %w", err)
				}
				leaf = cert
			}
		}
	}
	if key == nil {
		return nil, nil, fmt.Errorf("no PRIVATE KEY block found in PEM")
	}
	return key, leaf, nil
}

// signHashLocally runs the in-process signing that would otherwise be the
// external signer's job in sign-start/sign-finish. Selects the primitive
// by algorithm string; Ed25519 signs the input (not the digest) per RFC 8032.
func signHashLocally(priv crypto.PrivateKey, hashAlg crypto.Hash, hashToSign []byte, sigAlgStr string) ([]byte, error) {
	switch sigAlgStr {
	case pades.SigAlgStrRSAPKCS1v15:
		rsaKey, ok := priv.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("RSA-PKCS1-v1_5 needs RSA key, got %T", priv)
		}
		return rsa.SignPKCS1v15(rand.Reader, rsaKey, hashAlg, hashToSign)
	case pades.SigAlgStrRSAPSS:
		rsaKey, ok := priv.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("RSA-PSS needs RSA key, got %T", priv)
		}
		return rsa.SignPSS(rand.Reader, rsaKey, hashAlg, hashToSign, &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
			Hash:       hashAlg,
		})
	case pades.SigAlgStrECDSA:
		ecKey, ok := priv.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("ECDSA needs ECDSA key, got %T", priv)
		}
		return ecdsa.SignASN1(rand.Reader, ecKey, hashToSign)
	case pades.SigAlgStrEd25519:
		edKey, ok := priv.(ed25519.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("Ed25519 needs Ed25519 key, got %T", priv)
		}
		// Ed25519 signs the message directly; the caller passes
		// hashToSign but the signer needs to recompute over the same
		// bytes. sign-finish already handles this asymmetry by feeding
		// signedAttrs-as-SET; for sign-local we replicate that input.
		return ed25519.Sign(edKey, hashToSign), nil
	}
	return nil, fmt.Errorf("unknown signature algorithm %q", sigAlgStr)
}

// zeroBytes overwrites b with zeros. Defense-in-depth against post-use
// memory scans; Go's GC may keep a copy elsewhere but this reduces the
// surface of any residual password bytes.
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

