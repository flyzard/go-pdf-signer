package pades

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/flyzard/pdf-signer/internal/appearance"
	"github.com/flyzard/pdf-signer/internal/pdf"
)

// TestSignStartFinishEndToEnd exercises the full public API path that
// sign-start and sign-finish use: Prepare → BuildSignedAttrs → external
// sign → AssembleSignedData → EmbedCMS → Verify. Proves the emitted
// signature passes every in-repo verify gate, including the new
// ess_v2_binding and hash_alg_consistency gates.
func TestSignStartFinishEndToEnd(t *testing.T) {
	cert, key := makeTestSignerCert(t)

	// 1. Prepare: writes a PDF with placeholder + stamp and returns the
	//    SHA-256 of the ByteRange.
	inputPath := createTestPDF(t)
	preparedPath := filepath.Join(t.TempDir(), "prepared.pdf")
	prep, err := Prepare(PrepareOptions{
		InputPath:     inputPath,
		OutputPath:    preparedPath,
		SignerName:    cert.Subject.CommonName,
		SigningMethod: "cmd",
		SignaturePos:  appearance.DefaultPosition(0),
	})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	docHash, err := base64.StdEncoding.DecodeString(prep.Hash)
	if err != nil {
		t.Fatalf("decode ByteRange hash: %v", err)
	}

	// 2. Build signedAttrs.
	signedAttrs, hashToSign, err := BuildSignedAttrs(docHash, cert, BuildSignedAttrsOptions{
		DigestAlgorithm: crypto.SHA256,
		SigningTime:     time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("BuildSignedAttrs: %v", err)
	}

	// 3. External sign of hashToSign.
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hashToSign)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	// 4. Assemble CMS.
	cmsDER, err := AssembleSignedData(AssembleSignedDataOptions{
		SignedAttrs: signedAttrs, Signature: signature, SignerCert: cert,
		DigestAlg: crypto.SHA256, SignatureAlg: SigAlgRSAPKCS1v15,
	})
	if err != nil {
		t.Fatalf("AssembleSignedData: %v", err)
	}

	// 5. Embed into prepared PDF.
	prepared, err := os.ReadFile(preparedPath)
	if err != nil {
		t.Fatalf("read prepared: %v", err)
	}
	signed, err := pdf.EmbedCMS(prepared, cmsDER)
	if err != nil {
		t.Fatalf("EmbedCMS: %v", err)
	}
	signedPath := filepath.Join(t.TempDir(), "signed.pdf")
	if err := os.WriteFile(signedPath, signed, 0o600); err != nil {
		t.Fatalf("write signed: %v", err)
	}

	// 6. Verify. Every crypto gate must pass.
	res, err := Verify(VerifyOptions{InputPath: signedPath})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if len(res.Signatures) != 1 {
		t.Fatalf("want 1 signature, got %d", len(res.Signatures))
	}
	sig := res.Signatures[0]
	if !sig.ByteRangeValid || !sig.HashMatch || !sig.SignatureValid {
		t.Errorf("core gates failed: %+v (%s)", sig, sig.VerifyError)
	}

	// 7. Independently run the ESS binding and hash-alg consistency gates
	//    against the parsed CMS — the output bytes must support them.
	parsed, err := parseCMS(cmsDER)
	if err != nil {
		t.Fatalf("parseCMS: %v", err)
	}
	si := parsed.SignerInfos[0]
	signer, err := si.findSignerCert(parsed.Certificates)
	if err != nil {
		t.Fatalf("findSignerCert: %v", err)
	}
	if err := ValidateESSBinding(si, signer); err != nil {
		t.Errorf("ValidateESSBinding on sign-finish output: %v", err)
	}
	if err := HashAlgConsistency(parsed, si); err != nil {
		t.Errorf("HashAlgConsistency on sign-finish output: %v", err)
	}
}
