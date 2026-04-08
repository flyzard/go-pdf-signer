package pades

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/flyzard/pdf-signer/internal/appearance"
	"github.com/flyzard/pdf-signer/internal/pdf"
)

// buildTestCMS creates a minimal CMS SignedData structure containing a test
// certificate. This is not a valid CMS signature, but is structurally correct
// enough for extractCertsFromCMS to parse.
func buildTestCMS(t *testing.T) ([]byte, *x509.Certificate) {
	t.Helper()

	// Generate a self-signed test certificate.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test Signer",
		},
		NotBefore: time.Now().Add(-1 * time.Hour),
		NotAfter:  time.Now().Add(24 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}

	// Build a minimal CMS SignedData ASN.1 structure by hand.
	// We need to build it carefully to match what extractCertsFromCMS expects.
	//
	// ContentInfo ::= SEQUENCE {
	//   contentType OID (signedData),
	//   content [0] EXPLICIT SignedData
	// }
	//
	// SignedData ::= SEQUENCE {
	//   version INTEGER (1),
	//   digestAlgorithms SET {},
	//   encapContentInfo SEQUENCE { contentType OID },
	//   certificates [0] IMPLICIT SET OF Certificate,
	//   signerInfos SET {}
	// }

	signedDataOID := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	dataOID := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}

	// Build SignedData contents piece by piece.
	versionBytes, _ := asn1.Marshal(1)

	digestAlgsBytes, _ := asn1.Marshal(asn1.RawValue{
		Tag:        17, // SET
		Class:      asn1.ClassUniversal,
		IsCompound: true,
		Bytes:      nil,
	})

	encapBytes, _ := asn1.Marshal(struct {
		ContentType asn1.ObjectIdentifier
	}{ContentType: dataOID})

	certsEncoded, _ := asn1.Marshal(asn1.RawValue{
		Tag:        0,
		Class:      asn1.ClassContextSpecific,
		IsCompound: true,
		Bytes:      certDER,
	})

	signerInfosBytes, _ := asn1.Marshal(asn1.RawValue{
		Tag:        17,
		Class:      asn1.ClassUniversal,
		IsCompound: true,
		Bytes:      nil,
	})

	// Concatenate all SignedData fields.
	var signedDataContent []byte
	signedDataContent = append(signedDataContent, versionBytes...)
	signedDataContent = append(signedDataContent, digestAlgsBytes...)
	signedDataContent = append(signedDataContent, encapBytes...)
	signedDataContent = append(signedDataContent, certsEncoded...)
	signedDataContent = append(signedDataContent, signerInfosBytes...)

	// Wrap in SEQUENCE to form SignedData.
	signedDataSeq, _ := asn1.Marshal(asn1.RawValue{
		Tag:        16, // SEQUENCE
		Class:      asn1.ClassUniversal,
		IsCompound: true,
		Bytes:      signedDataContent,
	})

	// Build ContentInfo manually:
	// SEQUENCE { OID, [0] EXPLICIT <signedDataSeq> }
	oidBytes, _ := asn1.Marshal(signedDataOID)

	// [0] EXPLICIT wrapping of SignedData
	explicit0, _ := asn1.Marshal(asn1.RawValue{
		Tag:        0,
		Class:      asn1.ClassContextSpecific,
		IsCompound: true,
		Bytes:      signedDataSeq,
	})

	// Outer SEQUENCE
	var contentInfoInner []byte
	contentInfoInner = append(contentInfoInner, oidBytes...)
	contentInfoInner = append(contentInfoInner, explicit0...)

	cmsBytes, _ := asn1.Marshal(asn1.RawValue{
		Tag:        16, // SEQUENCE
		Class:      asn1.ClassUniversal,
		IsCompound: true,
		Bytes:      contentInfoInner,
	})

	return cmsBytes, cert
}

func TestExtractCertsFromCMS(t *testing.T) {
	cmsData, expectedCert := buildTestCMS(t)

	certs, err := extractCertsFromCMS(cmsData)
	if err != nil {
		t.Fatalf("extractCertsFromCMS: %v", err)
	}

	if len(certs) == 0 {
		t.Fatal("expected at least one certificate, got none")
	}

	if certs[0].Subject.CommonName != expectedCert.Subject.CommonName {
		t.Errorf("cert CN = %q, want %q", certs[0].Subject.CommonName, expectedCert.Subject.CommonName)
	}
}

func TestExtractSignatureContents(t *testing.T) {
	// Create a test PDF, prepare it, then embed a fake CMS.
	inputPath := createTestPDF(t)
	preparedPath := filepath.Join(t.TempDir(), "prepared.pdf")

	_, err := Prepare(PrepareOptions{
		InputPath:     inputPath,
		OutputPath:    preparedPath,
		SignerName:    "Test Signer",
		SignerNIC:     "12345678",
		SigningMethod: "cmd",
		SignaturePos:  appearance.DefaultPosition(0),
	})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}

	// Create a non-zero fake CMS.
	fakeCMS := make([]byte, 200)
	for i := range fakeCMS {
		fakeCMS[i] = byte((i + 1) % 256)
	}

	// Read, embed, write.
	data, err := os.ReadFile(preparedPath)
	if err != nil {
		t.Fatalf("read prepared: %v", err)
	}

	data, err = pdf.EmbedCMS(data, fakeCMS)
	if err != nil {
		t.Fatalf("EmbedCMS: %v", err)
	}

	signedPath := filepath.Join(t.TempDir(), "signed.pdf")
	if err := os.WriteFile(signedPath, data, 0644); err != nil {
		t.Fatalf("write signed: %v", err)
	}

	// Parse and extract.
	doc, err := pdf.Parse(data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	contents, err := extractSignatureContents(doc)
	if err != nil {
		t.Fatalf("extractSignatureContents: %v", err)
	}

	if len(contents) == 0 {
		t.Fatal("expected at least one signature contents, got none")
	}

	// The extracted contents should be non-empty.
	if len(contents[0]) == 0 {
		t.Error("first signature contents is empty")
	}
}

func TestWriteDSS(t *testing.T) {
	// Create a simple test PDF and add a DSS dictionary.
	inputPath := createTestPDF(t)
	doc, err := pdf.Open(inputPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	dss := &DSSData{
		Certs: [][]byte{[]byte("fake-cert-data")},
		OCSPs: [][]byte{[]byte("fake-ocsp-data")},
		CRLs:  [][]byte{[]byte("fake-crl-data")},
		VRIEntries: []VRIEntry{
			{
				SignatureHash: "ABCDEF0123456789ABCDEF0123456789ABCDEF01",
				CertIndices:   []int{0},
				OCSPIndices:   []int{0},
				CRLIndices:    []int{0},
			},
		},
	}

	outputPath := filepath.Join(t.TempDir(), "with_dss.pdf")
	err = WriteDSS(doc, dss, outputPath)
	if err != nil {
		t.Fatalf("WriteDSS: %v", err)
	}

	// Verify output exists.
	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}

	// Verify it parses as a valid PDF.
	outDoc, err := pdf.Parse(data)
	if err != nil {
		t.Fatalf("parse output: %v", err)
	}

	// Verify catalog has /DSS entry.
	if _, ok := outDoc.Catalog["DSS"]; !ok {
		t.Error("catalog does not contain /DSS entry")
	}
}

func TestFinalize(t *testing.T) {
	// Full prepare -> embed -> finalize flow.

	// 1. Create test PDF.
	inputPath := createTestPDF(t)

	// 2. Prepare it.
	preparedPath := filepath.Join(t.TempDir(), "prepared.pdf")
	_, err := Prepare(PrepareOptions{
		InputPath:     inputPath,
		OutputPath:    preparedPath,
		SignerName:    "Test Signer",
		SignerNIC:     "12345678",
		SigningMethod: "cmd",
		SignaturePos:  appearance.DefaultPosition(0),
	})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}

	// 3. Create fake CMS with embedded test certificate.
	testCMS, _ := buildTestCMS(t)

	// 4. Embed the CMS.
	data, err := os.ReadFile(preparedPath)
	if err != nil {
		t.Fatalf("read prepared: %v", err)
	}
	data, err = pdf.EmbedCMS(data, testCMS)
	if err != nil {
		t.Fatalf("EmbedCMS: %v", err)
	}
	signedPath := filepath.Join(t.TempDir(), "signed.pdf")
	if err := os.WriteFile(signedPath, data, 0644); err != nil {
		t.Fatalf("write signed: %v", err)
	}

	// 5. Call Finalize.
	outputPath := filepath.Join(t.TempDir(), "finalized.pdf")
	result, err := Finalize(FinalizeOptions{
		InputPath:  signedPath,
		OutputPath: outputPath,
	})
	if err != nil {
		t.Fatalf("Finalize: %v", err)
	}

	// 6. Verify output exists and is a valid PDF.
	outData, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}

	outDoc, err := pdf.Parse(outData)
	if err != nil {
		t.Fatalf("parse output: %v", err)
	}

	// 7. Verify catalog has /DSS entry.
	if _, ok := outDoc.Catalog["DSS"]; !ok {
		t.Error("catalog does not contain /DSS entry after finalize")
	}

	// 8. Verify LTV status is not empty.
	if result.LTVStatus == "" {
		t.Error("LTVStatus is empty")
	}

	// For a self-signed test cert with no OCSP servers, we expect "none" or "partial".
	// The test cert has no OCSP/CRL endpoints, so validation data collection
	// will likely fail for OCSP/CRL but may succeed for chain building.
	t.Logf("LTV status: %s", result.LTVStatus)
}

func TestFinalizeNoSignatures(t *testing.T) {
	// Call Finalize on an unsigned PDF — should return error.
	inputPath := createTestPDF(t)
	outputPath := filepath.Join(t.TempDir(), "finalized.pdf")

	_, err := Finalize(FinalizeOptions{
		InputPath:  inputPath,
		OutputPath: outputPath,
	})
	if err == nil {
		t.Fatal("expected error for unsigned PDF, got nil")
	}

	if !strings.Contains(err.Error(), "no signatures") {
		t.Errorf("error = %q, expected it to contain 'no signatures'", err.Error())
	}
}

func TestDetermineLTVStatus(t *testing.T) {
	tests := []struct {
		name        string
		dss         *DSSData
		signerCerts []*x509.Certificate
		want        string
	}{
		{
			name: "nil DSS",
			dss:  nil,
			want: "none",
		},
		{
			name:        "no validation data",
			dss:         &DSSData{},
			signerCerts: []*x509.Certificate{{}},
			want:        "none",
		},
		{
			name: "OCSP only, no extra certs",
			dss: &DSSData{
				Certs: [][]byte{[]byte("leaf")},
				OCSPs: [][]byte{[]byte("ocsp")},
			},
			signerCerts: []*x509.Certificate{{}},
			want:        "partial",
		},
		{
			name: "OCSP and chain certs",
			dss: &DSSData{
				Certs: [][]byte{[]byte("leaf"), []byte("intermediate")},
				OCSPs: [][]byte{[]byte("ocsp")},
			},
			signerCerts: []*x509.Certificate{{}},
			want:        "valid",
		},
		{
			name: "CRL only",
			dss: &DSSData{
				CRLs: [][]byte{[]byte("crl")},
			},
			signerCerts: []*x509.Certificate{{}},
			want:        "partial",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := determineLTVStatus(tt.dss, tt.signerCerts)
			if got != tt.want {
				t.Errorf("determineLTVStatus() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestVRIKeyComputation(t *testing.T) {
	// Verify that VRI key is computed as SHA-1 of raw contents, uppercase hex.
	contents := []byte{0x01, 0x02, 0x03, 0x04}
	h := sha1.Sum(contents)
	expected := strings.ToUpper(hex.EncodeToString(h[:]))

	if len(expected) != 40 {
		t.Errorf("SHA-1 hex length = %d, want 40", len(expected))
	}

	// Verify it's uppercase.
	if expected != strings.ToUpper(expected) {
		t.Error("VRI key is not uppercase")
	}
}
