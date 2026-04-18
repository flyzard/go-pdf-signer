package pades

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestStateRoundTripInlinePDF(t *testing.T) {
	stateID, err := NewStateID()
	if err != nil {
		t.Fatalf("NewStateID: %v", err)
	}

	preparedPDF := []byte("%PDF-1.7\n...")
	signedAttrs := []byte{0xA0, 0x02, 0x31, 0x00}
	certDER := []byte{0x30, 0x82, 0x00, 0x00}

	s, err := NewState(NewStateOptions{
		StateID:            stateID,
		PreparedPDF:        preparedPDF,
		SignedAttrsDER:     signedAttrs,
		SignerCertDER:      certDER,
		PlaceholderOffset:  42,
		PlaceholderSize:    16384,
		FieldName:          "Sig_1",
		PAdESLevel:         "B-LT",
		TSAURL:             "http://ts.example/tsa",
		DigestAlgorithm:    "SHA-256",
		SignatureAlgorithm: SigAlgStrRSAPKCS1v15,
	})
	if err != nil {
		t.Fatalf("NewState: %v", err)
	}

	path := filepath.Join(t.TempDir(), "state.json")
	if err := s.Write(path); err != nil {
		t.Fatalf("Write: %v", err)
	}

	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("Lstat: %v", err)
	}
	// 0600 mode is load-bearing for state-token confidentiality.
	if info.Mode().Perm() != 0600 {
		t.Errorf("state perms = %o, want 0600", info.Mode().Perm())
	}

	loaded, err := LoadState(path)
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	if loaded.StateID != stateID {
		t.Errorf("state_id round-trip: got %q want %q", loaded.StateID, stateID)
	}
	if loaded.PlaceholderSize != 16384 {
		t.Errorf("placeholder_size round-trip: got %d", loaded.PlaceholderSize)
	}
	pdfBack, err := loaded.LoadPreparedPDF()
	if err != nil {
		t.Fatalf("LoadPreparedPDF: %v", err)
	}
	if string(pdfBack) != string(preparedPDF) {
		t.Errorf("prepared PDF round-trip mismatch: got %q", pdfBack)
	}
	sa, err := loaded.DecodeSignedAttrs()
	if err != nil {
		t.Fatalf("DecodeSignedAttrs: %v", err)
	}
	if string(sa) != string(signedAttrs) {
		t.Errorf("signedAttrs round-trip mismatch")
	}
}

func TestStateExpiredRejected(t *testing.T) {
	s := &State{
		StateVersion:       StateVersion,
		StateID:            "deadbeef",
		CreatedAt:          time.Now().Add(-48 * time.Hour).UTC().Format(time.RFC3339),
		ExpiresAt:          time.Now().Add(-time.Hour).UTC().Format(time.RFC3339),
		PreparedPDFBase64:  base64.StdEncoding.EncodeToString([]byte("x")),
		SignedAttrsDERB64:  base64.StdEncoding.EncodeToString([]byte{0xA0, 0}),
		SignerCertDERB64:   base64.StdEncoding.EncodeToString([]byte{0x30, 0}),
		PlaceholderOffset:  0,
		PlaceholderSize:    16384,
		FieldName:          "Sig_1",
		PAdESLevel:         "B-LT",
		DigestAlgorithm:    "SHA-256",
		SignatureAlgorithm: SigAlgStrRSAPKCS1v15,
	}
	if err := s.Validate(); err == nil {
		t.Fatal("Validate must reject expired state")
	}
}

func TestStateVersionMismatchRejected(t *testing.T) {
	s := &State{
		StateVersion:       "9.9",
		StateID:            "deadbeef",
		ExpiresAt:          time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
		PreparedPDFBase64:  base64.StdEncoding.EncodeToString([]byte("x")),
		SignedAttrsDERB64:  base64.StdEncoding.EncodeToString([]byte{0xA0, 0}),
		SignerCertDERB64:   base64.StdEncoding.EncodeToString([]byte{0x30, 0}),
		PlaceholderSize:    16384,
		FieldName:          "Sig_1",
		PAdESLevel:         "B-LT",
		DigestAlgorithm:    "SHA-256",
		SignatureAlgorithm: SigAlgStrRSAPKCS1v15,
	}
	if err := s.Validate(); err == nil {
		t.Fatal("Validate must reject unknown state_version")
	}
}

func TestStateBothInlineAndPathRejected(t *testing.T) {
	_, err := NewState(NewStateOptions{
		StateID:            "id",
		PreparedPDF:        []byte("x"),
		PreparedPDFPath:    "/tmp/also-set",
		SignedAttrsDER:     []byte{0xA0, 0},
		SignerCertDER:      []byte{0x30, 0},
		PlaceholderSize:    16384,
		FieldName:          "Sig_1",
		PAdESLevel:         "B-LT",
		DigestAlgorithm:    "SHA-256",
		SignatureAlgorithm: SigAlgStrRSAPKCS1v15,
	})
	if err == nil {
		t.Fatal("NewState must refuse both inline bytes and path")
	}
}
