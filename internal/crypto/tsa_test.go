package crypto

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"
)

// TestBuildTimeStampReqStructure verifies BuildTimeStampReq emits a DER
// SEQUENCE with the expected version and hash algorithm, and that nonce
// generation works when includeNonce=true.
func TestBuildTimeStampReqStructure(t *testing.T) {
	digest := sha256.Sum256([]byte("test"))
	reqDER, nonce, err := BuildTimeStampReq(digest[:], crypto.SHA256, true, true)
	if err != nil {
		t.Fatalf("BuildTimeStampReq: %v", err)
	}
	if nonce == nil || nonce.Sign() == 0 {
		t.Fatalf("nonce should be non-zero when requested, got %v", nonce)
	}

	var parsed timeStampReq
	if _, err := asn1.Unmarshal(reqDER, &parsed); err != nil {
		t.Fatalf("re-parse: %v", err)
	}
	if parsed.Version != 1 {
		t.Errorf("version = %d, want 1", parsed.Version)
	}
	if !parsed.MessageImprint.HashAlgorithm.Algorithm.Equal(oidTSADigestSHA256) {
		t.Errorf("hash alg = %v, want SHA-256", parsed.MessageImprint.HashAlgorithm.Algorithm)
	}
	if !bytes.Equal(parsed.MessageImprint.HashedMessage, digest[:]) {
		t.Errorf("message imprint digest mismatch")
	}
	if !parsed.CertReq {
		t.Errorf("certReq should be true")
	}
	if parsed.Nonce == nil || parsed.Nonce.Cmp(nonce) != 0 {
		t.Errorf("nonce round-trip mismatch")
	}
}

func TestBuildTimeStampReqNoNonce(t *testing.T) {
	digest := sha256.Sum256([]byte("x"))
	reqDER, nonce, err := BuildTimeStampReq(digest[:], crypto.SHA256, false, false)
	if err != nil {
		t.Fatalf("BuildTimeStampReq: %v", err)
	}
	if nonce != nil {
		t.Fatalf("nonce should be nil when includeNonce=false, got %v", nonce)
	}
	var parsed timeStampReq
	if _, err := asn1.Unmarshal(reqDER, &parsed); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if parsed.Nonce != nil {
		t.Errorf("parsed nonce should be nil, got %v", parsed.Nonce)
	}
}

// TestValidateTSTInfoRejectsFutureGenTime locks the clock-skew gate.
func TestValidateTSTInfoRejectsFutureGenTime(t *testing.T) {
	future := time.Now().Add(2 * DefaultTSAClockSkew)
	tst := &TSTInfo{GenTime: future, HashedMessage: []byte("x")}
	if err := validateTSTInfo(tst, nil); err == nil {
		t.Fatal("expected future-genTime rejection")
	}
}

func TestValidateTSTInfoAcceptsSmallSkew(t *testing.T) {
	slightlyFuture := time.Now().Add(DefaultTSAClockSkew / 2)
	tst := &TSTInfo{GenTime: slightlyFuture, HashedMessage: []byte("x")}
	if err := validateTSTInfo(tst, nil); err != nil {
		t.Fatalf("should tolerate %s skew: %v", DefaultTSAClockSkew/2, err)
	}
}

func TestValidateTSTInfoNonceEcho(t *testing.T) {
	tst := &TSTInfo{
		GenTime:       time.Now().Add(-time.Minute),
		HashedMessage: []byte("x"),
		Nonce:         big.NewInt(12345),
	}
	if err := validateTSTInfo(tst, big.NewInt(12345)); err != nil {
		t.Errorf("matching nonces should validate: %v", err)
	}
	if err := validateTSTInfo(tst, big.NewInt(99999)); err == nil {
		t.Errorf("mismatched nonce must be rejected")
	}
	// sent nonce but TSA dropped it → reject (RFC 3161 §2.4.1 says it's
	// optional, but when the caller asked, a missing echo is suspicious).
	tstNoNonce := &TSTInfo{
		GenTime:       time.Now().Add(-time.Minute),
		HashedMessage: []byte("x"),
	}
	if err := validateTSTInfo(tstNoNonce, big.NewInt(12345)); err == nil {
		t.Errorf("dropped nonce must be rejected when we asked for one")
	}
}

// TestTSAStatusNames keeps the text labels stable — callers include these
// in JSON error messages so a rename would surface in parent services.
func TestTSAStatusNames(t *testing.T) {
	cases := map[int]string{
		TSAStatusGranted:         "granted",
		TSAStatusGrantedWithMods: "grantedWithMods",
		TSAStatusRejection:       "rejection",
		99:                       "unknown",
	}
	for code, want := range cases {
		if got := tsaStatusName(code); got != want {
			t.Errorf("tsaStatusName(%d) = %q, want %q", code, got, want)
		}
	}
}

// Sanity that timeStampResp decodes the status shape we expect when a
// hand-assembled rejection comes back — exercises the asn1 tags without
// needing a real TSA.
func TestTimeStampRespStatusParse(t *testing.T) {
	failInfo := asn1.BitString{Bytes: []byte{0x80}, BitLength: 1}
	statusInfo := pkiStatusInfo{
		Status:       TSAStatusRejection,
		StatusString: []string{"bad request"},
		FailInfo:     failInfo,
	}
	resp := timeStampResp{Status: statusInfo}
	der, err := asn1.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var back timeStampResp
	if _, err := asn1.Unmarshal(der, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back.Status.Status != TSAStatusRejection {
		t.Errorf("status round-trip: got %d", back.Status.Status)
	}
	if len(back.Status.StatusString) != 1 || back.Status.StatusString[0] != "bad request" {
		t.Errorf("statusString round-trip: %v", back.Status.StatusString)
	}
}

