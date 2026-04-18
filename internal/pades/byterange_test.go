package pades

import (
	"testing"

	"github.com/flyzard/pdf-signer/internal/pdf"
)

func TestParseSigByteRangeAcceptsFourInts(t *testing.T) {
	sig := pdf.Dict{"ByteRange": []any{0, 100, 150, 200}}
	br, err := parseSigByteRange(sig)
	if err != nil {
		t.Fatalf("parseSigByteRange: %v", err)
	}
	if br.Length1 != 100 || br.Offset2 != 150 || br.Length2 != 200 {
		t.Errorf("unexpected range: %s", br)
	}
}

func TestParseSigByteRangeRejectsMissing(t *testing.T) {
	if _, err := parseSigByteRange(pdf.Dict{}); err == nil {
		t.Fatal("expected error when /ByteRange missing")
	}
}

func TestParseSigByteRangeRejectsWrongLength(t *testing.T) {
	sig := pdf.Dict{"ByteRange": []any{0, 100, 150}}
	if _, err := parseSigByteRange(sig); err == nil {
		t.Fatal("expected error when /ByteRange has 3 entries")
	}
}

func TestParseSigByteRangeRejectsNonNumeric(t *testing.T) {
	sig := pdf.Dict{"ByteRange": []any{0, "abc", 150, 200}}
	if _, err := parseSigByteRange(sig); err == nil {
		t.Fatal("expected error on non-numeric entry")
	}
}

func TestValidateByteRangeAcceptsFullCoverage(t *testing.T) {
	br := pdf.ByteRange{Offset1: 0, Length1: 100, Offset2: 150, Length2: 50}
	// dataLen = 200 → offset2+length2 = 200 ✓
	if err := validateByteRangeCoversEntireFile(br, 200); err != nil {
		t.Errorf("valid range rejected: %v", err)
	}
}

func TestValidateByteRangeRejectsTrailingData(t *testing.T) {
	br := pdf.ByteRange{Offset1: 0, Length1: 100, Offset2: 150, Length2: 50}
	// dataLen = 300 → 50 bytes of trailing unsigned content.
	if err := validateByteRangeCoversEntireFile(br, 300); err == nil {
		t.Fatal("expected error: range does not reach EOF")
	}
}

func TestValidateByteRangeRejectsOverlap(t *testing.T) {
	br := pdf.ByteRange{Offset1: 0, Length1: 100, Offset2: 80, Length2: 120}
	if err := validateByteRangeCoversEntireFile(br, 200); err == nil {
		t.Fatal("expected error on overlapping ranges")
	}
}

func TestValidateByteRangeRejectsNonZeroOffset1(t *testing.T) {
	br := pdf.ByteRange{Offset1: 10, Length1: 90, Offset2: 150, Length2: 50}
	if err := validateByteRangeCoversEntireFile(br, 200); err == nil {
		t.Fatal("expected error on Offset1 != 0")
	}
}
