package pdf

import (
	"math"
	"testing"
)

func TestHashByteRangesRejectsNonZeroOffset1(t *testing.T) {
	data := make([]byte, 100)
	br := ByteRange{Offset1: 1, Length1: 10, Offset2: 50, Length2: 40}
	if _, err := HashByteRanges(data, br); err == nil {
		t.Fatal("expected error for Offset1 != 0, got nil")
	}
}

func TestHashByteRangesRejectsOverlappingRanges(t *testing.T) {
	data := make([]byte, 100)
	// Range 1 ends at 50; range 2 starts at 40 — overlap.
	br := ByteRange{Offset1: 0, Length1: 50, Offset2: 40, Length2: 30}
	if _, err := HashByteRanges(data, br); err == nil {
		t.Fatal("expected error for overlapping ranges, got nil")
	}
}

func TestHashByteRangesRejectsLength2Overflow(t *testing.T) {
	data := make([]byte, 100)
	// Offset2 + Length2 overflows int64 — must be rejected without panicking.
	br := ByteRange{Offset1: 0, Length1: 10, Offset2: math.MaxInt64 - 5, Length2: 100}
	if _, err := HashByteRanges(data, br); err == nil {
		t.Fatal("expected error for length2 overflow, got nil")
	}
}

func TestHashByteRangesAcceptsAdjacentRanges(t *testing.T) {
	data := make([]byte, 100)
	// Range 1 = [0,40); range 2 = [60,100). 20-byte gap simulating placeholder.
	br := ByteRange{Offset1: 0, Length1: 40, Offset2: 60, Length2: 40}
	if _, err := HashByteRanges(data, br); err != nil {
		t.Fatalf("valid ranges should hash cleanly: %v", err)
	}
}

func TestHashByteRangesRejectsNegativeOffset1(t *testing.T) {
	data := make([]byte, 100)
	br := ByteRange{Offset1: -1, Length1: 10, Offset2: 50, Length2: 40}
	if _, err := HashByteRanges(data, br); err == nil {
		t.Fatal("expected error for Offset1 < 0, got nil")
	}
}
