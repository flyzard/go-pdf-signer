package pades

import (
	"fmt"
	"math"

	"github.com/flyzard/pdf-signer/internal/pdf"
)

// parseSigByteRange decodes a signature dict's /ByteRange array into a
// pdf.ByteRange. The /ByteRange must be present, hold exactly four numeric
// entries, and each entry must be a non-fractional number in int64 range.
func parseSigByteRange(sig pdf.Dict) (pdf.ByteRange, error) {
	arr, ok := sig.GetArray("ByteRange")
	if !ok {
		return pdf.ByteRange{}, fmt.Errorf("/ByteRange missing or not an array")
	}
	if len(arr) != 4 {
		return pdf.ByteRange{}, fmt.Errorf("/ByteRange has %d entries, want 4", len(arr))
	}
	nums := make([]int64, 4)
	for i, v := range arr {
		n, err := toInt64(v)
		if err != nil {
			return pdf.ByteRange{}, fmt.Errorf("/ByteRange[%d]: %w", i, err)
		}
		nums[i] = n
	}
	return pdf.ByteRange{
		Offset1: nums[0],
		Length1: nums[1],
		Offset2: nums[2],
		Length2: nums[3],
	}, nil
}

// toInt64 coerces a PDF-parsed numeric value into int64, rejecting
// non-integers, NaN, Inf, or values outside int64 range.
func toInt64(v any) (int64, error) {
	switch t := v.(type) {
	case int:
		return int64(t), nil
	case int64:
		return t, nil
	case float64:
		if math.IsNaN(t) || math.IsInf(t, 0) {
			return 0, fmt.Errorf("non-finite number %v", t)
		}
		if t != math.Trunc(t) {
			return 0, fmt.Errorf("fractional number %v", t)
		}
		if t < math.MinInt64 || t > math.MaxInt64 {
			return 0, fmt.Errorf("out-of-int64 number %v", t)
		}
		return int64(t), nil
	}
	return 0, fmt.Errorf("not numeric: %T", v)
}

// validateByteRangeCoversEntireFile asserts the byte range is well-formed and
// — crucially — that Offset2+Length2 equals the total file length. That
// equality is what stops an attacker from appending a forged incremental
// update after the signed region and having it ignored by the verifier.
func validateByteRangeCoversEntireFile(br pdf.ByteRange, dataLen int64) error {
	if br.Offset1 != 0 {
		return fmt.Errorf("byte range Offset1=%d, want 0", br.Offset1)
	}
	if br.Length1 < 0 || br.Offset2 < 0 || br.Length2 < 0 {
		return fmt.Errorf("byte range has negative component: %s", br)
	}
	if br.Offset2 < br.Length1 {
		return fmt.Errorf("byte range 2 (offset=%d) overlaps range 1 (length=%d)", br.Offset2, br.Length1)
	}
	// Use subtraction to avoid overflow: Length2 == dataLen - Offset2 ⇔ Offset2+Length2==dataLen.
	if br.Length2 != dataLen-br.Offset2 {
		return fmt.Errorf("byte range does not cover full file: offset2=%d length2=%d dataLen=%d", br.Offset2, br.Length2, dataLen)
	}
	return nil
}
