package pdf

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// ByteRange represents the two ranges of bytes to hash (everything except the /Contents placeholder).
type ByteRange struct {
	Offset1 int64
	Length1 int64
	Offset2 int64
	Length2 int64
}

func (br ByteRange) String() string {
	return fmt.Sprintf("[%d %d %d %d]", br.Offset1, br.Length1, br.Offset2, br.Length2)
}

// ErrPlaceholderTooSmall is returned by EmbedCMS when the CMS blob does not
// fit in the in-PDF signature placeholder. Callers (CLI) translate this into
// the PLACEHOLDER_TOO_SMALL error code and exit status 5.
var ErrPlaceholderTooSmall = errors.New("CMS signature exceeds placeholder capacity")

// findPlaceholderBounds locates the signature /Contents hex placeholder in
// data. The placeholder is a `<0000...0000>` hex string of even length
// chosen by the writer. We can't hard-code its size — callers may have
// requested a non-default placeholder via --placeholder-size — so we scan
// for any `<` followed by a run of zeros of even length ≥ minPlaceholderHex
// followed by `>`. The minimum length is 2 KB of hex (1 KB of CMS) to avoid
// false positives against short hex literals elsewhere in the PDF.
const minPlaceholderHex = 2048

func findPlaceholderBounds(data []byte) (start, end, hexLen int, err error) {
	i := 0
	for i < len(data) {
		lt := bytes.IndexByte(data[i:], '<')
		if lt < 0 {
			break
		}
		lt += i
		j := lt + 1
		for j < len(data) && data[j] == '0' {
			j++
		}
		if j < len(data) && data[j] == '>' {
			zeros := j - lt - 1
			if zeros >= minPlaceholderHex && zeros%2 == 0 {
				return lt, j + 1, zeros, nil
			}
		}
		i = lt + 1
	}
	return 0, 0, 0, fmt.Errorf("signature placeholder not found in PDF data")
}

// FindPlaceholder locates the signature /Contents hex placeholder in the PDF data
// and returns the ByteRange that describes the two segments to hash (everything
// outside the placeholder).
func FindPlaceholder(data []byte) (ByteRange, error) {
	start, end, _, err := findPlaceholderBounds(data)
	if err != nil {
		return ByteRange{}, err
	}
	length1 := int64(start)
	offset2 := int64(end)
	length2 := int64(len(data)) - offset2
	return ByteRange{
		Offset1: 0,
		Length1: length1,
		Offset2: offset2,
		Length2: length2,
	}, nil
}

// HashByteRanges computes SHA-256 over data[0:length1] + data[offset2:offset2+length2].
//
// Invariants enforced (not just assumed):
//   - Offset1 must be 0 (the PDF spec mandates range 1 start at the file start).
//   - All lengths/offsets must be non-negative.
//   - Range 2 must begin at or after the end of range 1 — no overlap, no
//     out-of-order ranges. Once Verify is wired up, the ByteRange comes from
//     the untrusted signature dict; a crafted overlap would double-hash bytes
//     and change the digest.
//   - Offset2 + Length2 must fit in int64 AND not run past end-of-data.
//
// Returns an error rather than panicking on any violation.
func HashByteRanges(data []byte, br ByteRange) ([]byte, error) {
	if br.Offset1 != 0 {
		return nil, fmt.Errorf("byte range requires Offset1=0, got %d", br.Offset1)
	}
	if br.Length1 < 0 || br.Offset2 < 0 || br.Length2 < 0 {
		return nil, fmt.Errorf("byte range has negative component: %s", br)
	}
	if br.Length1 > int64(len(data)) {
		return nil, fmt.Errorf("byte range length1 %d exceeds data length %d", br.Length1, len(data))
	}
	if br.Offset2 < br.Length1 {
		return nil, fmt.Errorf("byte range 2 (offset %d) overlaps range 1 (length %d)", br.Offset2, br.Length1)
	}
	// length2 <= len(data) - offset2, written as subtraction to avoid int64 overflow.
	if br.Length2 > int64(len(data))-br.Offset2 {
		return nil, fmt.Errorf("byte range 2 runs past end of data: offset2=%d length2=%d dataLen=%d", br.Offset2, br.Length2, len(data))
	}
	h := sha256.New()
	h.Write(data[0:br.Length1])
	h.Write(data[br.Offset2 : br.Offset2+br.Length2])
	return h.Sum(nil), nil
}

// EmbedCMS replaces the hex zero placeholder in data with the hex-encoded CMS
// signature. The placeholder size is detected from data, so non-default
// --placeholder-size values are honoured automatically. If the CMS bytes
// exceed the detected placeholder capacity, ErrPlaceholderTooSmall is wrapped
// with context and returned.
func EmbedCMS(data []byte, cms []byte) ([]byte, error) {
	start, _, hexLen, err := findPlaceholderBounds(data)
	if err != nil {
		return nil, err
	}
	placeholderCap := hexLen / 2
	if len(cms) > placeholderCap {
		return nil, fmt.Errorf("%w: have %d bytes, capacity %d", ErrPlaceholderTooSmall, len(cms), placeholderCap)
	}
	hexCMS := hex.EncodeToString(cms)
	if pad := hexLen - len(hexCMS); pad > 0 {
		hexCMS += strings.Repeat("0", pad)
	}
	result := make([]byte, len(data))
	copy(result, data)
	copy(result[start+1:start+1+hexLen], []byte(hexCMS))
	return result, nil
}
