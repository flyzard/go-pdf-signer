package pdf

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// ByteRange represents the two ranges of bytes to hash (everything except the /Contents placeholder).
type ByteRange struct {
	Offset1 int64
	Length1 int64
	Offset2 int64
	Length2 int64
}

func (br ByteRange) String() string {
	return fmt.Sprintf("[0 %d %d %d]", br.Length1, br.Offset2, br.Length2)
}

// FindPlaceholder locates the signature /Contents hex placeholder in the PDF data
// and returns the ByteRange that describes the two segments to hash (everything
// outside the placeholder).
func FindPlaceholder(data []byte) (ByteRange, error) {
	needle := []byte(SignaturePlaceholder())

	idx := bytes.Index(data, needle)
	if idx < 0 {
		return ByteRange{}, fmt.Errorf("signature placeholder not found in PDF data")
	}

	// offset1 = 0, length1 = index of '<'
	// offset2 = index after '>', length2 = total - offset2
	length1 := int64(idx)
	offset2 := int64(idx + len(needle))
	length2 := int64(len(data)) - offset2

	return ByteRange{
		Offset1: 0,
		Length1: length1,
		Offset2: offset2,
		Length2: length2,
	}, nil
}

// HashByteRanges computes SHA-256 over data[0:length1] + data[offset2:offset2+length2].
func HashByteRanges(data []byte, br ByteRange) []byte {
	h := sha256.New()
	h.Write(data[0:br.Length1])
	h.Write(data[br.Offset2 : br.Offset2+br.Length2])
	return h.Sum(nil)
}

// EmbedCMS replaces the hex zero placeholder in data with the hex-encoded CMS signature.
// If the CMS bytes exceed PlaceholderSize, an error is returned.
func EmbedCMS(data []byte, cms []byte) ([]byte, error) {
	if len(cms) > PlaceholderSize {
		return nil, fmt.Errorf("CMS signature (%d bytes) exceeds placeholder capacity (%d bytes)", len(cms), PlaceholderSize)
	}

	// Hex-encode the CMS and pad with zeros to PlaceholderHexLen.
	hexCMS := hex.EncodeToString(cms)
	for len(hexCMS) < PlaceholderHexLen {
		hexCMS += "0"
	}

	// Find the placeholder in the data.
	placeholder := []byte(SignaturePlaceholder())
	idx := bytes.Index(data, placeholder)
	if idx < 0 {
		return nil, fmt.Errorf("signature placeholder not found in PDF data")
	}

	// Replace the hex content between < and > (keeping the angle brackets).
	result := make([]byte, len(data))
	copy(result, data)
	copy(result[idx+1:idx+1+PlaceholderHexLen], []byte(hexCMS))

	return result, nil
}
