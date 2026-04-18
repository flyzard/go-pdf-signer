package pades

import "fmt"

// PAdESLevel enumerates the four ETSI EN 319 142-1 signature levels this
// binary can produce. Callers that would otherwise switch on raw strings
// ("B-T","B-LT","B-LTA") should use the typed value so a typo is a
// compile error, not a silent miss.
type PAdESLevel string

const (
	LevelBB   PAdESLevel = "B-B"
	LevelBT   PAdESLevel = "B-T"
	LevelBLT  PAdESLevel = "B-LT"
	LevelBLTA PAdESLevel = "B-LTA"
)

// ParseLevel maps the CLI-facing string to a PAdESLevel, refusing any
// value outside the four published levels.
func ParseLevel(s string) (PAdESLevel, error) {
	switch PAdESLevel(s) {
	case LevelBB, LevelBT, LevelBLT, LevelBLTA:
		return PAdESLevel(s), nil
	}
	return "", fmt.Errorf("unknown PAdES level %q (want B-B|B-T|B-LT|B-LTA)", s)
}

// NeedsTSA reports whether the level requires a TSA-issued signature
// timestamp token in unsignedAttrs. True for B-T and above.
func (l PAdESLevel) NeedsTSA() bool {
	return l == LevelBT || l == LevelBLT || l == LevelBLTA
}

// NeedsDSS reports whether the level requires a post-embed DSS
// incremental update with chain/OCSP/CRL validation data. True for B-LT
// and above.
func (l PAdESLevel) NeedsDSS() bool {
	return l == LevelBLT || l == LevelBLTA
}

// NeedsDocTimeStamp reports whether the level requires an appended
// DocTimeStamp signature as a further incremental update. True for
// B-LTA only.
func (l PAdESLevel) NeedsDocTimeStamp() bool {
	return l == LevelBLTA
}

// String satisfies fmt.Stringer so PAdESLevel prints as the CLI-facing
// token ("B-LT") rather than the Go name.
func (l PAdESLevel) String() string { return string(l) }
