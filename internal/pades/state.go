package pades

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/flyzard/pdf-signer/internal/pdf"
)

// StateVersion is the format-version stamp on every on-disk state token.
// Bumps only on a breaking change to the JSON shape; additive fields keep
// the same string. sign-finish refuses any state whose version it does not
// recognise.
const StateVersion = "1.0"

// DefaultStateTTL is the expiry window sign-start applies when the caller
// did not pass --state-ttl. 24h matches R-8.4.4.5. AMA OTP flows complete
// in seconds; 24h is a generous safety margin for retries and offline
// handoffs without becoming a DoS vector (old state files eventually
// self-reject).
const DefaultStateTTL = 24 * time.Hour

// InlinePDFMaxBytes is the cut-off at which sign-start embeds the prepared
// PDF as base64 inside the state file instead of writing it as a separate
// file. 2 MB keeps the state JSON small enough to ship via stdout/stdin
// transport (Open Question #11) if that's ever enabled, while covering the
// vast majority of atas/meeting-minutes documents.
const InlinePDFMaxBytes = 2 * 1024 * 1024

// SignatureAlgorithmString enumerates the allowed --signature-algorithm
// values. The string is what gets written into the state file; sign-finish
// re-derives the Go SignatureAlgorithm constant from it.
const (
	SigAlgStrRSAPKCS1v15 = "RSA-PKCS1-v1_5"
	SigAlgStrRSAPSS      = "RSA-PSS"
	SigAlgStrECDSA       = "ECDSA"
	SigAlgStrEd25519     = "Ed25519"
)

// State is the on-disk state-token format consumed by sign-finish. All
// binary fields are base64-encoded so the file round-trips through text
// tooling (`jq`, `cat`) without byte loss. Times are RFC 3339 UTC.
type State struct {
	StateVersion        string `json:"state_version"`
	StateID             string `json:"state_id"`
	CreatedAt           string `json:"created_at"`
	ExpiresAt           string `json:"expires_at"`
	PreparedPDFBase64   string `json:"prepared_pdf_b64,omitempty"`
	PreparedPDFPath     string `json:"prepared_pdf_path,omitempty"`
	SignedAttrsDERB64   string `json:"signed_attrs_der_b64"`
	SignerCertDERB64    string `json:"signer_cert_der_b64"`
	PlaceholderOffset   int    `json:"placeholder_offset"`
	PlaceholderSize     int    `json:"placeholder_size"`
	FieldName           string `json:"field_name"`
	PAdESLevel          string `json:"pades_level"`
	TSAURL              string `json:"tsa_url,omitempty"`
	DigestAlgorithm     string `json:"digest_algorithm"`
	SignatureAlgorithm  string `json:"signature_algorithm"`
}

// NewStateID returns a random 128-bit state identifier encoded as
// lower-case hex. Uses crypto/rand; avoids a ULID/UUID dependency while
// still giving operators a stable, copy-pasteable handle for logs. Call
// sites pass this into State.StateID.
func NewStateID() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("state id: %w", err)
	}
	return hex.EncodeToString(buf), nil
}

// NewStateOptions assembles a fresh State. Exactly one of PreparedPDF
// (bytes) or PreparedPDFPath (on-disk reference) must be set; see
// InlinePDFMaxBytes for the inline cut-off. TTL <= 0 means DefaultStateTTL.
type NewStateOptions struct {
	StateID            string
	PreparedPDF        []byte
	PreparedPDFPath    string
	SignedAttrsDER     []byte
	SignerCertDER      []byte
	PlaceholderOffset  int
	PlaceholderSize    int
	FieldName          string
	PAdESLevel         string
	TSAURL             string
	DigestAlgorithm    string
	SignatureAlgorithm string
	TTL                time.Duration
}

// NewState assembles a fresh state struct from opts.
func NewState(opts NewStateOptions) (*State, error) {
	if opts.TTL <= 0 {
		opts.TTL = DefaultStateTTL
	}
	now := time.Now().UTC()
	s := &State{
		StateVersion:       StateVersion,
		StateID:            opts.StateID,
		CreatedAt:          now.Format(time.RFC3339),
		ExpiresAt:          now.Add(opts.TTL).Format(time.RFC3339),
		SignedAttrsDERB64:  base64.StdEncoding.EncodeToString(opts.SignedAttrsDER),
		SignerCertDERB64:   base64.StdEncoding.EncodeToString(opts.SignerCertDER),
		PlaceholderOffset:  opts.PlaceholderOffset,
		PlaceholderSize:    opts.PlaceholderSize,
		FieldName:          opts.FieldName,
		PAdESLevel:         opts.PAdESLevel,
		TSAURL:             opts.TSAURL,
		DigestAlgorithm:    opts.DigestAlgorithm,
		SignatureAlgorithm: opts.SignatureAlgorithm,
	}
	switch {
	case len(opts.PreparedPDF) > 0 && opts.PreparedPDFPath != "":
		return nil, fmt.Errorf("state: set exactly one of PreparedPDF bytes or PreparedPDFPath")
	case len(opts.PreparedPDF) > 0:
		s.PreparedPDFBase64 = base64.StdEncoding.EncodeToString(opts.PreparedPDF)
	case opts.PreparedPDFPath != "":
		s.PreparedPDFPath = opts.PreparedPDFPath
	default:
		return nil, fmt.Errorf("state: no prepared PDF reference (neither bytes nor path)")
	}
	return s, nil
}

// Write serialises s as indented JSON and atomically writes it to path at
// 0600. DER-encoded signedAttrs isn't catastrophic to leak (no private
// key) but is metadata-sensitive, so tight perms are load-bearing.
func (s *State) Write(path string) error {
	raw, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("state marshal: %w", err)
	}
	return pdf.WriteFileAtomicMode(path, raw, 0600)
}

// LoadState reads and validates a state file. Errors distinguish parse
// from structural failures; sign-finish surfaces the exact cause to the
// caller so debugging doesn't require re-running sign-start.
func LoadState(path string) (*State, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("state read: %w", err)
	}
	var s State
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, fmt.Errorf("state parse: %w", err)
	}
	if err := s.Validate(); err != nil {
		return nil, err
	}
	return &s, nil
}

// Validate enforces structural + expiry invariants before sign-finish
// touches any crypto. Called by LoadState; exported for unit testing.
func (s *State) Validate() error {
	if s.StateVersion != StateVersion {
		return fmt.Errorf("state: unsupported version %q (want %q)", s.StateVersion, StateVersion)
	}
	if s.StateID == "" {
		return fmt.Errorf("state: state_id is empty")
	}
	if s.SignedAttrsDERB64 == "" || s.SignerCertDERB64 == "" {
		return fmt.Errorf("state: signed_attrs_der_b64 or signer_cert_der_b64 missing")
	}
	if s.PreparedPDFBase64 == "" && s.PreparedPDFPath == "" {
		return fmt.Errorf("state: no prepared PDF reference")
	}
	if s.PreparedPDFBase64 != "" && s.PreparedPDFPath != "" {
		return fmt.Errorf("state: set exactly one of prepared_pdf_b64 or prepared_pdf_path")
	}
	if s.PlaceholderSize < pdf.MinPlaceholderSize || s.PlaceholderSize > pdf.MaxPlaceholderSize {
		return fmt.Errorf("state: placeholder_size %d out of range", s.PlaceholderSize)
	}
	expiry, err := time.Parse(time.RFC3339, s.ExpiresAt)
	if err != nil {
		return fmt.Errorf("state: parse expires_at: %w", err)
	}
	if time.Now().After(expiry) {
		return fmt.Errorf("state: expired at %s", s.ExpiresAt)
	}
	return nil
}

// LoadPreparedPDF returns the prepared PDF bytes referenced by the state,
// either decoded from the inline base64 blob or read from the external
// file. Returned bytes are safe to mutate (copy of the decoded payload).
func (s *State) LoadPreparedPDF() ([]byte, error) {
	if s.PreparedPDFBase64 != "" {
		b, err := base64.StdEncoding.DecodeString(s.PreparedPDFBase64)
		if err != nil {
			return nil, fmt.Errorf("state: decode prepared PDF: %w", err)
		}
		return b, nil
	}
	if s.PreparedPDFPath != "" {
		return os.ReadFile(s.PreparedPDFPath)
	}
	return nil, fmt.Errorf("state: no prepared PDF reference")
}

// DecodeSignedAttrs / DecodeSignerCert / DecodeX509Cert are helpers so the
// CLI layer never has to touch base64 directly.
func (s *State) DecodeSignedAttrs() ([]byte, error) {
	return base64.StdEncoding.DecodeString(s.SignedAttrsDERB64)
}
