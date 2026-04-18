//go:build live

package crypto

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"fmt"
	"os"
	"testing"
	"time"
)

// Live tests — only run with `-tags=live`. They hit real public endpoints
// and are intentionally excluded from the default test run so offline
// builds stay green. Use them to shake out interop bugs against
// production TSAs before preprod.
//
// Example:
//
//   go test -tags=live -v -run TestAMATSA ./internal/crypto/...
//
// The AMA TSA accepts anonymous requests, so no credentials are required.
// The request carries a synthetic digest — nothing is actually signed by
// the caller; we're only exercising the RFC 3161 client plumbing.

const amaTSAURL = "http://ts.cartaodecidadao.pt/tsa/v2"

// TestAMATSA_HappyPath POSTs a single TimeStampReq to the AMA public TSA
// and walks the response through BuildTimeStampReq / FetchTimeStampToken /
// ParseTSTInfoFromToken / validateTSTInfo. A pass here proves the
// TSA-client layer works against the canonical PT production endpoint.
func TestAMATSA_HappyPath(t *testing.T) {
	// Allow override for preprod or alternate TSAs without editing code.
	url := os.Getenv("PDFSIGNER_LIVE_TSA_URL")
	if url == "" {
		url = amaTSAURL
	}

	digest := sha256.Sum256([]byte(fmt.Sprintf("live-test %d", time.Now().UnixNano())))
	reqDER, nonce, err := BuildTimeStampReq(digest[:], crypto.SHA256, true, true)
	if err != nil {
		t.Fatalf("BuildTimeStampReq: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	token, err := FetchTimeStampToken(ctx, url, reqDER, nonce)
	if err != nil {
		t.Fatalf("FetchTimeStampToken(%s): %v", url, err)
	}
	if len(token) == 0 {
		t.Fatal("TSA returned empty token")
	}

	tst, err := ParseTSTInfoFromToken(token)
	if err != nil {
		t.Fatalf("ParseTSTInfoFromToken: %v", err)
	}

	// Sanity — the TSA stamped the digest we sent, at roughly the current
	// time, with our nonce echoed back (validateTSTInfo already checked
	// the last two; we log the genTime for operator visibility).
	if !bytes.Equal(tst.HashedMessage, digest[:]) {
		t.Errorf("messageImprint mismatch:\n  sent: %x\n  got:  %x", digest[:], tst.HashedMessage)
	}
	t.Logf("TSA %s issued token at %s (serial=%v, policy=%v, token size=%d bytes)",
		url, tst.GenTime.Format(time.RFC3339), tst.SerialNumber, tst.Policy, len(token))
}
