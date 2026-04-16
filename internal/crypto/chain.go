package crypto

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/flyzard/pdf-signer/internal/certs"
)

// Shared HTTP clients for connection reuse across calls.
var (
	httpClient10s = &http.Client{Timeout: 10 * time.Second}
	httpClient30s = &http.Client{Timeout: 30 * time.Second}
)

// ChainResult holds the result of a certificate chain build.
type ChainResult struct {
	Certificates []*x509.Certificate // Leaf -> ... -> Root
	IsComplete   bool                // True if chain reaches a trusted root
}

// BuildChain walks the AIA (Authority Info Access) extensions to build the
// full certificate chain starting from leaf. Max depth is 10.
func BuildChain(leaf *x509.Certificate) (*ChainResult, error) {
	const maxDepth = 10

	result := &ChainResult{}
	roots := certs.PortugueseRoots()

	seen := make(map[[32]byte]bool)
	current := leaf

	for depth := 0; depth < maxDepth; depth++ {
		// Track fingerprint to detect cycles
		fp := sha256.Sum256(current.Raw)
		if seen[fp] {
			break
		}
		seen[fp] = true
		result.Certificates = append(result.Certificates, current)

		// Check if current cert verifies against trusted roots
		opts := x509.VerifyOptions{
			Roots: roots,
		}
		_, err := current.Verify(opts)
		if err == nil {
			result.IsComplete = true
			return result, nil
		}

		// Check if self-signed (IsCA and raw subject == raw issuer)
		if current.IsCA && bytes.Equal(current.RawSubject, current.RawIssuer) {
			result.IsComplete = true
			return result, nil
		}

		// Try to fetch issuer via AIA
		if len(current.IssuingCertificateURL) == 0 {
			// No AIA URLs — chain is incomplete
			result.IsComplete = false
			return result, nil
		}

		var issuer *x509.Certificate
		var fetchErr error
		for _, url := range current.IssuingCertificateURL {
			issuer, fetchErr = fetchCert(url)
			if fetchErr == nil {
				break
			}
		}

		if fetchErr != nil || issuer == nil {
			// Could not fetch any issuer
			result.IsComplete = false
			return result, nil
		}

		current = issuer
	}

	result.IsComplete = false
	return result, nil
}

// fetchCert fetches a DER-encoded certificate from the given URL.
func fetchCert(url string) (*x509.Certificate, error) {
	if err := validateFetchURL(url); err != nil {
		return nil, fmt.Errorf("unsafe URL %s: %w", url, err)
	}
	resp, err := httpClient10s.Get(url)
	if err != nil {
		return nil, fmt.Errorf("fetching cert from %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetching cert from %s: HTTP %d", url, resp.StatusCode)
	}

	const maxSize = 1 << 20 // 1 MB
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxSize))
	if err != nil {
		return nil, fmt.Errorf("reading cert from %s: %w", url, err)
	}

	cert, err := x509.ParseCertificate(raw)
	if err != nil {
		return nil, fmt.Errorf("parsing cert from %s: %w", url, err)
	}

	return cert, nil
}
