package crypto

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/flyzard/pdf-signer/internal/certs"
)

// sharedTransport pins DialContext to a resolver+validator that blocks
// DNS-rebinding attacks against private/loopback ranges. Both clients below
// share it so connections to a CA host stay pooled across cert/OCSP/CRL
// fetches.
var sharedTransport = &http.Transport{
	DialContext:         secureDialContext,
	MaxIdleConns:        100,
	MaxIdleConnsPerHost: 4,
	IdleConnTimeout:     90 * time.Second,
}

var (
	httpClient10s = &http.Client{Timeout: 10 * time.Second, Transport: sharedTransport}
	httpClient30s = &http.Client{Timeout: 30 * time.Second, Transport: sharedTransport}
)

// ChainResult holds the result of a certificate chain build.
type ChainResult struct {
	Certificates []*x509.Certificate // Leaf -> ... -> Root
	IsComplete   bool                // True if chain reaches a trusted root
}

// BuildChain walks the AIA (Authority Info Access) extensions to build the
// full certificate chain starting from leaf. Max depth is 10. AIA fetches
// retry up to 3 times with exponential backoff and respect ctx cancellation.
func BuildChain(ctx context.Context, leaf *x509.Certificate) (*ChainResult, error) {
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
		for _, url := range current.IssuingCertificateURL {
			var candidate *x509.Certificate
			err := withRetry(ctx, 3, 200*time.Millisecond, func() error {
				c, e := fetchCert(ctx, url)
				candidate = c
				return e
			})
			if err != nil {
				continue
			}
			// Require the candidate to be permitted to sign certificates —
			// CheckSignatureFrom alone doesn't enforce basic constraints or
			// key usage, so a tampered AIA could otherwise hand us a leaf cert
			// with the right public key but no CA status.
			if !candidate.IsCA {
				continue
			}
			if candidate.KeyUsage != 0 && candidate.KeyUsage&x509.KeyUsageCertSign == 0 {
				continue
			}
			if err := current.CheckSignatureFrom(candidate); err != nil {
				continue
			}
			issuer = candidate
			break
		}

		if issuer == nil {
			result.IsComplete = false
			return result, nil
		}

		current = issuer
	}

	result.IsComplete = false
	return result, nil
}

// fetchCert fetches a DER-encoded certificate from the given URL.
func fetchCert(ctx context.Context, url string) (*x509.Certificate, error) {
	if err := validateFetchURL(url); err != nil {
		return nil, fmt.Errorf("unsafe URL %s: %w", url, err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := httpClient10s.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching cert from %s: %w", url, err)
	}
	defer resp.Body.Close()

	if err := classifyHTTPStatus(resp, url); err != nil {
		return nil, err
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
