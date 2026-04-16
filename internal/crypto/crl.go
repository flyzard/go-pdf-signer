package crypto

import (
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
)

// CRLResult holds the raw DER-encoded CRL for DSS embedding.
type CRLResult struct {
	RawCRL []byte // DER-encoded for DSS embedding
}

// FetchCRL downloads the CRL from the first reachable distribution point in cert.
func FetchCRL(cert *x509.Certificate) (*CRLResult, error) {
	if len(cert.CRLDistributionPoints) == 0 {
		return nil, fmt.Errorf("certificate has no CRL distribution points")
	}

	var lastErr error
	for _, url := range cert.CRLDistributionPoints {
		raw, err := fetchCRL(httpClient30s, url)
		if err != nil {
			lastErr = err
			continue
		}
		return &CRLResult{RawCRL: raw}, nil
	}

	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("CRL fetch failed for all distribution points")
}

func fetchCRL(client *http.Client, url string) ([]byte, error) {
	if err := validateFetchURL(url); err != nil {
		return nil, fmt.Errorf("unsafe CRL URL %s: %w", url, err)
	}
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("fetching CRL from %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("CRL server %s returned HTTP %d", url, resp.StatusCode)
	}

	const maxSize = 10 << 20 // 10 MB
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxSize))
	if err != nil {
		return nil, fmt.Errorf("reading CRL from %s: %w", url, err)
	}

	return raw, nil
}
