package crypto

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"

	"golang.org/x/crypto/ocsp"
)

// OCSPResult holds the parsed OCSP response and its raw DER bytes.
type OCSPResult struct {
	Response    *ocsp.Response
	RawResponse []byte // DER-encoded for DSS embedding
}

// FetchOCSP fetches and validates the OCSP response for cert signed by issuer.
func FetchOCSP(cert, issuer *x509.Certificate) (*OCSPResult, error) {
	if len(cert.OCSPServer) == 0 {
		return nil, fmt.Errorf("certificate has no OCSP server URLs")
	}

	reqBytes, err := ocsp.CreateRequest(cert, issuer, nil)
	if err != nil {
		return nil, fmt.Errorf("creating OCSP request: %w", err)
	}

	var lastErr error
	for _, serverURL := range cert.OCSPServer {
		rawResp, err := postOCSP(httpClient10s, serverURL, reqBytes)
		if err != nil {
			lastErr = err
			continue
		}

		parsed, err := ocsp.ParseResponse(rawResp, issuer)
		if err != nil {
			lastErr = fmt.Errorf("parsing OCSP response from %s: %w", serverURL, err)
			continue
		}

		if parsed.Status != ocsp.Good {
			lastErr = fmt.Errorf("certificate status is not good: %d", parsed.Status)
			continue
		}

		return &OCSPResult{
			Response:    parsed,
			RawResponse: rawResp,
		}, nil
	}

	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("OCSP fetch failed for all servers")
}

func postOCSP(client *http.Client, url string, body []byte) ([]byte, error) {
	resp, err := client.Post(url, "application/ocsp-request", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("POST to OCSP server %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OCSP server %s returned HTTP %d", url, resp.StatusCode)
	}

	const maxSize = 1 << 20 // 1 MB
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxSize))
	if err != nil {
		return nil, fmt.Errorf("reading OCSP response from %s: %w", url, err)
	}

	return raw, nil
}
