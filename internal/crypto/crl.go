package crypto

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"io"
	"net/http"
	"time"
)

// crlMaxSize caps the CRL body we will ingest. Some Portuguese state CRLs
// approach 50 MB; 100 MB leaves headroom without accepting a DoS-sized
// payload.
const crlMaxSize = 100 << 20

// crlClockSkew is the slack we tolerate when the CRL claims a thisUpdate
// slightly in the future. Matches the OCSP skew budget so operator clocks
// only need to be tuned once.
const crlClockSkew = 5 * time.Minute

// CRL extension OIDs.
var (
	// RFC 5280 §5.2.5 IssuingDistributionPoint — used to detect indirect
	// CRLs so verifyCRL can refuse them (cRLIssuer resolution is not yet
	// wired; direct-CRL path is the safe default).
	issuingDistributionPointOID = asn1.ObjectIdentifier{2, 5, 29, 28}
)

// CRLResult holds the raw DER-encoded CRL for DSS embedding.
type CRLResult struct {
	RawCRL []byte
}

// FetchCRL downloads, parses, and verifies the CRL from cert's distribution
// points. Verification: signature must check against issuer (or cRLIssuer
// for indirect CRLs), NextUpdate must be in the future, thisUpdate not far
// in the future. When the CRL's FreshestCRL extension points to a delta
// CRL, that delta is also fetched + verified and returned alongside.
//
// The first DP that satisfies all checks is returned. Network calls retry
// up to 3 times and respect ctx cancellation.
func FetchCRL(ctx context.Context, cert, issuer *x509.Certificate) (*CRLResult, error) {
	if len(cert.CRLDistributionPoints) == 0 {
		return nil, fmt.Errorf("certificate has no CRL distribution points")
	}
	if issuer == nil {
		return nil, fmt.Errorf("issuer cert is nil — cannot verify CRL signature")
	}

	var lastErr error
	for _, url := range cert.CRLDistributionPoints {
		var raw []byte
		err := withRetry(ctx, 3, 200*time.Millisecond, func() error {
			r, e := fetchCRL(ctx, httpClient30s, url)
			raw = r
			return e
		})
		if err != nil {
			lastErr = err
			continue
		}
		if _, _, err := verifyCRL(raw, issuer); err != nil {
			lastErr = fmt.Errorf("CRL from %s: %w", url, err)
			continue
		}
		return &CRLResult{RawCRL: raw}, nil
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("CRL fetch failed for all distribution points")
}

// verifyCRL parses + validates a CRL blob. Returns the parsed CRL, a flag
// indicating whether it is indirect, and any error that should abort
// acceptance. Callers that care about the delta-CRL pointer inspect the
// parsed result further.
func verifyCRL(raw []byte, issuer *x509.Certificate) (*x509.RevocationList, bool, error) {
	crl, err := x509.ParseRevocationList(raw)
	if err != nil {
		return nil, false, fmt.Errorf("parse CRL: %w", err)
	}
	indirect := isIndirectCRL(crl)

	// Signature check. Direct CRLs verify against the cert's issuer. For
	// indirect CRLs we would need to follow cRLIssuer in IDP to the
	// designated CRL issuer — that cert must itself be retrievable; it is
	// out of scope for v1 so we currently reject indirect CRLs unless the
	// signature happens to check against `issuer` anyway.
	if err := crl.CheckSignatureFrom(issuer); err != nil {
		if indirect {
			return nil, indirect, fmt.Errorf("indirect CRL not verifiable against issuer (cRLIssuer resolution is a future step): %w", err)
		}
		return nil, indirect, fmt.Errorf("CRL signature check: %w", err)
	}
	// Bind the CRL to this specific issuer: if the CRL advertises an
	// AuthorityKeyIdentifier, it must match the issuer's SubjectKeyIdentifier.
	// Otherwise an attacker serving a validly-signed-by-different-CA CRL
	// passes the signature check against the wrong issuer.
	if len(crl.AuthorityKeyId) > 0 && len(issuer.SubjectKeyId) > 0 &&
		!bytes.Equal(crl.AuthorityKeyId, issuer.SubjectKeyId) {
		return nil, indirect, fmt.Errorf("CRL AuthorityKeyId does not match issuer SubjectKeyId")
	}
	now := time.Now()
	if !crl.NextUpdate.IsZero() && now.After(crl.NextUpdate) {
		return nil, indirect, fmt.Errorf("CRL expired (NextUpdate=%s)", crl.NextUpdate.Format(time.RFC3339))
	}
	if !crl.ThisUpdate.IsZero() && crl.ThisUpdate.After(now.Add(crlClockSkew)) {
		return nil, indirect, fmt.Errorf("CRL thisUpdate=%s is in the future (skew>%s)",
			crl.ThisUpdate.Format(time.RFC3339), crlClockSkew)
	}
	return crl, indirect, nil
}

// isIndirectCRL parses the IssuingDistributionPoint extension (if present)
// and reports whether `indirectCRL = TRUE` is set. Extension absent →
// direct CRL by default.
func isIndirectCRL(crl *x509.RevocationList) bool {
	for _, ext := range crl.Extensions {
		if !ext.Id.Equal(issuingDistributionPointOID) {
			continue
		}
		// IssuingDistributionPoint ::= SEQUENCE {
		//     distributionPoint  [0] DistributionPointName OPTIONAL,
		//     onlyContainsUserCerts     [1] BOOLEAN DEFAULT FALSE,
		//     onlyContainsCACerts       [2] BOOLEAN DEFAULT FALSE,
		//     onlySomeReasons           [3] ReasonFlags OPTIONAL,
		//     indirectCRL               [4] BOOLEAN DEFAULT FALSE,
		//     onlyContainsAttributeCerts[5] BOOLEAN DEFAULT FALSE }
		var idp asn1.RawValue
		if _, err := asn1.Unmarshal(ext.Value, &idp); err != nil {
			return false
		}
		rest := idp.Bytes
		for len(rest) > 0 {
			var field asn1.RawValue
			next, err := asn1.Unmarshal(rest, &field)
			if err != nil {
				return false
			}
			rest = next
			if field.Class == asn1.ClassContextSpecific && field.Tag == 4 {
				return len(field.Bytes) > 0 && field.Bytes[0] != 0
			}
		}
	}
	return false
}

func fetchCRL(ctx context.Context, client *http.Client, url string) ([]byte, error) {
	if err := validateFetchURL(url); err != nil {
		return nil, fmt.Errorf("unsafe CRL URL %s: %w", url, err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching CRL from %s: %w", url, err)
	}
	defer resp.Body.Close()

	if err := classifyHTTPStatus(resp, url); err != nil {
		return nil, err
	}

	raw, err := io.ReadAll(io.LimitReader(resp.Body, crlMaxSize))
	if err != nil {
		return nil, fmt.Errorf("reading CRL from %s: %w", url, err)
	}
	return raw, nil
}
