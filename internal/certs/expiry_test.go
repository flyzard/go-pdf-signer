package certs

import (
	"crypto/x509"
	"encoding/pem"
	"path"
	"testing"
	"time"
)

// minEmbeddedRootValidity is the smallest NotAfter window we accept for any
// vendored trust anchor. Per R-9.1.5 the build must fail when a shipped
// root would expire in < 90 days — operators would otherwise find out in
// production when a signature validation quietly starts failing.
const minEmbeddedRootValidity = 90 * 24 * time.Hour

// TestEmbeddedRootsAreNotExpiringSoon walks every committed PEM under
// internal/certs/embed/ (including the split signer/ and tsa/ subdirs) and
// fails if any certificate expires within minEmbeddedRootValidity from now.
// When no PEMs are vendored the test is a no-op — bootstrap before the
// TSL refresh tooling + committed trust anchors land.
func TestEmbeddedRootsAreNotExpiringSoon(t *testing.T) {
	now := time.Now()
	threshold := now.Add(minEmbeddedRootValidity)

	walk(t, "embed", func(file string, data []byte) {
		rest := data
		for {
			block, remaining := pem.Decode(rest)
			if block == nil {
				return
			}
			rest = remaining
			if block.Type != "CERTIFICATE" {
				continue
			}
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				t.Errorf("%s: parse cert: %v", file, err)
				continue
			}
			if cert.NotAfter.Before(threshold) {
				t.Errorf("%s: cert %q expires at %s, within %s refresh window — run `make refresh-tsl`",
					file, cert.Subject.CommonName, cert.NotAfter.Format(time.RFC3339),
					minEmbeddedRootValidity)
			}
		}
	})
}

// walk visits every regular file under the embedded dir rooted at base,
// recursively. readFile/dir errors are reported via t.Errorf so the caller
// sees which PEM triggered.
func walk(t *testing.T, base string, visit func(file string, data []byte)) {
	t.Helper()
	entries, err := embedded.ReadDir(base)
	if err != nil {
		// Missing dir is expected on a fresh checkout; the //go:embed
		// directive only includes files that exist at build time.
		return
	}
	for _, e := range entries {
		full := path.Join(base, e.Name())
		if e.IsDir() {
			walk(t, full, visit)
			continue
		}
		data, err := embedded.ReadFile(full)
		if err != nil {
			t.Errorf("read %s: %v", full, err)
			continue
		}
		visit(full, data)
	}
}
