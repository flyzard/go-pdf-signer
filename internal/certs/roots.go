package certs

import (
	"crypto/x509"
	"embed"
	"fmt"
	"os"
	"path"
)

//go:embed embed
var embedded embed.FS

// Pool identifiers used as subdirectory names under internal/certs/embed/.
// Each subdir holds PEMs for exactly one trust role; keeping them separate
// lets the signer and TSA trust decisions stay independent (per doc
// R-3.1.5 / R-9.1.6), and stops a TSA-only root from being silently
// accepted as a signer anchor.
const (
	poolSigner = "signer"
	poolTSA    = "tsa"
)

// Built once at package init from the embedded PEMs (or the OS pool as
// fallback) and reused by every PortugueseRoots() / SignerRoots() /
// TSARoots() call.
var (
	signerRootPool = buildPool(poolSigner)
	tsaRootPool    = buildPool(poolTSA)
	// portugueseRootPool preserves the legacy flat layout (internal/certs/embed/*.pem)
	// for back-compat with callers that haven't migrated to the split API.
	portugueseRootPool = buildPool("")
)

// SignerRoots returns the trust pool used to validate signer (and CMS-chain)
// certificates. Sourced from internal/certs/embed/signer/*.pem when present,
// otherwise falls back via the same rules as PortugueseRoots.
func SignerRoots() *x509.CertPool { return signerRootPool }

// TSARoots returns the trust pool used to validate RFC 3161 timestamp
// authority certificates. Sourced from internal/certs/embed/tsa/*.pem. Must
// stay distinct from SignerRoots (R-3.1.5): a TSA anchor should never
// accidentally validate a signer cert and vice-versa.
func TSARoots() *x509.CertPool { return tsaRootPool }

// PortugueseRoots returns a cert pool seeded from the flat legacy
// internal/certs/embed/*.pem layout. Retained for back-compat during the
// migration window; new callers should prefer SignerRoots or TSARoots.
func PortugueseRoots() *x509.CertPool { return portugueseRootPool }

// buildPool loads PEMs from internal/certs/embed/<subdir>/. If subdir is "",
// it loads from internal/certs/embed/ directly (flat legacy layout).
// Returns the system pool as last-resort fallback when no PEMs were found,
// so an uninitialised repo still has *some* chance of verifying a widely-
// recognised public-sector chain during bootstrap. Production deployments
// must commit real PEMs and exercise the 90-day expiry guard.
func buildPool(subdir string) *x509.CertPool {
	pool := x509.NewCertPool()
	dir := "embed"
	if subdir != "" {
		dir = path.Join(dir, subdir)
	}
	added := false

	entries, err := embedded.ReadDir(dir)
	if err != nil {
		diag("read %s: %v", dir, err)
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		data, err := embedded.ReadFile(path.Join(dir, e.Name()))
		if err != nil {
			diag("read %s/%s: %v", dir, e.Name(), err)
			continue
		}
		if pool.AppendCertsFromPEM(data) {
			added = true
		}
	}

	if added {
		return pool
	}
	sys, err := x509.SystemCertPool()
	if err != nil {
		diag("no embedded PEMs in %s and SystemCertPool failed: %v", dir, err)
		return pool
	}
	return sys
}

// diag writes a diagnostic line to stderr only when PDFSIGNER_DEBUG is set.
// Keeps the JSON protocol on stdout/stderr clean in production while
// preserving a way to observe cert-pool issues during debugging.
func diag(format string, args ...any) {
	if os.Getenv("PDFSIGNER_DEBUG") == "" {
		return
	}
	fmt.Fprintf(os.Stderr, "certs: "+format+"\n", args...)
}
