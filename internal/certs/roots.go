package certs

import (
	"crypto/x509"
)

// PortugueseRoots returns a cert pool with Portuguese state root CAs.
// In production, this should contain ECRaizEstado and Multicert roots.
// For now, returns the system cert pool as a fallback.
func PortugueseRoots() *x509.CertPool {
	pool, err := x509.SystemCertPool()
	if err != nil {
		pool = x509.NewCertPool()
	}
	// TODO: Add embedded ECRaizEstado PEM via //go:embed when available
	return pool
}
