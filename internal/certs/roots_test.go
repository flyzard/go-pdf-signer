package certs

import (
	"bytes"
	"path/filepath"
	"testing"
)

func TestPortugueseRootsContainsEmbedded(t *testing.T) {
	matches, _ := filepath.Glob(filepath.Join("embed", "*.pem"))
	if len(matches) == 0 {
		t.Skip("no PEMs vendored under internal/certs/embed/")
	}

	pool := PortugueseRoots()
	subjects := pool.Subjects() //nolint:staticcheck
	if len(subjects) == 0 {
		t.Fatal("PortugueseRoots returned an empty pool")
	}

	found := false
	for _, raw := range subjects {
		if bytes.Contains(raw, []byte("ECRaizEstado")) {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected at least one cert subject to contain 'ECRaizEstado'")
	}
}
