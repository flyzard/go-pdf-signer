package crypto

import (
	"net"
	"testing"
)

// allowLoopbackForTest replaces both validateFetchURL and validateDialIP with
// no-ops for the duration of t and restores the defaults on cleanup. Use only
// in tests that legitimately need to fetch from httptest.NewServer (loopback
// URL) — the URL-level check happens pre-dial and the IP-level check happens
// inside secureDialContext; both must be bypassed or the loopback connection
// is refused.
func allowLoopbackForTest(t *testing.T) {
	t.Helper()
	prevURL := validateFetchURL
	prevDial := validateDialIP
	validateFetchURL = func(string) error { return nil }
	validateDialIP = func(net.IP) error { return nil }
	t.Cleanup(func() {
		validateFetchURL = prevURL
		validateDialIP = prevDial
	})
}
