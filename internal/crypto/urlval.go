package crypto

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

// validateFetchURL is the active URL validator. Tests may swap it via
// allowLoopbackForTest() in testhook_test.go. Production code path is
// validateFetchURLDefault.
var validateFetchURL = validateFetchURLDefault

// validateFetchURLDefault checks that a URL is safe to fetch (HTTP/HTTPS, no private IPs).
func validateFetchURLDefault(rawURL string) error {
	if rawURL == "" {
		return fmt.Errorf("empty URL")
	}

	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}

	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("unsupported URL scheme: %q", u.Scheme)
	}

	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("empty hostname in URL")
	}

	if strings.EqualFold(host, "localhost") {
		return fmt.Errorf("localhost URLs are not allowed")
	}

	ip := net.ParseIP(host)
	if ip != nil {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
			return fmt.Errorf("private/loopback IP %s is not allowed", ip)
		}
	}

	return nil
}
