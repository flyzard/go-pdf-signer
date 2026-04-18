package crypto

import (
	"context"
	"fmt"
	"net"
	"time"
)

// validateDialIP gates which resolved IPs the crypto package's HTTP transport
// is allowed to dial. The default rejects loopback/private/link-local/
// multicast/unspecified ranges. Tests may swap this via allowLoopbackForTest
// (see testhook_test.go) so httptest servers on 127.0.0.1 stay reachable.
var validateDialIP = validateDialIPDefault

func validateDialIPDefault(ip net.IP) error {
	if ip == nil {
		return fmt.Errorf("nil IP")
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return fmt.Errorf("refuse dial to private/loopback IP %s", ip)
	}
	return nil
}

// secureDialContext is the DialContext implementation used by the crypto
// package's shared HTTP transport. It resolves the destination host itself,
// validates each candidate IP, and dials a specific IP — defeating the DNS
// rebinding race where the hostname is checked once (in urlval.go) and then
// re-resolved to an attacker-controlled private IP on the wire.
func secureDialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("dial: split %s: %w", addr, err)
	}

	dialer := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}

	// addr may already be an IP literal (e.g., after the resolver returned).
	if ip := net.ParseIP(host); ip != nil {
		if err := validateDialIP(ip); err != nil {
			return nil, err
		}
		return dialer.DialContext(ctx, network, addr)
	}

	resolver := &net.Resolver{}
	ips, err := resolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("dial: resolve %s: %w", host, err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("dial: no addresses for %s", host)
	}

	var lastErr error
	for _, ipa := range ips {
		if err := validateDialIP(ipa.IP); err != nil {
			lastErr = err
			continue
		}
		pinned := net.JoinHostPort(ipa.IP.String(), port)
		conn, err := dialer.DialContext(ctx, network, pinned)
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("dial: no safe IP for %s", host)
	}
	return nil, lastErr
}
