package crypto

import (
	"context"
	"net"
	"testing"
)

func TestValidateDialIPDefaultRejectsLoopback(t *testing.T) {
	if err := validateDialIPDefault(net.ParseIP("127.0.0.1")); err == nil {
		t.Error("127.0.0.1 should be rejected")
	}
}

func TestValidateDialIPDefaultRejectsPrivate(t *testing.T) {
	cases := []string{
		"10.0.0.5",
		"192.168.1.1",
		"172.16.0.1",
		"169.254.169.254", // AWS/GCP metadata
		"::1",
		"fc00::1",
		"fe80::1",
	}
	for _, s := range cases {
		if err := validateDialIPDefault(net.ParseIP(s)); err == nil {
			t.Errorf("%s should be rejected", s)
		}
	}
}

func TestValidateDialIPDefaultAllowsPublic(t *testing.T) {
	cases := []string{"8.8.8.8", "1.1.1.1", "93.184.216.34"}
	for _, s := range cases {
		if err := validateDialIPDefault(net.ParseIP(s)); err != nil {
			t.Errorf("%s should be allowed: %v", s, err)
		}
	}
}

func TestSecureDialContextRefusesLoopbackLiteral(t *testing.T) {
	// No allowLoopbackForTest — default policy in effect.
	_, err := secureDialContext(context.Background(), "tcp", "127.0.0.1:65500")
	if err == nil {
		t.Fatal("secureDialContext should refuse to dial 127.0.0.1")
	}
}
