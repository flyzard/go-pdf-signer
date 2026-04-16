package crypto

import (
	"testing"
)

func TestValidateFetchURL(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		wantErr bool
	}{
		{"valid http", "http://ca.example.com/cert.crt", false},
		{"valid https", "https://ca.example.com/cert.crt", false},
		{"file scheme", "file:///etc/passwd", true},
		{"ftp scheme", "ftp://example.com/cert.crt", true},
		{"no scheme", "example.com/cert.crt", true},
		{"empty", "", true},
		{"loopback ipv4", "http://127.0.0.1/cert.crt", true},
		{"loopback localhost", "http://localhost/cert.crt", true},
		{"link-local", "http://169.254.169.254/latest/meta-data", true},
		{"private 10.x", "http://10.0.0.1/cert.crt", true},
		{"private 172.16.x", "http://172.16.0.1/cert.crt", true},
		{"private 192.168.x", "http://192.168.1.1/cert.crt", true},
		{"valid public ip", "http://198.51.100.1/cert.crt", false},
		{"loopback ipv6", "http://[::1]/cert.crt", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateFetchURL(tt.url)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateFetchURL(%q) error = %v, wantErr %v", tt.url, err, tt.wantErr)
			}
		})
	}
}
