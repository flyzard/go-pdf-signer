package crypto

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestWithRetryDoesNotRetryTerminal(t *testing.T) {
	calls := 0
	err := withRetry(context.Background(), 5, time.Millisecond, func() error {
		calls++
		return asTerminal(errors.New("HTTP 404"))
	})
	if err == nil {
		t.Fatal("expected terminal error to propagate")
	}
	if calls != 1 {
		t.Errorf("terminal error retried %d times, want 1", calls)
	}
}

func TestWithRetryHonorsRetryAfter(t *testing.T) {
	calls := 0
	start := time.Now()
	err := withRetry(context.Background(), 2, time.Millisecond, func() error {
		calls++
		if calls == 1 {
			return &retryAfterError{err: errors.New("503"), after: 100 * time.Millisecond}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if elapsed := time.Since(start); elapsed < 80*time.Millisecond {
		t.Errorf("withRetry did not wait for Retry-After, elapsed=%v", elapsed)
	}
}

func TestWithRetryGivesUpOnOverlyLongRetryAfter(t *testing.T) {
	calls := 0
	err := withRetry(context.Background(), 5, time.Millisecond, func() error {
		calls++
		return &retryAfterError{err: errors.New("503"), after: time.Hour}
	})
	if err == nil {
		t.Fatal("expected error when Retry-After exceeds cap")
	}
	if calls != 1 {
		t.Errorf("overly-long Retry-After retried %d times, want 1", calls)
	}
}

func TestClassifyHTTPStatusCategorises(t *testing.T) {
	tests := []struct {
		status     int
		wantNil    bool
		isTerminal bool
		isRetryAft bool
	}{
		{200, true, false, false},
		{204, true, false, false},
		{400, false, true, false},
		{403, false, true, false},
		{404, false, true, false},
		{408, false, false, true},
		{429, false, false, true},
		{500, false, false, false},
		{502, false, false, false},
		{503, false, false, true},
	}
	for _, tc := range tests {
		resp := &http.Response{StatusCode: tc.status, Header: http.Header{}}
		err := classifyHTTPStatus(resp, "http://x")
		if tc.wantNil {
			if err != nil {
				t.Errorf("status %d: want nil, got %v", tc.status, err)
			}
			continue
		}
		if err == nil {
			t.Errorf("status %d: want error, got nil", tc.status)
			continue
		}
		var term *terminalError
		var ra *retryAfterError
		gotTerminal := errors.As(err, &term)
		gotRA := errors.As(err, &ra)
		if gotTerminal != tc.isTerminal {
			t.Errorf("status %d: terminal=%v, want %v", tc.status, gotTerminal, tc.isTerminal)
		}
		if gotRA != tc.isRetryAft {
			t.Errorf("status %d: retryAfter=%v, want %v", tc.status, gotRA, tc.isRetryAft)
		}
	}
}

func TestFetchCRL4xxNotRetried(t *testing.T) {
	allowLoopbackForTest(t)
	ca, caKey := generateTestCA(t)

	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.WriteHeader(404)
	}))
	defer srv.Close()

	leafTpl := &x509.Certificate{
		SerialNumber:          big.NewInt(777),
		Subject:               pkix.Name{CommonName: "Leaf 4xx"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		CRLDistributionPoints: []string{srv.URL},
	}
	leafKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTpl, ca, &leafKey.PublicKey, caKey)
	leaf, _ := x509.ParseCertificate(leafDER)

	if _, err := FetchCRL(context.Background(), leaf, ca); err == nil {
		t.Fatal("expected error on 404")
	}
	if calls != 1 {
		t.Errorf("server called %d times, want 1 (4xx must not retry)", calls)
	}
}

func TestFetchCRL5xxRetries(t *testing.T) {
	allowLoopbackForTest(t)
	ca, caKey := generateTestCA(t)

	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.WriteHeader(500)
	}))
	defer srv.Close()

	leafTpl := &x509.Certificate{
		SerialNumber:          big.NewInt(778),
		Subject:               pkix.Name{CommonName: "Leaf 5xx"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		CRLDistributionPoints: []string{srv.URL},
	}
	leafKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTpl, ca, &leafKey.PublicKey, caKey)
	leaf, _ := x509.ParseCertificate(leafDER)

	if _, err := FetchCRL(context.Background(), leaf, ca); err == nil {
		t.Fatal("expected error after retries")
	}
	if calls < 2 {
		t.Errorf("server called %d times, want >=2 (5xx should retry)", calls)
	}
}
