package crypto

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"
)

// maxRetryAfterWait caps how long we'll honor a server-supplied Retry-After
// header. Anything larger is treated as a non-retryable signal.
const maxRetryAfterWait = 30 * time.Second

// terminalError wraps an underlying error to signal that withRetry must not
// retry. Used to short-circuit on HTTP 4xx (other than 408/429).
type terminalError struct{ err error }

func (e *terminalError) Error() string { return e.err.Error() }
func (e *terminalError) Unwrap() error { return e.err }

// asTerminal marks err as non-retryable.
func asTerminal(err error) error {
	if err == nil {
		return nil
	}
	return &terminalError{err: err}
}

// retryAfterError carries a server-supplied wait before the next attempt.
type retryAfterError struct {
	err   error
	after time.Duration
}

func (e *retryAfterError) Error() string { return e.err.Error() }
func (e *retryAfterError) Unwrap() error { return e.err }

// withRetry calls fn up to maxAttempts times. Between attempts it sleeps
// baseDelay * 2^attempt unless fn returned a retryAfterError — in which case
// the Retry-After value is used (capped at maxRetryAfterWait). fn returning
// a terminalError causes immediate return. Honors ctx cancellation.
func withRetry(ctx context.Context, maxAttempts int, baseDelay time.Duration, fn func() error) error {
	var err error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		err = fn()
		if err == nil {
			return nil
		}
		var term *terminalError
		if errors.As(err, &term) {
			return err
		}
		if attempt == maxAttempts-1 {
			break
		}

		delay := baseDelay << attempt
		var ra *retryAfterError
		if errors.As(err, &ra) && ra.after > 0 {
			if ra.after > maxRetryAfterWait {
				// Server wants a longer wait than we're willing to give —
				// treat as terminal for this call.
				return err
			}
			delay = ra.after
		}
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return err
}

// classifyHTTPStatus returns a typed error appropriate for the retry layer:
// nil for 2xx, retryAfterError honoring Retry-After for 429/503, terminal for
// other 4xx, and a plain error (retryable by default) for 5xx.
func classifyHTTPStatus(resp *http.Response, url string) error {
	if resp == nil {
		return nil
	}
	code := resp.StatusCode
	if code >= 200 && code < 300 {
		return nil
	}
	msg := fmt.Errorf("%s returned HTTP %d", url, code)

	switch code {
	case http.StatusRequestTimeout, http.StatusTooManyRequests:
		return &retryAfterError{err: msg, after: parseRetryAfter(resp.Header.Get("Retry-After"))}
	case http.StatusServiceUnavailable:
		return &retryAfterError{err: msg, after: parseRetryAfter(resp.Header.Get("Retry-After"))}
	}
	if code >= 400 && code < 500 {
		return asTerminal(msg)
	}
	// 5xx (other than 503) — retry with default backoff.
	return msg
}

// parseRetryAfter decodes the Retry-After HTTP header. The spec permits
// either delta-seconds or an HTTP-date; this implementation supports
// delta-seconds and returns 0 for anything else. 0 means "no hint".
func parseRetryAfter(s string) time.Duration {
	if s == "" {
		return 0
	}
	if n, err := strconv.Atoi(s); err == nil && n > 0 {
		return time.Duration(n) * time.Second
	}
	if t, err := http.ParseTime(s); err == nil {
		if d := time.Until(t); d > 0 {
			return d
		}
	}
	return 0
}
