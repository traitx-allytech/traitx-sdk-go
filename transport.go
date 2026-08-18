package traitx

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

var retryableStatuses = map[int]bool{
	408: true, 429: true, 500: true, 502: true, 503: true, 504: true,
}

const retryAfterCap = 5 * time.Second

type requestSpec struct {
	method string
	path   string
	query  map[string]string
	body   interface{}
	// headers are added last and win over the defaults.
	headers map[string]string
	// omitAPIKey skips X-API-Key (management calls use a bearer token).
	omitAPIKey bool
}

type transport struct {
	cfg     Config
	breaker *CircuitBreaker
}

// send performs a request, never returning an error for transport or HTTP
// problems: the outcome is data so the caller can turn it into a Decision.
func (t *transport) send(ctx context.Context, spec requestSpec) HTTPOutcome {
	started := t.cfg.Clock()

	if !t.breaker.Allow() {
		return HTTPOutcome{TransportError: "circuit breaker open"}
	}

	endpoint, err := t.buildURL(spec)
	if err != nil {
		t.breaker.RecordSuccess() // a bad URL is our bug, not the service's
		return HTTPOutcome{TransportError: err.Error(), LatencyMS: t.elapsed(started)}
	}

	var payload []byte
	if spec.body != nil {
		payload, err = json.Marshal(spec.body)
		if err != nil {
			t.breaker.RecordSuccess()
			return HTTPOutcome{
				TransportError: fmt.Sprintf("could not encode request body: %v", err),
				LatencyMS:      t.elapsed(started),
			}
		}
	}

	var (
		lastError      = "request failed"
		lastStatus     int
		lastBody       map[string]interface{}
		lastDecoded    bool
		retryAfterWait time.Duration
	)

	for attempt := 0; attempt <= t.cfg.MaxRetries; attempt++ {
		if attempt > 0 {
			wait := retryAfterWait
			if wait <= 0 {
				wait = t.backoff(attempt)
			}
			select {
			case <-ctx.Done():
				t.breaker.RecordFailure()
				return HTTPOutcome{
					TransportError: fmt.Sprintf("context cancelled while retrying: %v", ctx.Err()),
					LatencyMS:      t.elapsed(started),
				}
			case <-time.After(wait):
			}
		}

		status, body, decoded, retryAfter, reqErr := t.attempt(ctx, spec, endpoint, payload)
		retryAfterWait = retryAfter

		if reqErr != nil {
			lastError = describeTransportError(reqErr, t.cfg.Timeout)
			t.debugf("x %s %s: %s", spec.method, endpoint, lastError)
			retryAfterWait = 0
			// The caller gave up. That is not a service failure, so it must not
			// count towards opening the breaker.
			if errors.Is(reqErr, context.Canceled) && ctx.Err() != nil {
				t.breaker.RecordSuccess()
				return HTTPOutcome{
					TransportError: "request cancelled by the caller",
					LatencyMS:      t.elapsed(started),
				}
			}
			if attempt >= t.cfg.MaxRetries {
				break
			}
			continue
		}

		lastStatus, lastBody, lastDecoded = status, body, decoded

		if retryableStatuses[status] && attempt < t.cfg.MaxRetries {
			lastError = fmt.Sprintf("risk api returned HTTP %d", status)
			continue
		}

		if status >= 500 || status == 429 || status == 408 {
			t.breaker.RecordFailure()
		} else {
			// A 401 is a settled answer from a healthy service; it must not
			// count towards opening the breaker.
			t.breaker.RecordSuccess()
		}

		return HTTPOutcome{
			StatusCode:  status,
			Body:        body,
			BodyDecoded: decoded,
			LatencyMS:   t.elapsed(started),
		}
	}

	t.breaker.RecordFailure()
	statusCode := 0
	if lastStatus >= 500 || lastStatus == 429 {
		statusCode = lastStatus
	}
	return HTTPOutcome{
		StatusCode:     statusCode,
		Body:           lastBody,
		BodyDecoded:    lastDecoded,
		LatencyMS:      t.elapsed(started),
		TransportError: lastError,
	}
}

func (t *transport) attempt(
	ctx context.Context, spec requestSpec, endpoint string, payload []byte,
) (status int, body map[string]interface{}, decoded bool, retryAfter time.Duration, err error) {
	attemptCtx, cancel := context.WithTimeout(ctx, t.cfg.Timeout)
	defer cancel()

	var reader io.Reader
	if payload != nil {
		reader = bytes.NewReader(payload)
	}

	req, err := http.NewRequestWithContext(attemptCtx, spec.method, endpoint, reader)
	if err != nil {
		return 0, nil, false, 0, err
	}
	for name, value := range t.headers(spec) {
		req.Header.Set(name, value)
	}

	t.debugf("-> %s %s", spec.method, endpoint)

	resp, err := t.cfg.HTTPClient.Do(req)
	if err != nil {
		return 0, nil, false, 0, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return 0, nil, false, 0, err
	}

	t.debugf("<- %d %s %s", resp.StatusCode, spec.method, truncate(string(raw), 2000))

	if len(raw) > 0 {
		var parsed map[string]interface{}
		if json.Unmarshal(raw, &parsed) == nil {
			body, decoded = parsed, true
		}
	}

	return resp.StatusCode, body, decoded, parseRetryAfter(resp.Header.Get("Retry-After")), nil
}

func (t *transport) buildURL(spec requestSpec) (string, error) {
	parsed, err := url.Parse(t.cfg.BaseURL + spec.path)
	if err != nil {
		return "", fmt.Errorf("invalid url %q: %w", t.cfg.BaseURL+spec.path, err)
	}
	if len(spec.query) > 0 {
		values := parsed.Query()
		for key, value := range spec.query {
			if value != "" {
				values.Set(key, value)
			}
		}
		parsed.RawQuery = values.Encode()
	}
	return parsed.String(), nil
}

func (t *transport) headers(spec requestSpec) map[string]string {
	headers := map[string]string{
		"Accept":     "application/json",
		"User-Agent": t.cfg.UserAgent,
	}
	if spec.body != nil {
		headers["Content-Type"] = "application/json"
	}
	if !spec.omitAPIKey {
		headers["X-API-Key"] = t.cfg.APIKey
	}
	if t.cfg.ApplicationID != "" {
		headers["X-Application-ID"] = t.cfg.ApplicationID
	}
	for name, value := range spec.headers {
		headers[name] = value
	}
	return headers
}

// backoff is full jitter: random(0, base * 2^(n-1)). See SPEC.md §9.
func (t *transport) backoff(attempt int) time.Duration {
	ceiling := t.cfg.RetryBackoff * (1 << (attempt - 1))
	if ceiling <= 0 {
		return 0
	}
	return time.Duration(rand.Int63n(int64(ceiling)))
}

func (t *transport) elapsed(started time.Time) int {
	return int(t.cfg.Clock().Sub(started) / time.Millisecond)
}

func (t *transport) debugf(format string, args ...interface{}) {
	if !t.cfg.Debug {
		return
	}
	t.cfg.Logger.Printf("[traitx key %s] "+format, append([]interface{}{RedactKey(t.cfg.APIKey)}, args...)...)
}

func parseRetryAfter(value string) time.Duration {
	if value == "" {
		return 0
	}
	if seconds, err := strconv.ParseFloat(value, 64); err == nil && seconds >= 0 {
		wait := time.Duration(seconds * float64(time.Second))
		if wait > retryAfterCap {
			return retryAfterCap
		}
		return wait
	}
	if when, err := http.ParseTime(value); err == nil {
		wait := time.Until(when)
		if wait < 0 {
			return 0
		}
		if wait > retryAfterCap {
			return retryAfterCap
		}
		return wait
	}
	return 0
}

func describeTransportError(err error, timeout time.Duration) string {
	if errors.Is(err, context.DeadlineExceeded) {
		return fmt.Sprintf("risk api timed out after %s", timeout)
	}
	if errors.Is(err, context.Canceled) {
		return "request cancelled by the caller"
	}
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		if urlErr.Timeout() {
			return fmt.Sprintf("risk api timed out after %s", timeout)
		}
		return urlErr.Err.Error()
	}
	return err.Error()
}

func truncate(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	return s[:limit] + "…"
}
