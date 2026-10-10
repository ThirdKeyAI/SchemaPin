// Package transport provides the hardened HTTP fetch helper shared by
// discovery and revocation.
//
// Every outbound request made by this module goes through FetchJSON:
//
//   - https:// only -- plaintext URLs are refused before any socket is opened
//   - redirects are never followed (CheckRedirect returns an error)
//   - the response body is capped at MaxResponseBytes
//   - a timeout is always applied
package transport

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// MaxResponseBytes is the maximum accepted response body size.
const MaxResponseBytes = 64 * 1024

// DefaultTimeout is the default request timeout.
const DefaultTimeout = 10 * time.Second

// ErrTransport wraps every transport-level failure (scheme, redirect, size,
// network) so callers can test for it with errors.Is.
var ErrTransport = errors.New("transport error")

var errNoRedirect = errors.New("redirects are not followed")

// RequireHTTPS returns nil if rawURL is an absolute https:// URL without
// userinfo.
func RequireHTTPS(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("%w: invalid URL %q: %v", ErrTransport, rawURL, err)
	}
	if u.Scheme != "https" || u.Host == "" {
		return fmt.Errorf("%w: only https:// URLs are permitted: %q", ErrTransport, rawURL)
	}
	if u.User != nil {
		return fmt.Errorf("%w: userinfo is not permitted in URLs: %q", ErrTransport, rawURL)
	}
	return nil
}

// NewClient returns an http.Client with the hardening rules applied.
func NewClient(timeout time.Duration) *http.Client {
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	return &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return errNoRedirect
		},
	}
}

// FetchJSON GETs rawURL with client (nil means NewClient(DefaultTimeout)) and
// decodes the JSON body into out under the hardening rules above.
func FetchJSON(ctx context.Context, client *http.Client, rawURL string, out interface{}) error {
	return FetchJSONLimited(ctx, client, rawURL, MaxResponseBytes, out)
}

// FetchJSONLimited is FetchJSON with an explicit body cap.
func FetchJSONLimited(ctx context.Context, client *http.Client, rawURL string, maxBytes int64, out interface{}) error {
	if err := RequireHTTPS(rawURL); err != nil {
		return err
	}
	if client == nil {
		client = NewClient(DefaultTimeout)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrTransport, err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "SchemaPin")

	resp, err := client.Do(req) // #nosec G704 -- URL validated by RequireHTTPS; redirects refused
	if err != nil {
		return fmt.Errorf("%w: request failed for %s: %v", ErrTransport, rawURL, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: HTTP %d fetching %s", ErrTransport, resp.StatusCode, rawURL)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		return fmt.Errorf("%w: reading %s: %v", ErrTransport, rawURL, err)
	}
	if int64(len(body)) > maxBytes {
		return fmt.Errorf("%w: response from %s exceeds %d bytes", ErrTransport, rawURL, maxBytes)
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("%w: invalid JSON from %s: %v", ErrTransport, rawURL, err)
	}
	return nil
}
