package transport

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func clientWith(status int, body string, headers map[string]string) *http.Client {
	c := NewClient(0)
	c.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		h := http.Header{}
		for k, v := range headers {
			h.Set(k, v)
		}
		return &http.Response{StatusCode: status, Header: h, Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
	})
	return c
}

func TestRequireHTTPS(t *testing.T) {
	for _, bad := range []string{"http://example.com/x", "ftp://example.com/x", "https://user:pw@example.com/x", "example.com", ""} {
		if err := RequireHTTPS(bad); !errors.Is(err, ErrTransport) {
			t.Errorf("RequireHTTPS(%q) = %v, want ErrTransport", bad, err)
		}
	}
	if err := RequireHTTPS("https://example.com/.well-known/schemapin.json"); err != nil {
		t.Fatal(err)
	}
}

func TestFetchJSONRefusesPlaintext(t *testing.T) {
	var out map[string]interface{}
	err := FetchJSON(context.Background(), clientWith(200, `{"a":1}`, nil), "http://example.com/x", &out)
	if !errors.Is(err, ErrTransport) {
		t.Fatalf("expected ErrTransport, got %v", err)
	}
}

func TestFetchJSONRefusesRedirects(t *testing.T) {
	var out map[string]interface{}
	err := FetchJSON(context.Background(), clientWith(302, "", map[string]string{"Location": "https://evil.example/x"}), "https://example.com/x", &out)
	if err == nil {
		t.Fatal("redirect must fail")
	}
	// With the real client a redirect is refused by CheckRedirect before any
	// second request is issued.
	c := NewClient(0)
	if err := c.CheckRedirect(nil, nil); err == nil {
		t.Fatal("CheckRedirect must refuse")
	}
}

func TestFetchJSONCapsBody(t *testing.T) {
	var out interface{}
	big := `"` + strings.Repeat("x", MaxResponseBytes+10) + `"`
	err := FetchJSON(context.Background(), clientWith(200, big, nil), "https://example.com/x", &out)
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("expected size-cap error, got %v", err)
	}
}

func TestFetchJSONSuccess(t *testing.T) {
	var out map[string]interface{}
	if err := FetchJSON(context.Background(), clientWith(200, `{"ok":true}`, nil), "https://example.com/x", &out); err != nil {
		t.Fatal(err)
	}
	if out["ok"] != true {
		t.Fatalf("unexpected body %v", out)
	}
	if err := FetchJSON(context.Background(), clientWith(404, "", nil), "https://example.com/x", &out); err == nil {
		t.Fatal("non-200 must fail")
	}
}
