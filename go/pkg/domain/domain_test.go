package domain

import (
	"errors"
	"strings"
	"testing"
)

func TestValidDomains(t *testing.T) {
	cases := map[string]string{
		"example.com":              "example.com",
		"Example.COM":              "example.com",
		"sub.domain.example.co.uk": "sub.domain.example.co.uk",
		"xn--bcher-kva.example":    "xn--bcher-kva.example",
		"a-b.c1":                   "a-b.c1",
		"1.example":                "1.example",
	}
	for in, want := range cases {
		got, err := ValidateDomain(in)
		if err != nil || got != want {
			t.Errorf("ValidateDomain(%q) = %q, %v; want %q", in, got, err, want)
		}
		if !IsValidDomain(in) {
			t.Errorf("IsValidDomain(%q) = false", in)
		}
	}
}

func TestInvalidDomains(t *testing.T) {
	bad := []string{
		"", "localhost", "example", "http://example.com", "https://example.com",
		"example.com/path", "example.com:8443", "user@example.com", "good.com@evil.com",
		"../skills/evil/key", "/etc/passwd", "example.com.", ".example.com", "exa mple.com",
		"-bad.example.com", "bad-.example.com", "under_score.example.com", "10.0.0.1", "[::1]",
		"bücher.example", strings.Repeat("a", 64) + ".example.com",
		strings.Repeat(strings.Repeat("a", 63)+".", 4) + "com", "evil.com\nexample.com",
	}
	for _, in := range bad {
		if _, err := ValidateDomain(in); err == nil {
			t.Errorf("ValidateDomain(%q) accepted", in)
		} else if !errors.Is(err, ErrInvalidDomain) {
			t.Errorf("ValidateDomain(%q) error is not ErrInvalidDomain: %v", in, err)
		}
		if IsValidDomain(in) {
			t.Errorf("IsValidDomain(%q) = true", in)
		}
	}
}
