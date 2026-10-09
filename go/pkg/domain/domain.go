// Package domain provides the shared domain-name validator.
//
// Every place that turns a domain string into something security-relevant --
// a .well-known URL, a pin-store key, a local file path, a DNS lookup name --
// MUST pass it through ValidateDomain first. The grammar is the RFC 1123
// hostname grammar, restricted further so the value cannot be confused with a
// URL, a path, an IP literal or an IDN U-label:
//
//   - ASCII only (internationalized names must be given as punycode A-labels)
//   - at least two labels, each 1-63 characters of [a-z0-9-] that neither start
//     nor end with "-"
//   - total length at most 253 characters
//   - the last label is not purely numeric (rejects IPv4 literals)
//   - no scheme, path, port, userinfo or trailing dot
//
// The returned value is lowercased so pin keys and file names are consistent
// regardless of how the caller spelled the domain.
package domain

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// MaxDomainLength is the maximum total length of a domain name.
const MaxDomainLength = 253

// ErrInvalidDomain wraps every validation failure so callers can test for it
// with errors.Is.
var ErrInvalidDomain = errors.New("invalid domain")

var labelRe = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
var digitsRe = regexp.MustCompile(`^[0-9]+$`)

// ValidateDomain validates domain and returns its normalized (lowercase) form.
func ValidateDomain(domain string) (string, error) {
	if domain == "" {
		return "", fmt.Errorf("%w: domain must be a non-empty string", ErrInvalidDomain)
	}
	if len(domain) > MaxDomainLength {
		return "", fmt.Errorf("%w: domain exceeds %d characters", ErrInvalidDomain, MaxDomainLength)
	}
	for i := 0; i < len(domain); i++ {
		if domain[i] > 0x7f {
			return "", fmt.Errorf("%w: domain must be ASCII; encode internationalized names as punycode", ErrInvalidDomain)
		}
	}
	normalized := strings.ToLower(domain)
	labels := strings.Split(normalized, ".")
	if len(labels) < 2 {
		return "", fmt.Errorf("%w: domain %q must contain at least two labels", ErrInvalidDomain, domain)
	}
	for _, label := range labels {
		if !labelRe.MatchString(label) {
			return "", fmt.Errorf("%w: domain %q has an invalid label %q", ErrInvalidDomain, domain, label)
		}
	}
	if digitsRe.MatchString(labels[len(labels)-1]) {
		return "", fmt.Errorf("%w: domain %q looks like an IP literal", ErrInvalidDomain, domain)
	}
	return normalized, nil
}

// IsValidDomain reports whether ValidateDomain would accept domain.
func IsValidDomain(domain string) bool {
	_, err := ValidateDomain(domain)
	return err == nil
}
