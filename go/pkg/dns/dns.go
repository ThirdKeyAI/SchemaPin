// Package dns implements the v1.4 DNS TXT cross-verification feature.
//
// A tool provider MAY publish a TXT record at _schemapin.{domain} containing
// the public-key fingerprint advertised in .well-known/schemapin.json. When
// present, clients use it as a second-channel verification: the DNS
// credential chain is independent of the HTTPS hosting credential chain, so
// compromising one does not compromise the other.
//
// TXT record format:
//
//	_schemapin.example.com. IN TXT "v=schemapin1; kid=acme-2026-01; fp=sha256:a1b2c3..."
//
// Fields:
//   - v   -- version tag (schemapin1); required
//   - fp  -- key fingerprint (sha256:<hex>); required, lowercase hex
//   - kid -- optional key id, used for disambiguating multi-key endpoints
//
// Verification semantics:
//   - Absent record           -> no effect (DNS TXT is optional)
//   - Present and matching    -> confidence boost (no warning emitted)
//   - Present and mismatching -> hard failure with verification.ErrDomainMismatch
//
// Use ParseTxtRecord to parse a raw TXT string and VerifyDnsMatch to
// cross-check it against a discovery document. FetchDnsTxt performs the
// actual lookup using the Go stdlib resolver -- no external dependency.
package dns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/ThirdKeyAi/schemapin/go/pkg/crypto"
	"github.com/ThirdKeyAi/schemapin/go/pkg/discovery"
)

// DnsTxtRecord is a parsed _schemapin.{domain} TXT record.
type DnsTxtRecord struct {
	// Version is the protocol tag; currently always "schemapin1".
	Version string
	// Kid is the optional key id; empty when not present.
	Kid string
	// Fingerprint is the lowercase fingerprint string, including the
	// "sha256:" prefix. Always lower-case after parsing.
	Fingerprint string
}

// ParseTxtRecord parses a raw TXT record value such as
// "v=schemapin1; kid=acme-2026-01; fp=sha256:abcd...".
//
// Whitespace around ';' and '=' is tolerated. Field order is not significant.
// Unknown fields are ignored for forward compatibility. Returns an error if
// the record is missing the required 'v' or 'fp' fields, has an unsupported
// version, has a fingerprint without the "sha256:" prefix, or contains a
// field without an '=' separator.
func ParseTxtRecord(value string) (*DnsTxtRecord, error) {
	var (
		version string
		kid     string
		fp      string
		hasV    bool
		hasFp   bool
	)

	for _, raw := range strings.Split(value, ";") {
		part := strings.TrimSpace(raw)
		if part == "" {
			continue
		}
		idx := strings.Index(part, "=")
		if idx < 0 {
			return nil, fmt.Errorf("DNS TXT field missing '=': %s", part)
		}
		k := strings.ToLower(strings.TrimSpace(part[:idx]))
		v := strings.TrimSpace(part[idx+1:])
		switch k {
		case "v":
			version = v
			hasV = true
		case "kid":
			kid = v
		case "fp":
			fp = strings.ToLower(v)
			hasFp = true
		default:
			// Forward-compat: ignore unknown fields rather than reject.
		}
	}

	if !hasV {
		return nil, errors.New("DNS TXT record missing required 'v' field")
	}
	if version != "schemapin1" {
		return nil, fmt.Errorf("DNS TXT unsupported version: %s", version)
	}
	if !hasFp {
		return nil, errors.New("DNS TXT record missing required 'fp' field")
	}
	if !strings.HasPrefix(fp, "sha256:") {
		return nil, fmt.Errorf("DNS TXT 'fp' must be sha256:<hex>: %s", fp)
	}

	return &DnsTxtRecord{
		Version:     version,
		Kid:         kid,
		Fingerprint: fp,
	}, nil
}

// VerifyDnsMatch cross-checks the DNS TXT record's fingerprint against the
// discovery document's public key.
//
// Returns nil when the fingerprint matches the SHA-256 fingerprint of the
// public key in discovery.PublicKeyPEM. Returns an error otherwise. Callers
// MUST treat any non-nil return as a hard verification failure
// (verification.ErrDomainMismatch).
func VerifyDnsMatch(disc *discovery.WellKnownResponse, txt *DnsTxtRecord) error {
	if disc == nil {
		return errors.New("DNS TXT match requires a non-nil discovery document")
	}
	if txt == nil {
		return errors.New("DNS TXT match requires a non-nil record")
	}
	keyManager := crypto.NewKeyManager()
	computed, err := keyManager.CalculateKeyFingerprintFromPEM(disc.PublicKeyPEM)
	if err != nil {
		return fmt.Errorf("DNS TXT match: failed to compute fingerprint: %w", err)
	}
	computed = strings.ToLower(computed)
	if computed != txt.Fingerprint {
		return fmt.Errorf("DNS TXT fingerprint mismatch: discovery=%s, dns=%s", computed, txt.Fingerprint)
	}
	return nil
}

// TxtRecordName returns the DNS lookup name for a given tool domain
// ("_schemapin." prepended; trailing dot stripped).
func TxtRecordName(domain string) string {
	return "_schemapin." + strings.TrimSuffix(domain, ".")
}

// FetchDnsTxt fetches and parses the _schemapin.{domain} TXT record using
// the Go stdlib resolver.
//
// Returns:
//   - (record, nil) -- record present and parseable
//   - (nil, nil)    -- no _schemapin TXT record exists for the domain
//   - (nil, err)    -- DNS resolution error or the record is malformed
//
// Multi-chunk TXT records are concatenated per RFC 1464 (in emit order).
// When multiple TXT records exist at the same name, the first one whose
// joined value contains "v=schemapin1" is selected.
func FetchDnsTxt(ctx context.Context, domain string) (*DnsTxtRecord, error) {
	name := TxtRecordName(domain)
	resolver := &net.Resolver{}
	records, err := resolver.LookupTXT(ctx, name)
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			return nil, nil
		}
		return nil, fmt.Errorf("DNS TXT lookup failed for %s: %w", name, err)
	}

	// Note: net.Resolver.LookupTXT already concatenates multi-chunk strings
	// within a single TXT RR into one entry, so each element here is the
	// full record.
	for _, rec := range records {
		if strings.Contains(rec, "v=schemapin1") {
			return ParseTxtRecord(rec)
		}
	}
	return nil, nil
}
