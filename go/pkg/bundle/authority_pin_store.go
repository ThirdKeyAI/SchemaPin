package bundle

// In-memory TOFU pin store for bundle authorities (v1.4).
//
// Mirrors the Rust schemapin::pinning::KeyPinStore semantics used by
// verify_trust_bundle: authorities are pinned by a composite "kid@domain" key
// (domain is always BundleAuthorityPinDomain here), trust-on-first-use, and a
// later fingerprint that does not match a pinned one is reported as Changed.
//
// This is deliberately a lightweight in-memory store rather than the BoltDB
// KeyPinning type so bundle distribution stays self-contained and easy to embed
// (matching the Rust reference, which uses an in-memory store for authorities).

import "fmt"

// PinningResult is the outcome of checking a key fingerprint against the store.
type PinningResult int

const (
	// PinningResultFirstUse means this kid@domain had not been seen before and
	// the fingerprint has now been pinned (TOFU).
	PinningResultFirstUse PinningResult = iota
	// PinningResultMatched means the fingerprint matches a previously pinned key.
	PinningResultMatched
	// PinningResultChanged means kid@domain was seen before but the fingerprint
	// does not match any pinned key (impersonation / rotation).
	PinningResultChanged
)

// AuthorityPinStore is an in-memory TOFU store keyed by "kid@domain".
type AuthorityPinStore struct {
	fingerprints map[string]string
}

// NewAuthorityPinStore creates an empty authority pin store.
func NewAuthorityPinStore() *AuthorityPinStore {
	return &AuthorityPinStore{fingerprints: map[string]string{}}
}

func compositeKey(kid, domain string) string {
	return fmt.Sprintf("%s@%s", kid, domain)
}

// CheckAndPin checks a fingerprint against the store. The first time a kid@domain
// is seen the fingerprint is pinned and PinningResultFirstUse is returned;
// thereafter a matching fingerprint returns PinningResultMatched and a differing
// one returns PinningResultChanged.
func (s *AuthorityPinStore) CheckAndPin(kid, domain, fingerprint string) PinningResult {
	key := compositeKey(kid, domain)
	pinned, ok := s.fingerprints[key]
	if !ok {
		s.fingerprints[key] = fingerprint
		return PinningResultFirstUse
	}
	if pinned == fingerprint {
		return PinningResultMatched
	}
	return PinningResultChanged
}
