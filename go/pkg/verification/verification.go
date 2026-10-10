// Package verification provides offline and resolver-based schema verification for SchemaPin v1.2.
package verification

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/ThirdKeyAi/schemapin/go/pkg/core"
	"github.com/ThirdKeyAi/schemapin/go/pkg/crypto"
	"github.com/ThirdKeyAi/schemapin/go/pkg/discovery"
	"github.com/ThirdKeyAi/schemapin/go/pkg/dns"
	"github.com/ThirdKeyAi/schemapin/go/pkg/domain"
	"github.com/ThirdKeyAi/schemapin/go/pkg/resolver"
	"github.com/ThirdKeyAi/schemapin/go/pkg/revocation"
)

// ExpirationSkewSeconds is the clock-skew tolerance applied to expires_at
// comparisons.
const ExpirationSkewSeconds = 300

var rfc3339Re = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$`)

// ParseRFC3339 parses a strict RFC 3339 timestamp (T separator, mandatory
// offset). Date-only strings and local times without an offset are rejected.
func ParseRFC3339(value string) (time.Time, bool) {
	if !rfc3339Re.MatchString(value) {
		return time.Time{}, false
	}
	ts, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}, false
	}
	return ts.UTC(), true
}

// Warning constants for v1.4 signature expiration semantics.
const (
	// WarningSignatureExpired is appended to VerificationResult.Warnings when
	// a signature carried an expires_at field that has passed and the caller
	// opted in with allowExpired (degraded, not failed).
	WarningSignatureExpired = "signature_expired"
	// WarningSignatureExpiresAtUnparseable is appended when a signature's
	// expires_at field could not be parsed as RFC 3339 and the caller opted
	// in with allowExpired.
	WarningSignatureExpiresAtUnparseable = "signature_expires_at_unparseable"
	// WarningLegacySignatureFormat is appended when a skill signature uses the
	// pre-1.4 root-hash-only format whose metadata fields are unsigned.
	WarningLegacySignatureFormat = "legacy_signature_format"
	// WarningDomainUnbound is appended when the caller did not bind the
	// expected domain and the signature's own domain field was used.
	WarningDomainUnbound = "domain_unbound"
)

// ErrorCode represents structured error codes for verification results.
type ErrorCode string

const (
	ErrSignatureInvalid             ErrorCode = "signature_invalid"
	ErrKeyNotFound                  ErrorCode = "key_not_found"
	ErrKeyRevoked                   ErrorCode = "key_revoked"
	ErrKeyPinMismatch               ErrorCode = "key_pin_mismatch"
	ErrDiscoveryFetchFailed         ErrorCode = "discovery_fetch_failed"
	ErrDiscoveryInvalid             ErrorCode = "discovery_invalid"
	ErrDomainMismatch               ErrorCode = "domain_mismatch"
	ErrSchemaCanonicalizationFailed ErrorCode = "schema_canonicalization_failed"
	// ErrCanonicalizationUnsupported (v1.4 alpha.3) — signature declared a
	// canonicalization algorithm this verifier does not support.
	ErrCanonicalizationUnsupported ErrorCode = "canonicalization_unsupported"
	// ErrA2AScopeViolation (v1.4 alpha.3) — A2A scope violation (provider
	// domain not in caller's trusted_domains, or delegation_depth exceeded).
	ErrA2AScopeViolation ErrorCode = "a2a_scope_violation"
	// ErrBundleUnsigned (v1.4) — a trust bundle was passed to VerifyTrustBundle
	// without a bundle_authority / signature pair. Bundle distribution requires
	// a signed bundle.
	ErrBundleUnsigned ErrorCode = "bundle_unsigned"
	// ErrBundleExpired (v1.4) — a signed trust bundle's expires_at is in the
	// past (or unparseable).
	ErrBundleExpired ErrorCode = "bundle_expired"
	// ErrSignatureExpired — a signature's expires_at is in the past (or
	// unparseable) and the caller did not opt in with AllowExpired. Hard failure.
	ErrSignatureExpired ErrorCode = "signature_expired"
	// ErrDomainInvalid — the caller-supplied domain is not a valid RFC 1123 hostname.
	ErrDomainInvalid ErrorCode = "domain_invalid"
	// ErrBundleAuthorityUntrusted — a trust bundle's authority key is not
	// pre-seeded in the authority store and first-use trust was not allowed.
	ErrBundleAuthorityUntrusted ErrorCode = "bundle_authority_untrusted"
)

// CanonicalizationV1 is the algorithm identifier (v1.4 alpha.3) for the
// sorted-key, no-whitespace, UTF-8 canonicalization implemented in
// core.SchemaPinCore. Signatures MAY carry a "canonicalization" field
// naming the algorithm used to produce the signing input. Absence is
// equivalent to this identifier for backward compatibility with v1.3
// signatures. Verifiers MUST reject any other value as
// ErrCanonicalizationUnsupported.
const CanonicalizationV1 = "schemapin-v1"

// CheckCanonicalization returns the empty string when `algorithm` names a
// canonicalization algorithm this SDK supports, or the offending value
// otherwise.
//
// An empty string input means the field is absent and is equivalent to the
// default schemapin-v1 algorithm (v1.3 backward compatibility).
func CheckCanonicalization(algorithm string) string {
	if algorithm == "" || algorithm == CanonicalizationV1 {
		return ""
	}
	return algorithm
}

// KeyPinningStatus represents the pinning status in a verification result.
type KeyPinningStatus struct {
	Status    string `json:"status"`
	FirstSeen string `json:"first_seen,omitempty"`
}

// VerificationResult is the structured result from schema verification.
//
// The Expired and ExpiresAt fields are v1.4 additions for the optional
// signature expiration feature. Expired signals that a signature carried an
// expires_at timestamp that has passed; Valid is left untouched (degraded,
// not failed) so callers can apply policy decisions independently.
type VerificationResult struct {
	Valid         bool              `json:"valid"`
	Domain        string            `json:"domain,omitempty"`
	DeveloperName string            `json:"developer_name,omitempty"`
	KeyPinning    *KeyPinningStatus `json:"key_pinning,omitempty"`
	ErrorCode     ErrorCode         `json:"error_code,omitempty"`
	ErrorMessage  string            `json:"error_message,omitempty"`
	Warnings      []string          `json:"warnings,omitempty"`
	// Expired is true when the signature carried an expires_at value that
	// is in the past at verification time. Valid remains true (degraded).
	Expired bool `json:"expired,omitempty"`
	// ExpiresAt mirrors the signature's expires_at value when present.
	ExpiresAt string `json:"expires_at,omitempty"`
	// SchemaVersion (v1.4 alpha.2) mirrors the signature's schema_version
	// field when present -- a caller-supplied semver string identifying
	// *this* version of the artifact, surfaced for policy use.
	SchemaVersion string `json:"schema_version,omitempty"`
	// PreviousHash (v1.4 alpha.2) mirrors the signature's previous_hash
	// field when present -- sha256:<hex> of the prior signed version's
	// SkillHash. Pair with skill.VerifyChain to confirm lineage.
	PreviousHash string `json:"previous_hash,omitempty"`
}

// WithExpirationCheck applies a v1.4 signature expiration check and returns
// the (possibly mutated) receiver. It is fail-closed: see WithExpirationPolicy.
// Equivalent to WithExpirationPolicy(expiresAt, false).
func (r *VerificationResult) WithExpirationCheck(expiresAt string) *VerificationResult {
	return r.WithExpirationPolicy(expiresAt, false)
}

// WithExpirationPolicy applies a signature expiration check:
//
//   - expiresAt == "" returns the receiver unchanged.
//   - A value that is not strict RFC 3339 fails with ErrSignatureExpired
//     (allowExpired downgrades this to a WarningSignatureExpiresAtUnparseable
//     warning).
//   - A timestamp more than ExpirationSkewSeconds in the past fails with
//     ErrSignatureExpired and sets Expired. With allowExpired the result stays
//     Valid but is marked Expired and carries a WarningSignatureExpired
//     warning (the pre-1.4.0 "degraded, not failed" behavior).
//   - A future timestamp just records ExpiresAt.
//
// The receiver may be nil; in that case it is returned unchanged.
func (r *VerificationResult) WithExpirationPolicy(expiresAt string, allowExpired bool) *VerificationResult {
	if r == nil || expiresAt == "" {
		return r
	}
	ts, ok := ParseRFC3339(expiresAt)
	if !ok {
		if allowExpired {
			r.Warnings = append(r.Warnings, WarningSignatureExpiresAtUnparseable)
			return r
		}
		r.Valid = false
		r.ErrorCode = ErrSignatureExpired
		r.ErrorMessage = fmt.Sprintf("expires_at is not a valid RFC 3339 timestamp: %q", expiresAt)
		return r
	}
	r.ExpiresAt = expiresAt
	if time.Now().UTC().After(ts.Add(ExpirationSkewSeconds * time.Second)) {
		r.Expired = true
		if allowExpired {
			r.Warnings = append(r.Warnings, WarningSignatureExpired)
		} else {
			r.Valid = false
			r.ErrorCode = ErrSignatureExpired
			r.ErrorMessage = fmt.Sprintf("signature expired at %s", expiresAt)
		}
	}
	return r
}

// WithLineageMetadata copies v1.4 alpha.2 schema_version and previous_hash
// fields onto a successful VerificationResult and returns the receiver.
//
// No semantic enforcement -- these are informational fields callers use for
// version policy and chain verification (see skill.VerifyChain).
//
// The receiver may be nil; in that case it is returned unchanged.
func (r *VerificationResult) WithLineageMetadata(schemaVersion, previousHash string) *VerificationResult {
	if r == nil {
		return r
	}
	if schemaVersion != "" {
		r.SchemaVersion = schemaVersion
	}
	if previousHash != "" {
		r.PreviousHash = previousHash
	}
	return r
}

// PinResult represents the result of a pin check.
type PinResult string

const (
	PinFirstUse PinResult = "first_use"
	PinPinned   PinResult = "pinned"
	PinChanged  PinResult = "changed"
)

// KeyPinStore is a lightweight in-memory fingerprint-based pin store.
//
// Keys are stored by tool_id@domain. Verification flows use Check before the
// signature check and Pin only after it succeeds, so a failed verification
// never leaves a pin behind. Operators can pre-seed expected fingerprints with
// Seed.
type KeyPinStore struct {
	pins map[string]string
}

// NewKeyPinStore creates a new empty KeyPinStore.
func NewKeyPinStore() *KeyPinStore {
	return &KeyPinStore{pins: make(map[string]string)}
}

func pinKey(toolID, domain string) string {
	return toolID + "@" + domain
}

// Check compares fingerprint with the pinned value without mutating the store.
func (s *KeyPinStore) Check(toolID, domain, fingerprint string) PinResult {
	existing, ok := s.pins[pinKey(toolID, domain)]
	if !ok {
		return PinFirstUse
	}
	if existing == fingerprint {
		return PinPinned
	}
	return PinChanged
}

// Pin stores fingerprint for tool@domain (overwrites).
func (s *KeyPinStore) Pin(toolID, domain, fingerprint string) {
	s.pins[pinKey(toolID, domain)] = fingerprint
}

// Seed pre-seeds an expected fingerprint (out-of-band trust establishment).
func (s *KeyPinStore) Seed(toolID, domain, fingerprint string) {
	s.Pin(toolID, domain, fingerprint)
}

// CheckAndPin checks and pins on first use in one step. Prefer Check + Pin so
// that pinning can be deferred until after signature verification.
func (s *KeyPinStore) CheckAndPin(toolID, domain, fingerprint string) PinResult {
	result := s.Check(toolID, domain, fingerprint)
	if result == PinFirstUse {
		s.Pin(toolID, domain, fingerprint)
	}
	return result
}

// GetPinned returns the pinned fingerprint for a tool@domain, or empty string.
func (s *KeyPinStore) GetPinned(toolID, domain string) string {
	return s.pins[pinKey(toolID, domain)]
}

// ToJSON serializes the pin store to JSON.
func (s *KeyPinStore) ToJSON() (string, error) {
	data, err := json.Marshal(s.pins)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// FromJSON deserializes a pin store from JSON.
func FromJSON(jsonStr string) (*KeyPinStore, error) {
	store := NewKeyPinStore()
	if err := json.Unmarshal([]byte(jsonStr), &store.pins); err != nil {
		return nil, err
	}
	if store.pins == nil {
		return nil, fmt.Errorf("pin store JSON must be an object of string fingerprints")
	}
	return store, nil
}

// VerifySchemaOffline verifies a schema offline using pre-fetched discovery and revocation data.
//
// Verification flow:
//  1. Validate the canonicalization identifier and the domain syntax
//  2. Validate discovery document
//  3. Extract public key and compute fingerprint
//  4. Check revocation (both simple list + standalone doc)
//  5. TOFU pin check (read-only)
//  6. Canonicalize schema, compute hash, verify ECDSA signature
//  7. Pin the key on first use (only after a successful verification)
//  8. Return structured result
//
// Use VerifySchemaOfflineWithCanonicalization when the signature carries
// a v1.4 canonicalization algorithm identifier; this thin wrapper
// passes the empty string (== default schemapin-v1).
func VerifySchemaOffline(
	schema map[string]interface{},
	signatureB64 string,
	domain string,
	toolID string,
	disc *discovery.WellKnownResponse,
	rev *revocation.RevocationDocument,
	pinStore *KeyPinStore,
) *VerificationResult {
	return VerifySchemaOfflineWithCanonicalization(
		schema, signatureB64, domain, toolID, disc, rev, pinStore, "",
	)
}

// VerifySchemaOfflineWithCanonicalization is VerifySchemaOffline plus the
// optional v1.4 canonicalization algorithm parameter.
//
// `canonicalization` mirrors the optional "canonicalization" field on
// .schemapin.sig documents. Empty string or "schemapin-v1" are equivalent
// and accepted; any other value fails with ErrCanonicalizationUnsupported
// before any crypto work.
func VerifySchemaOfflineWithCanonicalization(
	schema map[string]interface{},
	signatureB64 string,
	domainName string,
	toolID string,
	disc *discovery.WellKnownResponse,
	rev *revocation.RevocationDocument,
	pinStore *KeyPinStore,
	canonicalization string,
) *VerificationResult {
	// Step 1: canonicalization algorithm + domain syntax.
	if bad := CheckCanonicalization(canonicalization); bad != "" {
		return &VerificationResult{
			Valid:        false,
			Domain:       domainName,
			ErrorCode:    ErrCanonicalizationUnsupported,
			ErrorMessage: fmt.Sprintf("Unsupported canonicalization algorithm: %s", bad),
		}
	}
	normalized, err := domain.ValidateDomain(domainName)
	if err != nil {
		return &VerificationResult{
			Valid:        false,
			Domain:       domainName,
			ErrorCode:    ErrDomainInvalid,
			ErrorMessage: err.Error(),
		}
	}
	domainName = normalized

	// Step 2: Validate discovery document
	if disc == nil || disc.PublicKeyPEM == "" || !strings.Contains(disc.PublicKeyPEM, "-----BEGIN PUBLIC KEY-----") {
		return &VerificationResult{
			Valid:        false,
			Domain:       domainName,
			ErrorCode:    ErrDiscoveryInvalid,
			ErrorMessage: "Discovery document missing or invalid public_key_pem",
		}
	}

	// Step 3: Extract public key and compute fingerprint
	keyManager := crypto.NewKeyManager()
	publicKey, err := keyManager.LoadPublicKeyPEM(disc.PublicKeyPEM)
	if err != nil {
		return &VerificationResult{
			Valid:        false,
			Domain:       domainName,
			ErrorCode:    ErrKeyNotFound,
			ErrorMessage: fmt.Sprintf("Failed to load public key: %v", err),
		}
	}

	fingerprint, err := keyManager.CalculateKeyFingerprintFromPEM(disc.PublicKeyPEM)
	if err != nil {
		return &VerificationResult{
			Valid:        false,
			Domain:       domainName,
			ErrorCode:    ErrKeyNotFound,
			ErrorMessage: fmt.Sprintf("Failed to calculate fingerprint: %v", err),
		}
	}

	// Step 4: Check revocation
	if err := revocation.CheckRevocationCombined(disc.RevokedKeys, rev, fingerprint); err != nil {
		return &VerificationResult{
			Valid:        false,
			Domain:       domainName,
			ErrorCode:    ErrKeyRevoked,
			ErrorMessage: err.Error(),
		}
	}

	// Step 5: TOFU pin check (no write yet)
	if pinStore == nil {
		pinStore = NewKeyPinStore()
	}
	pinResult := pinStore.Check(toolID, domainName, fingerprint)
	if pinResult == PinChanged {
		return &VerificationResult{
			Valid:        false,
			Domain:       domainName,
			ErrorCode:    ErrKeyPinMismatch,
			ErrorMessage: "Key fingerprint changed since last use",
		}
	}

	// Step 6: Canonicalize, hash, verify
	c := core.NewSchemaPinCore()
	schemaHash, err := c.CanonicalizeAndHash(schema)
	if err != nil {
		return &VerificationResult{
			Valid:        false,
			Domain:       domainName,
			ErrorCode:    ErrSchemaCanonicalizationFailed,
			ErrorMessage: fmt.Sprintf("Failed to canonicalize schema: %v", err),
		}
	}

	sigManager := crypto.NewSignatureManager()
	valid := sigManager.VerifySchemaSignature(schemaHash, signatureB64, publicKey)

	if !valid {
		return &VerificationResult{
			Valid:        false,
			Domain:       domainName,
			ErrorCode:    ErrSignatureInvalid,
			ErrorMessage: "Signature verification failed",
		}
	}

	// Step 7: Pin only after the signature verified
	if pinResult == PinFirstUse {
		pinStore.Pin(toolID, domainName, fingerprint)
	}

	// Step 8: Return success
	result := &VerificationResult{
		Valid:         true,
		Domain:        domainName,
		DeveloperName: disc.DeveloperName,
		KeyPinning: &KeyPinningStatus{
			Status: string(pinResult),
		},
		Warnings: []string{},
	}

	if disc.SchemaVersion != "" && disc.SchemaVersion < "1.2" {
		result.Warnings = append(result.Warnings,
			fmt.Sprintf("Discovery uses schema version %s, consider upgrading to 1.2", disc.SchemaVersion))
	}

	return result
}

// VerifySchemaOfflineWithDNS is VerifySchemaOffline plus a DNS TXT
// second-channel check. When txt is non-nil the discovery key's fingerprint
// must match the TXT record or the result is a hard ErrDomainMismatch failure.
// The DNS check runs before anything is pinned.
func VerifySchemaOfflineWithDNS(
	schema map[string]interface{},
	signatureB64 string,
	domainName string,
	toolID string,
	disc *discovery.WellKnownResponse,
	rev *revocation.RevocationDocument,
	pinStore *KeyPinStore,
	txt *dns.DnsTxtRecord,
	canonicalization string,
) *VerificationResult {
	if txt != nil {
		if err := dns.VerifyDnsMatch(disc, txt); err != nil {
			return &VerificationResult{
				Valid:        false,
				Domain:       domainName,
				ErrorCode:    ErrDomainMismatch,
				ErrorMessage: err.Error(),
			}
		}
	}
	return VerifySchemaOfflineWithCanonicalization(schema, signatureB64, domainName, toolID, disc, rev, pinStore, canonicalization)
}

// VerifySchemaWithResolver verifies a schema using a resolver for discovery and revocation.
//
// Revocation is fail-closed: if the discovery document declares a
// revocation_endpoint that cannot be fetched, verification fails with
// ErrDiscoveryFetchFailed. Use VerifySchemaWithResolverOptions to opt out.
func VerifySchemaWithResolver(
	schema map[string]interface{},
	signatureB64 string,
	domainName string,
	toolID string,
	r resolver.SchemaResolver,
	pinStore *KeyPinStore,
) *VerificationResult {
	return VerifySchemaWithResolverOptions(schema, signatureB64, domainName, toolID, r, pinStore, ResolverOptions{})
}

// ResolverOptions tunes the resolver-based verification flows.
type ResolverOptions struct {
	// AllowUnreachableRevocation treats a revocation fetch failure as "no
	// revocations" instead of failing closed.
	AllowUnreachableRevocation bool
	// AllowExpired accepts expired skill signatures (degraded) instead of
	// failing with ErrSignatureExpired. Ignored for schema signatures.
	AllowExpired bool
}

// VerifySchemaWithResolverOptions is VerifySchemaWithResolver with explicit
// policy knobs.
func VerifySchemaWithResolverOptions(
	schema map[string]interface{},
	signatureB64 string,
	domainName string,
	toolID string,
	r resolver.SchemaResolver,
	pinStore *KeyPinStore,
	opts ResolverOptions,
) *VerificationResult {
	normalized, err := domain.ValidateDomain(domainName)
	if err != nil {
		return &VerificationResult{
			Valid:        false,
			Domain:       domainName,
			ErrorCode:    ErrDomainInvalid,
			ErrorMessage: err.Error(),
		}
	}
	domainName = normalized

	disc, err := r.ResolveDiscovery(domainName)
	if err != nil {
		return &VerificationResult{
			Valid:        false,
			Domain:       domainName,
			ErrorCode:    ErrDiscoveryFetchFailed,
			ErrorMessage: fmt.Sprintf("Could not resolve discovery for domain: %s", domainName),
		}
	}

	rev, err := r.ResolveRevocation(domainName, disc)
	if err != nil {
		if !opts.AllowUnreachableRevocation {
			return &VerificationResult{
				Valid:        false,
				Domain:       domainName,
				ErrorCode:    ErrDiscoveryFetchFailed,
				ErrorMessage: fmt.Sprintf("Revocation document unreachable (fail-closed): %v", err),
			}
		}
		rev = nil
	}

	return VerifySchemaOffline(schema, signatureB64, domainName, toolID, disc, rev, pinStore)
}

// VerifySchemaForA2A verifies a schema in the context of an A2A interaction
// (v1.4 alpha.3).
//
// Wraps VerifySchemaOfflineWithCanonicalization with an A2A scope check:
//
//  1. Reject when context.DelegationDepth > A2AMaxDelegationDepth.
//     Surfaces as ErrA2AScopeViolation.
//  2. Run the standard 7-step verification. If it fails, return that
//     result unchanged.
//  3. Reject when context.TrustedDomains is non-empty and domain is not
//     allowed by it. Surfaces as ErrA2AScopeViolation.
//
// On success the returned VerificationResult is the result from step 2
// unchanged — A2A context does not modify the cryptographic outcome, only
// the policy outcome.
func VerifySchemaForA2A(
	schema map[string]interface{},
	signatureB64 string,
	domain string,
	toolID string,
	disc *discovery.WellKnownResponse,
	rev *revocation.RevocationDocument,
	pinStore *KeyPinStore,
	context *A2AVerificationContext,
	canonicalization string,
) *VerificationResult {
	if context != nil && context.DelegationDepth > A2AMaxDelegationDepth {
		return &VerificationResult{
			Valid:     false,
			Domain:    domain,
			ErrorCode: ErrA2AScopeViolation,
			ErrorMessage: fmt.Sprintf(
				"A2A delegation_depth %d exceeds cap of %d",
				context.DelegationDepth, A2AMaxDelegationDepth,
			),
		}
	}

	result := VerifySchemaOfflineWithCanonicalization(
		schema, signatureB64, domain, toolID, disc, rev, pinStore, canonicalization,
	)
	if !result.Valid {
		return result
	}

	var trusted []string
	if context != nil {
		trusted = context.TrustedDomains
	}
	if !A2AAllows(trusted, domain) {
		return &VerificationResult{
			Valid:     false,
			Domain:    domain,
			ErrorCode: ErrA2AScopeViolation,
			ErrorMessage: fmt.Sprintf(
				"Provider domain '%s' not in caller's A2A trusted_domains scope",
				domain,
			),
		}
	}

	return result
}
