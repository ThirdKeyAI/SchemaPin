package bundle

// (v1.4) Trust-bundle distribution for A2A networks.
//
// Lets a bundle authority sign a SchemaPinTrustBundle so it can be exchanged
// between agents over A2A without per-bundle out-of-band trust establishment.
// Provides:
//
//   - SignTrustBundle / VerifyTrustBundle — ECDSA P-256 over the canonical
//     bundle bytes, with an authority allow-list: the authority key must be
//     pre-seeded in the AuthorityPinStore (SeedBundleAuthority) unless the
//     caller explicitly opts in to first-use trust.
//   - MergeTrustBundles — combine bundles from multiple sources with
//     per-authority precedence and parsed-timestamp tie-breaking.
//   - BuildTrustBundleRequest / BuildTrustBundleResponse /
//     ParseTrustBundleResponse — the schemapin/trustBundle JSON-RPC envelope
//     for A2A bundle exchange.
//
// # Signing input
//
// The signature covers the schemapin-v1 canonicalization of the bundle's
// known fields (unknown fields are ignored and therefore unprotected) with the
// signature field set to the empty string "". All four SDKs build the
// identical byte string, so a bundle signed by any SDK verifies in every other.

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"time"

	"github.com/ThirdKeyAi/schemapin/go/pkg/core"
	"github.com/ThirdKeyAi/schemapin/go/pkg/crypto"
	"github.com/ThirdKeyAi/schemapin/go/pkg/revocation"
)

var rfc3339Strict = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$`)

func parseRFC3339Strict(value string) (time.Time, bool) {
	if !rfc3339Strict.MatchString(value) {
		return time.Time{}, false
	}
	ts, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}, false
	}
	return ts.UTC(), true
}

// ErrorCode mirrors ErrorCode for the bundle-distribution error
// surface. The values are kept identical to the verification package so callers
// can compare across both. The bundle package defines them locally rather than
// importing verification because verification -> resolver -> bundle forms an
// import cycle.
type ErrorCode = string

const (
	// ErrBundleUnsigned (v1.4) — a bundle was passed to VerifyTrustBundle
	// without a bundle_authority / signature pair.
	ErrBundleUnsigned ErrorCode = "bundle_unsigned"
	// ErrBundleExpired (v1.4) — a signed bundle's expires_at is in the past
	// (or unparseable).
	ErrBundleExpired ErrorCode = "bundle_expired"
	// ErrKeyPinMismatch — the bundle authority's key changed since first pin.
	ErrKeyPinMismatch ErrorCode = "key_pin_mismatch"
	// ErrSignatureInvalid — the bundle signature does not verify.
	ErrSignatureInvalid ErrorCode = "signature_invalid"
	// ErrDiscoveryInvalid — a JSON-RPC response was missing result.bundle, or
	// a bundle carries duplicate domain entries.
	ErrDiscoveryInvalid ErrorCode = "discovery_invalid"
	// ErrKeyNotFound — the bundle authority public key is not a valid P-256 key.
	ErrKeyNotFound ErrorCode = "key_not_found"
	// ErrBundleAuthorityUntrusted — the authority kid is not in the allow-list
	// and first-use trust was not allowed.
	ErrBundleAuthorityUntrusted ErrorCode = "bundle_authority_untrusted"
)

// BundleVerification is the successful outcome of VerifyTrustBundleWithOptions.
// FirstUse is true when the authority key was not pre-seeded and the caller
// allowed first-use trust; hosts should surface this exactly like a first-use
// tool key.
type BundleVerification struct {
	Kid         string
	Fingerprint string
	FirstUse    bool
}

// BundleVerifyOptions tunes VerifyTrustBundleWithOptions.
type BundleVerifyOptions struct {
	// AllowFirstUse pins an unknown authority on first use (TOFU) instead of
	// failing with ErrBundleAuthorityUntrusted.
	AllowFirstUse bool
}

// SeedBundleAuthority pre-seeds the expected fingerprint (sha256:<hex>) of a
// bundle authority. This is the allow-list entry VerifyTrustBundle requires.
func SeedBundleAuthority(store *AuthorityPinStore, kid, fingerprint string) {
	store.Seed(kid, BundleAuthorityPinDomain, fingerprint)
}

// SeedBundleAuthorityFromPEM seeds an authority from its PEM public key (for
// example the public_key_pem of the authority's own discovery document) and
// returns the fingerprint.
func SeedBundleAuthorityFromPEM(store *AuthorityPinStore, kid, publicKeyPEM string) (string, error) {
	fingerprint, err := crypto.NewKeyManager().CalculateKeyFingerprintFromPEM(publicKeyPEM)
	if err != nil {
		return "", err
	}
	SeedBundleAuthority(store, kid, fingerprint)
	return fingerprint, nil
}

// DuplicateDomain returns a domain that appears more than once in the bundle's
// documents or revocations, or "" when every domain is unique.
func DuplicateDomain(b *SchemaPinTrustBundle) string {
	seen := map[string]bool{}
	for _, d := range b.Documents {
		if seen[d.Domain] {
			return d.Domain
		}
		seen[d.Domain] = true
	}
	seen = map[string]bool{}
	for _, r := range b.Revocations {
		if seen[r.Domain] {
			return r.Domain
		}
		seen[r.Domain] = true
	}
	return ""
}

// BundleVersionSigned is the bundle-distribution wire format version stamped on
// signed bundles.
const BundleVersionSigned = "1.4"

// BundleAuthorityPinDomain is the sentinel "domain" used to key bundle-authority
// pins in an AuthorityPinStore. Authorities are pinned by kid, independent of
// any tool domain.
const BundleAuthorityPinDomain = "_bundle_authority"

// BundleError is a structured verification error carrying a stable ErrorCode,
// mirroring the Rust Error::Verification variant.
type BundleError struct {
	Code    ErrorCode
	Message string
}

func (e *BundleError) Error() string {
	return fmt.Sprintf("verification failed: %s: %s", e.Code, e.Message)
}

func newBundleError(code ErrorCode, msg string) *BundleError {
	return &BundleError{Code: code, Message: msg}
}

// canonicalizeValue produces the schemapin-v1 canonical form shared by every
// signing path in this module.
func canonicalizeValue(v interface{}) (string, error) {
	return core.CanonicalizeValue(v)
}

// signingBytes builds the canonical bytes that a bundle's signature covers: the
// bundle with its signature field forced to "", schemapin-v1-canonicalized.
//
// The bundle is first marshaled through marshalBundleForSigning (which mirrors
// the Rust serde output field-for-field) so absent optional fields are omitted
// and always-present fields like revoked_keys / revocations are emitted even
// when empty, then re-parsed into a generic map so Go's encoder sorts every
// object key recursively.
func signingBytes(b *SchemaPinTrustBundle) (string, error) {
	raw, err := marshalBundleForSigning(b)
	if err != nil {
		return "", err
	}
	var generic map[string]interface{}
	if err := json.Unmarshal(raw, &generic); err != nil {
		return "", err
	}
	generic["signature"] = ""
	return canonicalizeValue(generic)
}

// marshalBundleForSigning serializes a bundle into the canonical wire shape used
// by all SDKs. It deliberately does NOT reuse BundledDiscovery.MarshalJSON
// (which omits empty revoked_keys) because the cross-language signing input
// always emits revoked_keys / revocations even when empty, matching the Rust
// serde representation.
func marshalBundleForSigning(b *SchemaPinTrustBundle) ([]byte, error) {
	m := map[string]interface{}{
		"schemapin_bundle_version": b.SchemapinBundleVersion,
		"created_at":               b.CreatedAt,
		"documents":                marshalDocuments(b.Documents),
		"revocations":              marshalRevocations(b.Revocations),
	}
	if b.BundleAuthority != nil {
		m["bundle_authority"] = map[string]interface{}{
			"kid":            b.BundleAuthority.Kid,
			"public_key_pem": b.BundleAuthority.PublicKeyPEM,
		}
	}
	if b.SignedAt != "" {
		m["signed_at"] = b.SignedAt
	}
	if b.ExpiresAt != "" {
		m["expires_at"] = b.ExpiresAt
	}
	if b.Signature != "" {
		m["signature"] = b.Signature
	}
	return json.Marshal(m)
}

// marshalDocuments mirrors the Rust WellKnownResponse serde output:
// developer_name / contact / revocation_endpoint are omitted when empty, but
// revoked_keys is always present (possibly []).
func marshalDocuments(docs []BundledDiscovery) []interface{} {
	out := make([]interface{}, 0, len(docs))
	for _, d := range docs {
		m := map[string]interface{}{
			"domain":         d.Domain,
			"schema_version": d.WellKnown.SchemaVersion,
			"public_key_pem": d.WellKnown.PublicKeyPEM,
		}
		if d.WellKnown.DeveloperName != "" {
			m["developer_name"] = d.WellKnown.DeveloperName
		}
		rk := d.WellKnown.RevokedKeys
		if rk == nil {
			rk = []string{}
		}
		m["revoked_keys"] = rk
		if d.WellKnown.Contact != "" {
			m["contact"] = d.WellKnown.Contact
		}
		if d.WellKnown.RevocationEndpoint != "" {
			m["revocation_endpoint"] = d.WellKnown.RevocationEndpoint
		}
		out = append(out, m)
	}
	return out
}

// marshalRevocations serializes revocation documents preserving the always-
// present revoked_keys array so empty slices serialize as [] not null.
func marshalRevocations(revs []revocation.RevocationDocument) []interface{} {
	out := make([]interface{}, 0, len(revs))
	for _, r := range revs {
		keys := make([]interface{}, 0, len(r.RevokedKeys))
		for _, k := range r.RevokedKeys {
			keys = append(keys, map[string]interface{}{
				"fingerprint": k.Fingerprint,
				"revoked_at":  k.RevokedAt,
				"reason":      string(k.Reason),
			})
		}
		out = append(out, map[string]interface{}{
			"schemapin_version": r.SchemapinVersion,
			"domain":            r.Domain,
			"updated_at":        r.UpdatedAt,
			"revoked_keys":      keys,
		})
	}
	return out
}

// SignTrustBundle signs a trust bundle with a bundle-authority key.
//
// Stamps bundle_authority (derived public key + kid),
// schemapin_bundle_version = "1.4", signed_at, and optional expires_at, then
// writes the base64 DER ECDSA P-256 signature. signedAt / expiresAt are
// caller-supplied RFC 3339 strings (kept out of the core so signing is
// deterministic and cross-language testable); pass an empty expiresAt to omit
// it.
func SignTrustBundle(b *SchemaPinTrustBundle, privateKeyPEM, kid, signedAt, expiresAt string) (*SchemaPinTrustBundle, error) {
	km := crypto.NewKeyManager()
	priv, err := km.LoadPrivateKeyPEM(privateKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to load private key: %w", err)
	}
	publicKeyPEM, err := km.ExportPublicKeyPEM(&priv.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to export public key: %w", err)
	}

	if dup := DuplicateDomain(b); dup != "" {
		return nil, newBundleError(ErrDiscoveryInvalid, fmt.Sprintf("trust bundle has duplicate entries for domain %q", dup))
	}

	signed := b.clone()
	signed.SchemapinBundleVersion = BundleVersionSigned
	signed.BundleAuthority = &BundleAuthority{Kid: kid, PublicKeyPEM: publicKeyPEM}
	signed.SignedAt = signedAt
	signed.ExpiresAt = expiresAt
	signed.Signature = ""

	canonical, err := signingBytes(signed)
	if err != nil {
		return nil, err
	}

	// SignHash applies SHA-256 itself, so pass the canonical bytes directly:
	// the signature is ECDSA over SHA-256(canonical), identical to every SDK.
	sm := crypto.NewSignatureManager()
	sig, err := sm.SignHash([]byte(canonical), priv)
	if err != nil {
		return nil, fmt.Errorf("failed to sign bundle: %w", err)
	}
	signed.Signature = sig
	return signed, nil
}

// VerifyTrustBundle verifies a signed trust bundle against the authority
// allow-list: the authority kid must already be seeded in authorityPinStore
// (SeedBundleAuthority) or verification fails with ErrBundleAuthorityUntrusted.
// Use VerifyTrustBundleWithOptions to allow first-use pinning.
func VerifyTrustBundle(b *SchemaPinTrustBundle, authorityPinStore *AuthorityPinStore) error {
	_, err := VerifyTrustBundleWithOptions(b, authorityPinStore, BundleVerifyOptions{})
	return err
}

// VerifyTrustBundleWithOptions verifies a signed trust bundle.
//
// Steps: require bundle_authority + signature (else ErrBundleUnsigned); reject
// duplicate domains (ErrDiscoveryInvalid); reject when expires_at is in the
// past or not strict RFC 3339 (ErrBundleExpired); look the authority's key
// fingerprint up by kid -- a different pinned key is ErrKeyPinMismatch, an
// unknown kid is ErrBundleAuthorityUntrusted unless opts.AllowFirstUse; verify
// the signature over the canonical bytes (ErrSignatureInvalid); pin the
// authority on first use only after the signature verified.
//
// The bundle carries its own public key, so without an allow-list any
// self-signed bundle under a fresh kid would pass. Treat AllowFirstUse exactly
// like TOFU for a tool key (prompt the user, log it).
func VerifyTrustBundleWithOptions(b *SchemaPinTrustBundle, authorityPinStore *AuthorityPinStore, opts BundleVerifyOptions) (*BundleVerification, error) {
	if b.BundleAuthority == nil {
		return nil, newBundleError(ErrBundleUnsigned, "trust bundle has no bundle_authority")
	}
	if b.Signature == "" {
		return nil, newBundleError(ErrBundleUnsigned, "trust bundle has no signature")
	}
	if dup := DuplicateDomain(b); dup != "" {
		return nil, newBundleError(ErrDiscoveryInvalid, fmt.Sprintf("trust bundle has duplicate entries for domain %q", dup))
	}

	if b.ExpiresAt != "" {
		exp, ok := parseRFC3339Strict(b.ExpiresAt)
		if !ok {
			return nil, newBundleError(ErrBundleExpired,
				fmt.Sprintf("unparseable expires_at '%s'", b.ExpiresAt))
		}
		if time.Now().After(exp) {
			return nil, newBundleError(ErrBundleExpired,
				fmt.Sprintf("trust bundle expired at %s", b.ExpiresAt))
		}
	}

	km := crypto.NewKeyManager()
	fingerprint, err := km.CalculateKeyFingerprintFromPEM(b.BundleAuthority.PublicKeyPEM)
	if err != nil {
		return nil, newBundleError(ErrKeyNotFound, fmt.Sprintf("bundle authority key is invalid: %v", err))
	}
	if authorityPinStore == nil {
		authorityPinStore = NewAuthorityPinStore()
	}
	pinResult := authorityPinStore.Check(b.BundleAuthority.Kid, BundleAuthorityPinDomain, fingerprint)
	switch {
	case pinResult == PinningResultChanged:
		return nil, newBundleError(ErrKeyPinMismatch,
			fmt.Sprintf("bundle authority key for kid '%s' does not match the seeded authority key", b.BundleAuthority.Kid))
	case pinResult == PinningResultFirstUse && !opts.AllowFirstUse:
		return nil, newBundleError(ErrBundleAuthorityUntrusted,
			fmt.Sprintf("bundle authority kid '%s' is not in the authority allow-list; seed it with SeedBundleAuthority or set AllowFirstUse", b.BundleAuthority.Kid))
	}

	pub, err := km.LoadPublicKeyPEM(b.BundleAuthority.PublicKeyPEM)
	if err != nil {
		return nil, newBundleError(ErrKeyNotFound, fmt.Sprintf("failed to load authority public key: %v", err))
	}

	canonical, err := signingBytes(b)
	if err != nil {
		return nil, err
	}
	sm := crypto.NewSignatureManager()
	if !sm.VerifySignature([]byte(canonical), b.Signature, pub) {
		return nil, newBundleError(ErrSignatureInvalid, "trust bundle signature does not verify")
	}
	if pinResult == PinningResultFirstUse {
		authorityPinStore.Pin(b.BundleAuthority.Kid, BundleAuthorityPinDomain, fingerprint)
	}
	return &BundleVerification{
		Kid:         b.BundleAuthority.Kid,
		Fingerprint: fingerprint,
		FirstUse:    pinResult == PinningResultFirstUse,
	}, nil
}

// mergeRank orders bundles for MergeTrustBundles: higher wins. The first
// component is authority precedence, the second the parsed timestamp.
type mergeRank struct {
	precedence int
	ts         time.Time
}

func (r mergeRank) greater(o mergeRank) bool {
	if r.precedence != o.precedence {
		return r.precedence > o.precedence
	}
	return r.ts.After(o.ts)
}

func rankOf(b *SchemaPinTrustBundle, precedence []string) mergeRank {
	rank := 0
	if len(precedence) > 0 {
		rank = -len(precedence) - 1
		if b.BundleAuthority != nil {
			for i, kid := range precedence {
				if kid == b.BundleAuthority.Kid {
					rank = -i
					break
				}
			}
		}
	}
	raw := b.SignedAt
	if raw == "" {
		raw = b.CreatedAt
	}
	ts, ok := parseRFC3339Strict(raw)
	if !ok {
		ts = time.Time{}
	}
	return mergeRank{precedence: rank, ts: ts}
}

// MergeTrustBundles merges trust bundles, deduplicating discovery + revocation
// documents by domain. When two bundles carry the same domain, the entry from
// the bundle with the newer parsed timestamp (signed_at, else created_at)
// wins; unparseable timestamps rank oldest. Equivalent to
// MergeTrustBundlesWithPrecedence(bundles, nil).
func MergeTrustBundles(bundles []*SchemaPinTrustBundle) *SchemaPinTrustBundle {
	return MergeTrustBundlesWithPrecedence(bundles, nil)
}

// MergeTrustBundlesWithPrecedence is MergeTrustBundles with per-authority
// precedence: authorityPrecedence lists authority kids, earlier wins; bundles
// from unlisted or absent authorities rank last; the parsed timestamp breaks
// ties. Merge only bundles you have already verified with VerifyTrustBundle.
//
// The result is an unsigned bundle stamped schemapin_bundle_version = "1.4"
// with created_at set to the newest source timestamp, sorted by domain.
// Re-sign it with SignTrustBundle before redistribution.
func MergeTrustBundlesWithPrecedence(bundles []*SchemaPinTrustBundle, authorityPrecedence []string) *SchemaPinTrustBundle {
	type docEntry struct {
		rank mergeRank
		doc  BundledDiscovery
	}
	type revEntry struct {
		rank mergeRank
		rev  revocation.RevocationDocument
	}

	docs := map[string]docEntry{}
	revs := map[string]revEntry{}
	var newest *mergeRank
	newestRaw := ""

	for _, b := range bundles {
		rank := rankOf(b, authorityPrecedence)
		if newest == nil || rank.ts.After(newest.ts) {
			r := rank
			newest = &r
			newestRaw = b.SignedAt
			if newestRaw == "" {
				newestRaw = b.CreatedAt
			}
		}
		for _, d := range b.Documents {
			if existing, ok := docs[d.Domain]; ok && !rank.greater(existing.rank) {
				continue
			}
			docs[d.Domain] = docEntry{rank: rank, doc: d}
		}
		for _, r := range b.Revocations {
			if existing, ok := revs[r.Domain]; ok && !rank.greater(existing.rank) {
				continue
			}
			revs[r.Domain] = revEntry{rank: rank, rev: r}
		}
	}

	documents := make([]BundledDiscovery, 0, len(docs))
	for _, e := range docs {
		documents = append(documents, e.doc)
	}
	sort.Slice(documents, func(i, j int) bool { return documents[i].Domain < documents[j].Domain })

	revocations := make([]revocation.RevocationDocument, 0, len(revs))
	for _, e := range revs {
		revocations = append(revocations, e.rev)
	}
	sort.Slice(revocations, func(i, j int) bool { return revocations[i].Domain < revocations[j].Domain })

	return &SchemaPinTrustBundle{
		SchemapinBundleVersion: BundleVersionSigned,
		CreatedAt:              newestRaw,
		Documents:              documents,
		Revocations:            revocations,
	}
}

// BuildTrustBundleRequest builds a schemapin/trustBundle JSON-RPC request.
// domain optionally scopes the request to a single provider; pass an empty
// string for "send your whole bundle". id is the JSON-RPC request id.
func BuildTrustBundleRequest(domain string, id interface{}) map[string]interface{} {
	params := map[string]interface{}{}
	if domain != "" {
		params["domain"] = domain
	}
	return map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "schemapin/trustBundle",
		"params":  params,
		"id":      id,
	}
}

// BuildTrustBundleResponse builds a schemapin/trustBundle JSON-RPC response
// carrying a (typically signed) bundle.
func BuildTrustBundleResponse(b *SchemaPinTrustBundle, id interface{}) map[string]interface{} {
	return map[string]interface{}{
		"jsonrpc": "2.0",
		"result": map[string]interface{}{
			"bundle": b,
		},
		"id": id,
	}
}

// ParseTrustBundleResponse extracts the bundle from a schemapin/trustBundle
// JSON-RPC response (a generic map, e.g. from json.Unmarshal). A missing
// result.bundle yields a *BundleError with ErrDiscoveryInvalid.
func ParseTrustBundleResponse(response map[string]interface{}) (*SchemaPinTrustBundle, error) {
	result, ok := response["result"].(map[string]interface{})
	if !ok {
		return nil, newBundleError(ErrDiscoveryInvalid, "JSON-RPC response missing result.bundle")
	}
	bundleVal, ok := result["bundle"]
	if !ok {
		return nil, newBundleError(ErrDiscoveryInvalid, "JSON-RPC response missing result.bundle")
	}
	raw, err := json.Marshal(bundleVal)
	if err != nil {
		return nil, err
	}
	var b SchemaPinTrustBundle
	if err := json.Unmarshal(raw, &b); err != nil {
		return nil, err
	}
	return &b, nil
}

// clone returns a copy of the bundle suitable for signing (the signature and
// stamped fields are overwritten; the documents / revocations slices are shared
// but never mutated by signing).
func (b *SchemaPinTrustBundle) clone() *SchemaPinTrustBundle {
	cp := *b
	if b.BundleAuthority != nil {
		ba := *b.BundleAuthority
		cp.BundleAuthority = &ba
	}
	return &cp
}
