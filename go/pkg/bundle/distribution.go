package bundle

// (v1.4) Trust-bundle distribution for A2A networks.
//
// Lets a bundle authority sign a SchemaPinTrustBundle so it can be exchanged
// between agents over A2A without per-bundle out-of-band trust establishment.
// Provides:
//
//   - SignTrustBundle / VerifyTrustBundle — ECDSA P-256 over the canonical
//     bundle bytes, with TOFU pinning of the authority key by kid.
//   - MergeTrustBundles — combine bundles from multiple sources, newest entry
//     wins per domain.
//   - BuildTrustBundleRequest / BuildTrustBundleResponse /
//     ParseTrustBundleResponse — the schemapin/trustBundle JSON-RPC envelope
//     for A2A bundle exchange.
//
// # Signing input
//
// The signature covers the schemapin-v1 canonicalization (recursive sorted
// keys, compact, UTF-8) of the entire bundle object with the signature field
// set to the empty string "". All four SDKs build the identical byte string,
// so a bundle signed by any SDK verifies in every other.

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/ThirdKeyAi/schemapin/go/pkg/crypto"
	"github.com/ThirdKeyAi/schemapin/go/pkg/revocation"
)

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
	// ErrDiscoveryInvalid — a JSON-RPC response was missing result.bundle.
	ErrDiscoveryInvalid ErrorCode = "discovery_invalid"
)

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

// canonicalizeValue recursively sorts object keys and marshals to compact JSON
// with HTML escaping disabled, matching the Rust serde_json output used by
// canonicalize_schema. HTML escaping MUST be off so that '<', '>' and '&' are
// emitted literally (Go's encoding/json escapes them to \u00xx by default,
// which would diverge from every other SDK).
func canonicalizeValue(v interface{}) (string, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return "", err
	}
	// json.Encoder appends a trailing newline; trim it.
	return string(bytes.TrimRight(buf.Bytes(), "\n")), nil
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

	hash := sha256.Sum256([]byte(canonical))
	sm := crypto.NewSignatureManager()
	sig, err := sm.SignHash(hash[:], priv)
	if err != nil {
		return nil, fmt.Errorf("failed to sign bundle: %w", err)
	}
	signed.Signature = sig
	return signed, nil
}

// VerifyTrustBundle verifies a signed trust bundle and TOFU-pins its authority
// key by kid.
//
// Steps: require bundle_authority + signature (else ErrBundleUnsigned); reject
// when expires_at is in the past or unparseable (ErrBundleExpired); TOFU-pin
// the authority's key fingerprint by kid (mismatch -> ErrKeyPinMismatch);
// verify the signature over the canonical bytes (failure -> ErrSignatureInvalid).
//
// On a verification failure the returned error is a *BundleError whose Code is
// the relevant ErrorCode.
func VerifyTrustBundle(b *SchemaPinTrustBundle, authorityPinStore *AuthorityPinStore) error {
	if b.BundleAuthority == nil {
		return newBundleError(ErrBundleUnsigned, "trust bundle has no bundle_authority")
	}
	if b.Signature == "" {
		return newBundleError(ErrBundleUnsigned, "trust bundle has no signature")
	}

	if b.ExpiresAt != "" {
		exp, err := time.Parse(time.RFC3339, b.ExpiresAt)
		if err != nil {
			return newBundleError(ErrBundleExpired,
				fmt.Sprintf("unparseable expires_at '%s': %v", b.ExpiresAt, err))
		}
		if time.Now().After(exp) {
			return newBundleError(ErrBundleExpired,
				fmt.Sprintf("trust bundle expired at %s", b.ExpiresAt))
		}
	}

	km := crypto.NewKeyManager()
	fingerprint, err := km.CalculateKeyFingerprintFromPEM(b.BundleAuthority.PublicKeyPEM)
	if err != nil {
		return fmt.Errorf("failed to fingerprint authority key: %w", err)
	}
	if authorityPinStore.CheckAndPin(b.BundleAuthority.Kid, BundleAuthorityPinDomain, fingerprint) == PinningResultChanged {
		return newBundleError(ErrKeyPinMismatch,
			fmt.Sprintf("bundle authority key for kid '%s' has changed since last pinned", b.BundleAuthority.Kid))
	}

	pub, err := km.LoadPublicKeyPEM(b.BundleAuthority.PublicKeyPEM)
	if err != nil {
		return fmt.Errorf("failed to load authority public key: %w", err)
	}

	canonical, err := signingBytes(b)
	if err != nil {
		return err
	}
	hash := sha256.Sum256([]byte(canonical))
	sm := crypto.NewSignatureManager()
	if !sm.VerifySignature(hash[:], b.Signature, pub) {
		return newBundleError(ErrSignatureInvalid, "trust bundle signature does not verify")
	}
	return nil
}

// MergeTrustBundles merges trust bundles, deduplicating discovery + revocation
// documents by domain. When two bundles carry the same domain, the entry from
// the bundle with the newer timestamp (signed_at, else created_at) wins.
//
// The result is an unsigned bundle (a merge cannot carry a single authority's
// signature) stamped schemapin_bundle_version = "1.4" with created_at set to
// the newest source timestamp, sorted by domain. Re-sign it with
// SignTrustBundle before redistribution.
func MergeTrustBundles(bundles []*SchemaPinTrustBundle) *SchemaPinTrustBundle {
	type docEntry struct {
		ts  string
		doc BundledDiscovery
	}
	type revEntry struct {
		ts  string
		rev revocation.RevocationDocument
	}

	docs := map[string]docEntry{}
	revs := map[string]revEntry{}
	newestTS := ""

	for _, b := range bundles {
		ts := b.SignedAt
		if ts == "" {
			ts = b.CreatedAt
		}
		if ts > newestTS {
			newestTS = ts
		}
		for _, d := range b.Documents {
			if existing, ok := docs[d.Domain]; ok && existing.ts >= ts {
				continue
			}
			docs[d.Domain] = docEntry{ts: ts, doc: d}
		}
		for _, r := range b.Revocations {
			if existing, ok := revs[r.Domain]; ok && existing.ts >= ts {
				continue
			}
			revs[r.Domain] = revEntry{ts: ts, rev: r}
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
		CreatedAt:              newestTS,
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
