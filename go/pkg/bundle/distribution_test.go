package bundle

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ThirdKeyAi/schemapin/go/pkg/crypto"
	"github.com/ThirdKeyAi/schemapin/go/pkg/discovery"
	"github.com/ThirdKeyAi/schemapin/go/pkg/revocation"
)

func genKeyPair(t *testing.T) (privPEM string) {
	t.Helper()
	km := crypto.NewKeyManager()
	priv, err := km.GenerateKeypair()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	privPEM, err = km.ExportPrivateKeyPEM(priv)
	if err != nil {
		t.Fatalf("export private key: %v", err)
	}
	return privPEM
}

func makeDistBundle(domain, createdAt string) *SchemaPinTrustBundle {
	return &SchemaPinTrustBundle{
		SchemapinBundleVersion: "1.2",
		CreatedAt:              createdAt,
		Documents: []BundledDiscovery{
			{
				Domain: domain,
				WellKnown: discovery.WellKnownResponse{
					SchemaVersion: "1.2",
					DeveloperName: "Example",
					PublicKeyPEM:  "-----BEGIN PUBLIC KEY-----\nx\n-----END PUBLIC KEY-----",
				},
			},
		},
		Revocations: []revocation.RevocationDocument{},
	}
}

func bundleErrCode(t *testing.T, err error) ErrorCode {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	be, ok := err.(*BundleError)
	if !ok {
		t.Fatalf("expected *BundleError, got %T: %v", err, err)
	}
	return be.Code
}

func TestSignVerifyRoundtrip(t *testing.T) {
	priv := genKeyPair(t)
	b := makeDistBundle("example.com", "2026-05-15T00:00:00Z")
	signed, err := SignTrustBundle(b, priv, "auth-2026-05", "2026-05-15T00:00:00Z", "")
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if signed.SchemapinBundleVersion != "1.4" {
		t.Errorf("version = %q, want 1.4", signed.SchemapinBundleVersion)
	}
	if signed.Signature == "" {
		t.Error("signature is empty")
	}
	if signed.BundleAuthority == nil || signed.BundleAuthority.Kid != "auth-2026-05" {
		t.Errorf("bundle_authority kid mismatch: %+v", signed.BundleAuthority)
	}

	store := NewAuthorityPinStore()
	if err := verifyFirstUse(signed, store); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestTamperedBundleFails(t *testing.T) {
	priv := genKeyPair(t)
	b := makeDistBundle("example.com", "2026-05-15T00:00:00Z")
	signed, err := SignTrustBundle(b, priv, "auth", "2026-05-15T00:00:00Z", "")
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	signed.Documents[0].Domain = "evil.com"

	store := NewAuthorityPinStore()
	code := bundleErrCode(t, verifyFirstUse(signed, store))
	if code != ErrSignatureInvalid {
		t.Errorf("code = %q, want %q", code, ErrSignatureInvalid)
	}
}

func TestUnsignedBundleRejected(t *testing.T) {
	b := makeDistBundle("example.com", "2026-05-15T00:00:00Z")
	store := NewAuthorityPinStore()
	code := bundleErrCode(t, verifyFirstUse(b, store))
	if code != ErrBundleUnsigned {
		t.Errorf("code = %q, want %q", code, ErrBundleUnsigned)
	}
}

func TestExpiredBundleRejected(t *testing.T) {
	priv := genKeyPair(t)
	b := makeDistBundle("example.com", "2020-01-01T00:00:00Z")
	signed, err := SignTrustBundle(b, priv, "auth", "2020-01-01T00:00:00Z", "2020-02-01T00:00:00Z")
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	store := NewAuthorityPinStore()
	code := bundleErrCode(t, verifyFirstUse(signed, store))
	if code != ErrBundleExpired {
		t.Errorf("code = %q, want %q", code, ErrBundleExpired)
	}
}

func TestExpiredBundleUnparseable(t *testing.T) {
	priv := genKeyPair(t)
	b := makeDistBundle("example.com", "2026-05-15T00:00:00Z")
	signed, err := SignTrustBundle(b, priv, "auth", "2026-05-15T00:00:00Z", "")
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	signed.ExpiresAt = "not-a-date"
	store := NewAuthorityPinStore()
	code := bundleErrCode(t, verifyFirstUse(signed, store))
	if code != ErrBundleExpired {
		t.Errorf("code = %q, want %q", code, ErrBundleExpired)
	}
}

func TestAuthorityTOFUMismatch(t *testing.T) {
	priv1 := genKeyPair(t)
	priv2 := genKeyPair(t)
	b := makeDistBundle("example.com", "2026-05-15T00:00:00Z")

	signed1, err := SignTrustBundle(b, priv1, "auth", "2026-05-15T00:00:00Z", "")
	if err != nil {
		t.Fatalf("sign1: %v", err)
	}
	// Different key, SAME kid -> impersonation attempt.
	signed2, err := SignTrustBundle(b, priv2, "auth", "2026-05-16T00:00:00Z", "")
	if err != nil {
		t.Fatalf("sign2: %v", err)
	}

	store := NewAuthorityPinStore()
	if err := verifyFirstUse(signed1, store); err != nil {
		t.Fatalf("verify1 (pins kp1): %v", err)
	}
	code := bundleErrCode(t, verifyFirstUse(signed2, store))
	if code != ErrKeyPinMismatch {
		t.Errorf("code = %q, want %q", code, ErrKeyPinMismatch)
	}
}

func TestMergeNewestWins(t *testing.T) {
	older := makeDistBundle("example.com", "2026-01-01T00:00:00Z")
	older.Documents[0].WellKnown.DeveloperName = "Old"
	newer := makeDistBundle("example.com", "2026-05-01T00:00:00Z")
	newer.Documents[0].WellKnown.DeveloperName = "New"
	other := makeDistBundle("other.com", "2026-03-01T00:00:00Z")

	merged := MergeTrustBundles([]*SchemaPinTrustBundle{older, newer, other})
	if len(merged.Documents) != 2 {
		t.Fatalf("documents len = %d, want 2", len(merged.Documents))
	}
	ex := merged.FindDiscovery("example.com")
	if ex == nil || ex.DeveloperName != "New" {
		t.Errorf("example.com developer_name = %v, want New", ex)
	}
	if merged.CreatedAt != "2026-05-01T00:00:00Z" {
		t.Errorf("created_at = %q, want 2026-05-01T00:00:00Z", merged.CreatedAt)
	}
	if merged.SchemapinBundleVersion != "1.4" {
		t.Errorf("version = %q, want 1.4", merged.SchemapinBundleVersion)
	}
}

func TestMergeSignedAtBeatsCreatedAt(t *testing.T) {
	a := makeDistBundle("example.com", "2026-01-01T00:00:00Z")
	a.SignedAt = "2026-09-01T00:00:00Z"
	a.Documents[0].WellKnown.DeveloperName = "Signed-late"
	b := makeDistBundle("example.com", "2026-06-01T00:00:00Z")
	b.Documents[0].WellKnown.DeveloperName = "Created-mid"

	merged := MergeTrustBundles([]*SchemaPinTrustBundle{b, a})
	ex := merged.FindDiscovery("example.com")
	if ex == nil || ex.DeveloperName != "Signed-late" {
		t.Errorf("developer_name = %v, want Signed-late", ex)
	}
}

func TestJSONRPCEnvelopeRoundtrip(t *testing.T) {
	priv := genKeyPair(t)
	b := makeDistBundle("example.com", "2026-05-15T00:00:00Z")
	signed, err := SignTrustBundle(b, priv, "auth", "2026-05-15T00:00:00Z", "")
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	req := BuildTrustBundleRequest("example.com", 1)
	if req["method"] != "schemapin/trustBundle" {
		t.Errorf("method = %v", req["method"])
	}
	params := req["params"].(map[string]interface{})
	if params["domain"] != "example.com" {
		t.Errorf("params.domain = %v", params["domain"])
	}

	resp := BuildTrustBundleResponse(signed, 1)
	// Round-trip through JSON to emulate the wire.
	raw, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal resp: %v", err)
	}
	var generic map[string]interface{}
	if err := json.Unmarshal(raw, &generic); err != nil {
		t.Fatalf("unmarshal resp: %v", err)
	}
	parsed, err := ParseTrustBundleResponse(generic)
	if err != nil {
		t.Fatalf("parse resp: %v", err)
	}

	// The parsed bundle still verifies.
	store := NewAuthorityPinStore()
	if err := verifyFirstUse(parsed, store); err != nil {
		t.Fatalf("verify parsed: %v", err)
	}
}

func TestParseTrustBundleResponseMissingBundle(t *testing.T) {
	resp := map[string]interface{}{
		"jsonrpc": "2.0",
		"result":  map[string]interface{}{},
		"id":      1,
	}
	_, err := ParseTrustBundleResponse(resp)
	code := bundleErrCode(t, err)
	if code != ErrDiscoveryInvalid {
		t.Errorf("code = %q, want %q", code, ErrDiscoveryInvalid)
	}
}

func TestBuildTrustBundleRequestOmitsEmptyDomain(t *testing.T) {
	req := BuildTrustBundleRequest("", 1)
	params := req["params"].(map[string]interface{})
	if _, ok := params["domain"]; ok {
		t.Errorf("domain should be omitted when empty, got %v", params["domain"])
	}
}

// TestCrossLanguageFixture is the key interop proof: the bundle signed by the
// Rust SDK (tests/cross-language/signed_bundle.json) MUST verify in Go. If this
// fails the canonicalization diverges from Rust.
func TestCrossLanguageFixture(t *testing.T) {
	path := findFixture(t)
	raw, err := os.ReadFile(path) // #nosec G304 -- test fixture
	if err != nil {
		t.Fatal(err)
	}
	var b SchemaPinTrustBundle
	if err := json.Unmarshal(raw, &b); err != nil {
		t.Fatal(err)
	}
	if b.BundleAuthority.Kid != "schemapin-test-fixture-authority" {
		t.Fatalf("unexpected fixture kid %q", b.BundleAuthority.Kid)
	}
	// Unknown authority: refused unless seeded.
	if code := bundleErrCode(t, VerifyTrustBundle(&b, NewAuthorityPinStore())); code != ErrBundleAuthorityUntrusted {
		t.Fatalf("expected %s, got %s", ErrBundleAuthorityUntrusted, code)
	}
	pub, err := os.ReadFile(filepath.Join(filepath.Dir(path), "keys", "test-only-bundle-authority.pub.pem")) // #nosec G304
	if err != nil {
		t.Fatal(err)
	}
	store := NewAuthorityPinStore()
	if _, err := SeedBundleAuthorityFromPEM(store, b.BundleAuthority.Kid, string(pub)); err != nil {
		t.Fatal(err)
	}
	res, err := VerifyTrustBundleWithOptions(&b, store, BundleVerifyOptions{})
	if err != nil {
		t.Fatalf("cross-language fixture must verify once seeded: %v", err)
	}
	if res.FirstUse {
		t.Fatal("seeded authority must not be reported as first use")
	}
	other := NewAuthorityPinStore()
	SeedBundleAuthority(other, b.BundleAuthority.Kid, "sha256:"+strings.Repeat("00", 32))
	if code := bundleErrCode(t, VerifyTrustBundle(&b, other)); code != ErrKeyPinMismatch {
		t.Fatalf("expected %s, got %s", ErrKeyPinMismatch, code)
	}
}

// verifyFirstUse verifies with first-use trust allowed (the TOFU semantics
// the pre-allow-list tests were written against).
func verifyFirstUse(b *SchemaPinTrustBundle, store *AuthorityPinStore) error {
	_, err := VerifyTrustBundleWithOptions(b, store, BundleVerifyOptions{AllowFirstUse: true})
	return err
}

func TestAuthorityAllowList(t *testing.T) {
	priv := genKeyPair(t)
	signed, err := SignTrustBundle(makeDistBundle("victim.com", "2026-05-15T00:00:00Z"), priv, "victim-authority-2026", "2026-05-15T00:00:00Z", "")
	if err != nil {
		t.Fatal(err)
	}
	if code := bundleErrCode(t, VerifyTrustBundle(signed, NewAuthorityPinStore())); code != ErrBundleAuthorityUntrusted {
		t.Fatalf("self-signed bundle under a fresh kid must be refused, got %s", code)
	}
	store := NewAuthorityPinStore()
	fp, err := SeedBundleAuthorityFromPEM(store, "victim-authority-2026", signed.BundleAuthority.PublicKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	res, err := VerifyTrustBundleWithOptions(signed, store, BundleVerifyOptions{})
	if err != nil || res.FirstUse || res.Fingerprint != fp {
		t.Fatalf("seeded authority must pass strictly: %+v %v", res, err)
	}
	fresh := NewAuthorityPinStore()
	res, err = VerifyTrustBundleWithOptions(signed, fresh, BundleVerifyOptions{AllowFirstUse: true})
	if err != nil || !res.FirstUse {
		t.Fatalf("first use must be reported: %+v %v", res, err)
	}
	if _, err := VerifyTrustBundleWithOptions(signed, fresh, BundleVerifyOptions{}); err != nil {
		t.Fatalf("pinned authority must pass strictly afterwards: %v", err)
	}
	// A failed signature never pins.
	tampered, _ := SignTrustBundle(makeDistBundle("example.com", "2026-05-15T00:00:00Z"), priv, "auth", "2026-05-15T00:00:00Z", "")
	tampered.Documents[0].Domain = "evil.com"
	s2 := NewAuthorityPinStore()
	if code := bundleErrCode(t, verifyFirstUse(tampered, s2)); code != ErrSignatureInvalid {
		t.Fatalf("expected signature failure, got %s", code)
	}
	if s2.Get("auth", BundleAuthorityPinDomain) != "" {
		t.Fatal("failed verification must not pin the authority")
	}
}

func TestStrictExpiresAtAndDuplicates(t *testing.T) {
	priv := genKeyPair(t)
	for _, bad := range []string{"2099-01-01", "2099-01-01T00:00:00", "2099-01-01 00:00:00Z"} {
		signed, err := SignTrustBundle(makeDistBundle("example.com", "2026-05-15T00:00:00Z"), priv, "auth", "2026-05-15T00:00:00Z", bad)
		if err != nil {
			t.Fatal(err)
		}
		if code := bundleErrCode(t, verifyFirstUse(signed, NewAuthorityPinStore())); code != ErrBundleExpired {
			t.Errorf("%q: expected %s, got %s", bad, ErrBundleExpired, code)
		}
	}
	dup := makeDistBundle("example.com", "2026-05-15T00:00:00Z")
	dup.Documents = append(dup.Documents, dup.Documents[0])
	if _, err := SignTrustBundle(dup, priv, "auth", "2026-05-15T00:00:00Z", ""); err == nil {
		t.Fatal("duplicate domains must be rejected at sign time")
	}
	raw, _ := json.Marshal(dup)
	if _, err := ParseTrustBundle(string(raw)); err == nil {
		t.Fatal("duplicate domains must be rejected at parse time")
	}
}

func TestMergePrecedence(t *testing.T) {
	trusted := genKeyPair(t)
	rogue := genKeyPair(t)
	named := func(name, ts string) *SchemaPinTrustBundle {
		b := makeDistBundle("example.com", ts)
		b.Documents[0].WellKnown.DeveloperName = name
		return b
	}
	good, _ := SignTrustBundle(named("Good", "2026-01-01T00:00:00Z"), trusted, "trusted", "2026-01-01T00:00:00Z", "")
	bad, _ := SignTrustBundle(named("Rogue", "2099-01-01T00:00:00Z"), rogue, "rogue", "2099-01-01T00:00:00Z", "")
	if got := MergeTrustBundlesWithPrecedence([]*SchemaPinTrustBundle{bad, good}, []string{"trusted"}).Documents[0].WellKnown.DeveloperName; got != "Good" {
		t.Fatalf("precedence must beat timestamp, got %s", got)
	}
	if got := MergeTrustBundles([]*SchemaPinTrustBundle{good, bad}).Documents[0].WellKnown.DeveloperName; got != "Rogue" {
		t.Fatalf("newer parsed timestamp must win without precedence, got %s", got)
	}
	real := named("Real", "2026-01-01T00:00:00Z")
	bogus := named("Bogus", "9999-99-99 bogus")
	if got := MergeTrustBundles([]*SchemaPinTrustBundle{real, bogus}).Documents[0].WellKnown.DeveloperName; got != "Real" {
		t.Fatalf("unparseable timestamp must not win, got %s", got)
	}
	offset := named("Offset", "2026-02-01T00:00:00+00:00")
	if got := MergeTrustBundles([]*SchemaPinTrustBundle{real, offset}).Documents[0].WellKnown.DeveloperName; got != "Offset" {
		t.Fatalf("offset timestamps must compare as instants, got %s", got)
	}
}

// findFixture resolves tests/cross-language/signed_bundle.json relative to the
// repo root, walking up from the test working directory.
func findFixture(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for i := 0; i < 10; i++ {
		candidate := filepath.Join(dir, "tests", "cross-language", "signed_bundle.json")
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatalf("could not locate tests/cross-language/signed_bundle.json from %s", dir)
	return ""
}
