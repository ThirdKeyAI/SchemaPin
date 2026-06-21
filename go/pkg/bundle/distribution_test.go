package bundle

import (
	"encoding/json"
	"os"
	"path/filepath"
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
	if err := VerifyTrustBundle(signed, store); err != nil {
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
	code := bundleErrCode(t, VerifyTrustBundle(signed, store))
	if code != ErrSignatureInvalid {
		t.Errorf("code = %q, want %q", code, ErrSignatureInvalid)
	}
}

func TestUnsignedBundleRejected(t *testing.T) {
	b := makeDistBundle("example.com", "2026-05-15T00:00:00Z")
	store := NewAuthorityPinStore()
	code := bundleErrCode(t, VerifyTrustBundle(b, store))
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
	code := bundleErrCode(t, VerifyTrustBundle(signed, store))
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
	code := bundleErrCode(t, VerifyTrustBundle(signed, store))
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
	if err := VerifyTrustBundle(signed1, store); err != nil {
		t.Fatalf("verify1 (pins kp1): %v", err)
	}
	code := bundleErrCode(t, VerifyTrustBundle(signed2, store))
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
	if err := VerifyTrustBundle(parsed, store); err != nil {
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
	raw, err := os.ReadFile(path) //nolint:gosec // test fixture path
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var b SchemaPinTrustBundle
	if err := json.Unmarshal(raw, &b); err != nil {
		t.Fatalf("unmarshal fixture: %v", err)
	}
	store := NewAuthorityPinStore()
	if err := VerifyTrustBundle(&b, store); err != nil {
		t.Fatalf("cross-language fixture failed to verify: %v", err)
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
