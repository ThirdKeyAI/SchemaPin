package verification

import (
	"testing"

	"github.com/ThirdKeyAi/schemapin/go/pkg/bundle"
	"github.com/ThirdKeyAi/schemapin/go/pkg/core"
	gocrypto "github.com/ThirdKeyAi/schemapin/go/pkg/crypto"
	"github.com/ThirdKeyAi/schemapin/go/pkg/discovery"
	"github.com/ThirdKeyAi/schemapin/go/pkg/resolver"
	"github.com/ThirdKeyAi/schemapin/go/pkg/revocation"
)

func makeKeyAndSign(schema map[string]interface{}) (string, string, string) {
	km := gocrypto.NewKeyManager()
	sm := gocrypto.NewSignatureManager()
	c := core.NewSchemaPinCore()

	privKey, err := km.GenerateKeypair()
	if err != nil {
		panic(err)
	}

	pubPEM, err := km.ExportPublicKeyPEM(&privKey.PublicKey)
	if err != nil {
		panic(err)
	}

	schemaHash, err := c.CanonicalizeAndHash(schema)
	if err != nil {
		panic(err)
	}

	sig, err := sm.SignSchemaHash(schemaHash, privKey)
	if err != nil {
		panic(err)
	}

	fp, err := km.CalculateKeyFingerprintFromPEM(pubPEM)
	if err != nil {
		panic(err)
	}

	return pubPEM, sig, fp
}

func TestKeyPinStoreFirstUse(t *testing.T) {
	store := NewKeyPinStore()
	result := store.CheckAndPin("tool1", "example.com", "sha256:aaa")
	if result != PinFirstUse {
		t.Errorf("expected first_use, got %s", result)
	}
}

func TestKeyPinStorePinned(t *testing.T) {
	store := NewKeyPinStore()
	store.CheckAndPin("tool1", "example.com", "sha256:aaa")
	result := store.CheckAndPin("tool1", "example.com", "sha256:aaa")
	if result != PinPinned {
		t.Errorf("expected pinned, got %s", result)
	}
}

func TestKeyPinStoreChanged(t *testing.T) {
	store := NewKeyPinStore()
	store.CheckAndPin("tool1", "example.com", "sha256:aaa")
	result := store.CheckAndPin("tool1", "example.com", "sha256:bbb")
	if result != PinChanged {
		t.Errorf("expected changed, got %s", result)
	}
}

func TestKeyPinStoreDifferentTools(t *testing.T) {
	store := NewKeyPinStore()
	store.CheckAndPin("tool1", "example.com", "sha256:aaa")
	result := store.CheckAndPin("tool2", "example.com", "sha256:bbb")
	if result != PinFirstUse {
		t.Errorf("expected first_use, got %s", result)
	}
}

func TestKeyPinStoreDifferentDomains(t *testing.T) {
	store := NewKeyPinStore()
	store.CheckAndPin("tool1", "a.com", "sha256:aaa")
	result := store.CheckAndPin("tool1", "b.com", "sha256:bbb")
	if result != PinFirstUse {
		t.Errorf("expected first_use, got %s", result)
	}
}

func TestKeyPinStoreJSONRoundtrip(t *testing.T) {
	store := NewKeyPinStore()
	store.CheckAndPin("tool1", "example.com", "sha256:aaa")
	store.CheckAndPin("tool2", "other.com", "sha256:bbb")

	jsonStr, err := store.ToJSON()
	if err != nil {
		t.Fatalf("failed to serialize: %v", err)
	}

	restored, err := FromJSON(jsonStr)
	if err != nil {
		t.Fatalf("failed to deserialize: %v", err)
	}

	if restored.CheckAndPin("tool1", "example.com", "sha256:aaa") != PinPinned {
		t.Error("expected pinned for tool1")
	}
	if restored.CheckAndPin("tool2", "other.com", "sha256:bbb") != PinPinned {
		t.Error("expected pinned for tool2")
	}
}

func TestKeyPinStoreGetPinned(t *testing.T) {
	store := NewKeyPinStore()
	store.CheckAndPin("tool1", "example.com", "sha256:aaa")
	if store.GetPinned("tool1", "example.com") != "sha256:aaa" {
		t.Error("expected sha256:aaa")
	}
	if store.GetPinned("tool2", "example.com") != "" {
		t.Error("expected empty string for unknown tool")
	}
}

func TestVerifySchemaOfflineHappyPath(t *testing.T) {
	schema := map[string]interface{}{"name": "test_tool", "description": "A test"}
	pubPEM, sig, _ := makeKeyAndSign(schema)

	disc := &discovery.WellKnownResponse{
		SchemaVersion: "1.2",
		DeveloperName: "Test Dev",
		PublicKeyPEM:  pubPEM,
	}
	store := NewKeyPinStore()
	result := VerifySchemaOffline(schema, sig, "example.com", "tool1", disc, nil, store)

	if !result.Valid {
		t.Errorf("expected valid, got error: %s", result.ErrorMessage)
	}
	if result.Domain != "example.com" {
		t.Errorf("expected domain example.com, got %s", result.Domain)
	}
	if result.DeveloperName != "Test Dev" {
		t.Errorf("expected developer Test Dev, got %s", result.DeveloperName)
	}
	if result.KeyPinning == nil || result.KeyPinning.Status != "first_use" {
		t.Error("expected key_pinning.status = first_use")
	}
}

func TestVerifySchemaOfflinePinnedOnSecondCall(t *testing.T) {
	schema := map[string]interface{}{"name": "test_tool", "description": "A test"}
	pubPEM, sig, _ := makeKeyAndSign(schema)

	disc := &discovery.WellKnownResponse{
		SchemaVersion: "1.2",
		DeveloperName: "Test Dev",
		PublicKeyPEM:  pubPEM,
	}
	store := NewKeyPinStore()
	VerifySchemaOffline(schema, sig, "example.com", "tool1", disc, nil, store)
	result := VerifySchemaOffline(schema, sig, "example.com", "tool1", disc, nil, store)

	if !result.Valid {
		t.Error("expected valid")
	}
	if result.KeyPinning.Status != "pinned" {
		t.Error("expected pinned status")
	}
}

func TestVerifySchemaOfflineInvalidSignature(t *testing.T) {
	schema := map[string]interface{}{"name": "test_tool", "description": "A test"}
	pubPEM, _, _ := makeKeyAndSign(schema)

	disc := &discovery.WellKnownResponse{
		SchemaVersion: "1.2",
		DeveloperName: "Test Dev",
		PublicKeyPEM:  pubPEM,
	}
	store := NewKeyPinStore()
	result := VerifySchemaOffline(schema, "invalid_sig", "example.com", "tool1", disc, nil, store)

	if result.Valid {
		t.Error("expected invalid")
	}
	if result.ErrorCode != ErrSignatureInvalid {
		t.Errorf("expected signature_invalid, got %s", result.ErrorCode)
	}
}

func TestVerifySchemaOfflineTamperedSchema(t *testing.T) {
	schema := map[string]interface{}{"name": "test_tool", "description": "A test"}
	pubPEM, sig, _ := makeKeyAndSign(schema)

	tampered := map[string]interface{}{"name": "test_tool", "description": "TAMPERED"}
	disc := &discovery.WellKnownResponse{
		SchemaVersion: "1.2",
		DeveloperName: "Test Dev",
		PublicKeyPEM:  pubPEM,
	}
	store := NewKeyPinStore()
	result := VerifySchemaOffline(tampered, sig, "example.com", "tool1", disc, nil, store)

	if result.Valid {
		t.Error("expected invalid")
	}
	if result.ErrorCode != ErrSignatureInvalid {
		t.Errorf("expected signature_invalid, got %s", result.ErrorCode)
	}
}

func TestVerifySchemaOfflineRevokedKeySimpleList(t *testing.T) {
	schema := map[string]interface{}{"name": "test_tool", "description": "A test"}
	pubPEM, sig, fp := makeKeyAndSign(schema)

	disc := &discovery.WellKnownResponse{
		SchemaVersion: "1.2",
		DeveloperName: "Test Dev",
		PublicKeyPEM:  pubPEM,
		RevokedKeys:   []string{fp},
	}
	store := NewKeyPinStore()
	result := VerifySchemaOffline(schema, sig, "example.com", "tool1", disc, nil, store)

	if result.Valid {
		t.Error("expected invalid")
	}
	if result.ErrorCode != ErrKeyRevoked {
		t.Errorf("expected key_revoked, got %s", result.ErrorCode)
	}
}

func TestVerifySchemaOfflineRevokedKeyStandaloneDoc(t *testing.T) {
	schema := map[string]interface{}{"name": "test_tool", "description": "A test"}
	pubPEM, sig, fp := makeKeyAndSign(schema)

	disc := &discovery.WellKnownResponse{
		SchemaVersion: "1.2",
		DeveloperName: "Test Dev",
		PublicKeyPEM:  pubPEM,
	}
	rev := revocation.BuildRevocationDocument("example.com")
	revocation.AddRevokedKey(rev, fp, revocation.ReasonKeyCompromise)

	store := NewKeyPinStore()
	result := VerifySchemaOffline(schema, sig, "example.com", "tool1", disc, rev, store)

	if result.Valid {
		t.Error("expected invalid")
	}
	if result.ErrorCode != ErrKeyRevoked {
		t.Errorf("expected key_revoked, got %s", result.ErrorCode)
	}
}

func TestVerifySchemaOfflineKeyPinChangeRejected(t *testing.T) {
	schema := map[string]interface{}{"name": "test_tool", "description": "A test"}
	pubPEM1, sig1, _ := makeKeyAndSign(schema)
	pubPEM2, sig2, _ := makeKeyAndSign(schema)

	disc1 := &discovery.WellKnownResponse{
		SchemaVersion: "1.2",
		DeveloperName: "Dev",
		PublicKeyPEM:  pubPEM1,
	}
	disc2 := &discovery.WellKnownResponse{
		SchemaVersion: "1.2",
		DeveloperName: "Dev",
		PublicKeyPEM:  pubPEM2,
	}

	store := NewKeyPinStore()
	r1 := VerifySchemaOffline(schema, sig1, "example.com", "tool1", disc1, nil, store)
	if !r1.Valid {
		t.Fatalf("first verification failed: %s", r1.ErrorMessage)
	}

	r2 := VerifySchemaOffline(schema, sig2, "example.com", "tool1", disc2, nil, store)
	if r2.Valid {
		t.Error("expected invalid for key change")
	}
	if r2.ErrorCode != ErrKeyPinMismatch {
		t.Errorf("expected key_pin_mismatch, got %s", r2.ErrorCode)
	}
}

func TestVerifySchemaOfflineInvalidDiscovery(t *testing.T) {
	store := NewKeyPinStore()
	result := VerifySchemaOffline(
		map[string]interface{}{"name": "test"},
		"sig", "example.com", "tool1",
		&discovery.WellKnownResponse{SchemaVersion: "1.2"},
		nil, store,
	)

	if result.Valid {
		t.Error("expected invalid")
	}
	if result.ErrorCode != ErrDiscoveryInvalid {
		t.Errorf("expected discovery_invalid, got %s", result.ErrorCode)
	}
}

func TestVerifySchemaOfflineNilDiscovery(t *testing.T) {
	store := NewKeyPinStore()
	result := VerifySchemaOffline(
		map[string]interface{}{"name": "test"},
		"sig", "example.com", "tool1",
		nil, nil, store,
	)

	if result.Valid {
		t.Error("expected invalid")
	}
	if result.ErrorCode != ErrDiscoveryInvalid {
		t.Errorf("expected discovery_invalid, got %s", result.ErrorCode)
	}
}

func TestVerifySchemaWithResolverHappyPath(t *testing.T) {
	schema := map[string]interface{}{"name": "test_tool", "description": "A test"}
	pubPEM, sig, _ := makeKeyAndSign(schema)

	b := bundle.NewTrustBundle("2026-01-01T00:00:00Z")
	b.Documents = append(b.Documents, bundle.BundledDiscovery{
		Domain: "example.com",
		WellKnown: discovery.WellKnownResponse{
			SchemaVersion: "1.2",
			DeveloperName: "Bundle Dev",
			PublicKeyPEM:  pubPEM,
		},
	})

	r := resolver.NewTrustBundleResolver(b)
	store := NewKeyPinStore()

	result := VerifySchemaWithResolver(schema, sig, "example.com", "tool1", r, store)
	if !result.Valid {
		t.Errorf("expected valid, got error: %s", result.ErrorMessage)
	}
	if result.DeveloperName != "Bundle Dev" {
		t.Errorf("expected Bundle Dev, got %s", result.DeveloperName)
	}
}

func TestVerifySchemaWithResolverMissingDomain(t *testing.T) {
	b := bundle.NewTrustBundle("2026-01-01T00:00:00Z")
	r := resolver.NewTrustBundleResolver(b)
	store := NewKeyPinStore()

	result := VerifySchemaWithResolver(
		map[string]interface{}{"name": "test"},
		"sig", "missing.com", "tool1", r, store,
	)

	if result.Valid {
		t.Error("expected invalid")
	}
	if result.ErrorCode != ErrDiscoveryFetchFailed {
		t.Errorf("expected discovery_fetch_failed, got %s", result.ErrorCode)
	}
}
