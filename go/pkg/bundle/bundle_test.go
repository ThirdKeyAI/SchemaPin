package bundle

import (
	"encoding/json"
	"testing"

	"github.com/ThirdKeyAi/schemapin/go/pkg/discovery"
	"github.com/ThirdKeyAi/schemapin/go/pkg/revocation"
)

func makeBundle() *SchemaPinTrustBundle {
	bundle := NewTrustBundle("2026-01-01T00:00:00Z")
	bundle.Documents = append(bundle.Documents, BundledDiscovery{
		Domain: "example.com",
		WellKnown: discovery.WellKnownResponse{
			SchemaVersion: "1.2",
			DeveloperName: "Test Dev",
			PublicKeyPEM:  "-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----",
		},
	})

	rev := revocation.BuildRevocationDocument("example.com")
	revocation.AddRevokedKey(rev, "sha256:old", revocation.ReasonSuperseded)
	bundle.Revocations = append(bundle.Revocations, *rev)

	return bundle
}

func TestNewTrustBundle(t *testing.T) {
	bundle := makeBundle()
	if bundle.SchemapinBundleVersion != "1.2" {
		t.Errorf("expected version 1.2, got %s", bundle.SchemapinBundleVersion)
	}
	if len(bundle.Documents) != 1 {
		t.Errorf("expected 1 document, got %d", len(bundle.Documents))
	}
	if len(bundle.Revocations) != 1 {
		t.Errorf("expected 1 revocation, got %d", len(bundle.Revocations))
	}
}

func TestFindDiscoveryHit(t *testing.T) {
	bundle := makeBundle()
	disc := bundle.FindDiscovery("example.com")
	if disc == nil {
		t.Fatal("expected non-nil discovery")
	}
	if disc.DeveloperName != "Test Dev" {
		t.Errorf("expected developer Test Dev, got %s", disc.DeveloperName)
	}
}

func TestFindDiscoveryMiss(t *testing.T) {
	bundle := makeBundle()
	if bundle.FindDiscovery("unknown.com") != nil {
		t.Error("expected nil for unknown domain")
	}
}

func TestFindRevocationHit(t *testing.T) {
	bundle := makeBundle()
	rev := bundle.FindRevocation("example.com")
	if rev == nil {
		t.Fatal("expected non-nil revocation")
	}
	if rev.Domain != "example.com" {
		t.Errorf("expected domain example.com, got %s", rev.Domain)
	}
	if len(rev.RevokedKeys) != 1 {
		t.Errorf("expected 1 revoked key, got %d", len(rev.RevokedKeys))
	}
}

func TestFindRevocationMiss(t *testing.T) {
	bundle := makeBundle()
	if bundle.FindRevocation("unknown.com") != nil {
		t.Error("expected nil for unknown domain")
	}
}

func TestJSONRoundtrip(t *testing.T) {
	bundle := makeBundle()
	data, err := json.Marshal(bundle)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	restored, err := ParseTrustBundle(string(data))
	if err != nil {
		t.Fatalf("failed to parse: %v", err)
	}

	if restored.SchemapinBundleVersion != "1.2" {
		t.Errorf("expected version 1.2, got %s", restored.SchemapinBundleVersion)
	}
	if len(restored.Documents) != 1 {
		t.Errorf("expected 1 document, got %d", len(restored.Documents))
	}
	if restored.Documents[0].Domain != "example.com" {
		t.Errorf("expected domain example.com, got %s", restored.Documents[0].Domain)
	}
	if restored.Documents[0].WellKnown.DeveloperName != "Test Dev" {
		t.Errorf("expected developer Test Dev, got %s", restored.Documents[0].WellKnown.DeveloperName)
	}
	if len(restored.Revocations) != 1 {
		t.Errorf("expected 1 revocation, got %d", len(restored.Revocations))
	}
}

func TestFlattenedFormat(t *testing.T) {
	bd := BundledDiscovery{
		Domain: "example.com",
		WellKnown: discovery.WellKnownResponse{
			SchemaVersion: "1.2",
			DeveloperName: "Dev",
			PublicKeyPEM:  "PEM",
			Contact:       "dev@example.com",
		},
	}

	data, err := json.Marshal(bd)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	// All fields should be at the same level
	if m["domain"] != "example.com" {
		t.Errorf("expected domain example.com, got %v", m["domain"])
	}
	if m["schema_version"] != "1.2" {
		t.Errorf("expected schema_version 1.2, got %v", m["schema_version"])
	}
	if m["developer_name"] != "Dev" {
		t.Errorf("expected developer_name Dev, got %v", m["developer_name"])
	}
	if m["public_key_pem"] != "PEM" {
		t.Errorf("expected public_key_pem PEM, got %v", m["public_key_pem"])
	}
	if m["contact"] != "dev@example.com" {
		t.Errorf("expected contact dev@example.com, got %v", m["contact"])
	}
}

func TestEmptyBundle(t *testing.T) {
	bundle := NewTrustBundle("2026-01-01T00:00:00Z")
	if bundle.FindDiscovery("example.com") != nil {
		t.Error("expected nil for empty bundle")
	}
	if bundle.FindRevocation("example.com") != nil {
		t.Error("expected nil for empty bundle")
	}
}
