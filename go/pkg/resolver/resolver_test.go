package resolver

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/ThirdKeyAi/schemapin/go/pkg/bundle"
	"github.com/ThirdKeyAi/schemapin/go/pkg/discovery"
	"github.com/ThirdKeyAi/schemapin/go/pkg/revocation"
)

func makeBundle() *bundle.SchemaPinTrustBundle {
	b := bundle.NewTrustBundle("2026-01-01T00:00:00Z")
	b.Documents = append(b.Documents, bundle.BundledDiscovery{
		Domain: "example.com",
		WellKnown: discovery.WellKnownResponse{
			SchemaVersion: "1.2",
			DeveloperName: "Test Dev",
			PublicKeyPEM:  "-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----",
		},
	})

	rev := revocation.BuildRevocationDocument("example.com")
	revocation.AddRevokedKey(rev, "sha256:old", revocation.ReasonSuperseded)
	b.Revocations = append(b.Revocations, *rev)

	return b
}

func TestTrustBundleResolverDiscoveryHit(t *testing.T) {
	resolver := NewTrustBundleResolver(makeBundle())
	disc, err := resolver.ResolveDiscovery("example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if disc.DeveloperName != "Test Dev" {
		t.Errorf("expected Test Dev, got %s", disc.DeveloperName)
	}
}

func TestTrustBundleResolverDiscoveryMiss(t *testing.T) {
	resolver := NewTrustBundleResolver(makeBundle())
	_, err := resolver.ResolveDiscovery("unknown.com")
	if err == nil {
		t.Error("expected error for unknown domain")
	}
}

func TestTrustBundleResolverRevocation(t *testing.T) {
	resolver := NewTrustBundleResolver(makeBundle())
	disc, _ := resolver.ResolveDiscovery("example.com")
	rev, err := resolver.ResolveRevocation("example.com", disc)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rev == nil {
		t.Fatal("expected non-nil revocation")
	}
	if rev.Domain != "example.com" {
		t.Errorf("expected domain example.com, got %s", rev.Domain)
	}
}

func TestTrustBundleResolverFromJSON(t *testing.T) {
	b := makeBundle()
	data, err := json.Marshal(b)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	resolver, err := FromJSON(string(data))
	if err != nil {
		t.Fatalf("failed to create from JSON: %v", err)
	}

	disc, err := resolver.ResolveDiscovery("example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if disc.DeveloperName != "Test Dev" {
		t.Errorf("expected Test Dev, got %s", disc.DeveloperName)
	}
}

func TestLocalFileResolverDiscovery(t *testing.T) {
	tmpDir := t.TempDir()
	wellKnown := discovery.WellKnownResponse{
		SchemaVersion: "1.2",
		DeveloperName: "File Dev",
		PublicKeyPEM:  "PEM_DATA",
	}
	data, _ := json.Marshal(wellKnown)
	if err := os.WriteFile(filepath.Join(tmpDir, "example.com.json"), data, 0644); err != nil {
		t.Fatalf("failed to write file: %v", err)
	}

	resolver := NewLocalFileResolver(tmpDir, "")
	disc, err := resolver.ResolveDiscovery("example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if disc.DeveloperName != "File Dev" {
		t.Errorf("expected File Dev, got %s", disc.DeveloperName)
	}
}

func TestLocalFileResolverDiscoveryMissing(t *testing.T) {
	tmpDir := t.TempDir()
	resolver := NewLocalFileResolver(tmpDir, "")
	_, err := resolver.ResolveDiscovery("missing.com")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestLocalFileResolverRevocation(t *testing.T) {
	tmpDir := t.TempDir()
	rev := revocation.BuildRevocationDocument("example.com")
	revocation.AddRevokedKey(rev, "sha256:bad", revocation.ReasonKeyCompromise)
	data, _ := json.Marshal(rev)
	if err := os.WriteFile(filepath.Join(tmpDir, "example.com.revocations.json"), data, 0644); err != nil {
		t.Fatalf("failed to write file: %v", err)
	}

	resolver := NewLocalFileResolver(".", tmpDir)
	doc, err := resolver.ResolveRevocation("example.com", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if doc == nil {
		t.Fatal("expected non-nil revocation")
	}
	if doc.Domain != "example.com" {
		t.Errorf("expected domain example.com, got %s", doc.Domain)
	}
}

func TestLocalFileResolverNoRevDir(t *testing.T) {
	resolver := NewLocalFileResolver(".", "")
	doc, err := resolver.ResolveRevocation("example.com", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if doc != nil {
		t.Error("expected nil for empty revocation dir")
	}
}

func TestChainResolverFirstWins(t *testing.T) {
	b1 := bundle.NewTrustBundle("2026-01-01T00:00:00Z")
	b1.Documents = append(b1.Documents, bundle.BundledDiscovery{
		Domain: "a.com",
		WellKnown: discovery.WellKnownResponse{
			SchemaVersion: "1.2",
			DeveloperName: "First",
			PublicKeyPEM:  "PEM1",
		},
	})

	b2 := bundle.NewTrustBundle("2026-01-01T00:00:00Z")
	b2.Documents = append(b2.Documents, bundle.BundledDiscovery{
		Domain: "a.com",
		WellKnown: discovery.WellKnownResponse{
			SchemaVersion: "1.2",
			DeveloperName: "Second",
			PublicKeyPEM:  "PEM2",
		},
	})

	chain := NewChainResolver([]SchemaResolver{
		NewTrustBundleResolver(b1),
		NewTrustBundleResolver(b2),
	})

	disc, err := chain.ResolveDiscovery("a.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if disc.DeveloperName != "First" {
		t.Errorf("expected First, got %s", disc.DeveloperName)
	}
}

func TestChainResolverFallthrough(t *testing.T) {
	b1 := bundle.NewTrustBundle("2026-01-01T00:00:00Z")
	b1.Documents = append(b1.Documents, bundle.BundledDiscovery{
		Domain: "a.com",
		WellKnown: discovery.WellKnownResponse{
			SchemaVersion: "1.2",
			DeveloperName: "First",
			PublicKeyPEM:  "PEM1",
		},
	})

	b2 := bundle.NewTrustBundle("2026-01-01T00:00:00Z")
	b2.Documents = append(b2.Documents, bundle.BundledDiscovery{
		Domain: "b.com",
		WellKnown: discovery.WellKnownResponse{
			SchemaVersion: "1.2",
			DeveloperName: "Second",
			PublicKeyPEM:  "PEM2",
		},
	})

	chain := NewChainResolver([]SchemaResolver{
		NewTrustBundleResolver(b1),
		NewTrustBundleResolver(b2),
	})

	disc, err := chain.ResolveDiscovery("b.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if disc.DeveloperName != "Second" {
		t.Errorf("expected Second, got %s", disc.DeveloperName)
	}
}

func TestChainResolverAllMiss(t *testing.T) {
	b := bundle.NewTrustBundle("2026-01-01T00:00:00Z")
	chain := NewChainResolver([]SchemaResolver{
		NewTrustBundleResolver(b),
	})

	_, err := chain.ResolveDiscovery("missing.com")
	if err == nil {
		t.Error("expected error when all resolvers miss")
	}
}
