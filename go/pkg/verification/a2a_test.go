package verification

import (
	"testing"

	"github.com/ThirdKeyAi/schemapin/go/pkg/core"
	"github.com/ThirdKeyAi/schemapin/go/pkg/crypto"
	"github.com/ThirdKeyAi/schemapin/go/pkg/discovery"
)

// ──────────────────────────────────────────────────────────────────────
// AllowedDomains helpers — AgentPin v0.3 §4.11 semantics
// ──────────────────────────────────────────────────────────────────────

func TestA2AIsUnrestricted(t *testing.T) {
	if !A2AIsUnrestricted(nil) {
		t.Error("nil should be unrestricted")
	}
	if !A2AIsUnrestricted([]string{}) {
		t.Error("empty slice should be unrestricted")
	}
	if A2AIsUnrestricted([]string{"a.com"}) {
		t.Error("non-empty slice should not be unrestricted")
	}
}

func TestA2AAllowsUnrestricted(t *testing.T) {
	if !A2AAllows(nil, "literally-anything") {
		t.Error("nil list should allow anything")
	}
}

func TestA2AAllowsRestricted(t *testing.T) {
	ad := []string{"api.client.com", "*.partner.com"}
	cases := map[string]bool{
		"api.client.com":         true,
		"tools.partner.com":      true,
		"deep.tools.partner.com": true,
		"partner.com":            false, // *.partner.com excludes bare
		"evil.example.com":       false,
	}
	for domain, want := range cases {
		got := A2AAllows(ad, domain)
		if got != want {
			t.Errorf("A2AAllows(%v, %q) = %v, want %v", ad, domain, got, want)
		}
	}
}

func TestA2AIntersectWithUnrestrictedReturnsOther(t *testing.T) {
	restricted := []string{"a.com", "b.com"}
	got := A2AIntersect(nil, restricted)
	if len(got) != 2 || got[0] != "a.com" || got[1] != "b.com" {
		t.Errorf("unrestricted ∩ X should equal X, got %v", got)
	}
	got = A2AIntersect(restricted, nil)
	if len(got) != 2 || got[0] != "a.com" || got[1] != "b.com" {
		t.Errorf("X ∩ unrestricted should equal X, got %v", got)
	}
}

func TestA2AIntersectOverlap(t *testing.T) {
	got := A2AIntersect([]string{"a.com", "b.com", "c.com"}, []string{"b.com", "c.com", "d.com"})
	want := []string{"b.com", "c.com"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("expected %v, got %v", want, got)
	}
}

func TestA2AIntersectEmptyOverlapIsUnrestricted(t *testing.T) {
	got := A2AIntersect([]string{"a.com"}, []string{"b.com"})
	if !A2AIsUnrestricted(got) {
		t.Errorf("disjoint non-empty intersection should be re-interpreted as unrestricted, got %v", got)
	}
}

// ──────────────────────────────────────────────────────────────────────
// Canonicalization id
// ──────────────────────────────────────────────────────────────────────

func TestCheckCanonicalizationAbsent(t *testing.T) {
	if got := CheckCanonicalization(""); got != "" {
		t.Errorf("empty should be supported, got %q", got)
	}
}

func TestCheckCanonicalizationV1(t *testing.T) {
	if got := CheckCanonicalization(CanonicalizationV1); got != "" {
		t.Errorf("v1 should be supported, got %q", got)
	}
}

func TestCheckCanonicalizationUnknown(t *testing.T) {
	if got := CheckCanonicalization("schemapin-v999"); got != "schemapin-v999" {
		t.Errorf("unknown should return offending value, got %q", got)
	}
}

// ──────────────────────────────────────────────────────────────────────
// VerifySchemaForA2A — signed fixture helper
// ──────────────────────────────────────────────────────────────────────

type signedFixture struct {
	schema map[string]interface{}
	sig    string
	disc   *discovery.WellKnownResponse
}

func setupSignedSchema(t *testing.T) *signedFixture {
	t.Helper()
	kp, err := crypto.NewKeyManager().GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	pubPEM, err := crypto.NewKeyManager().ExportPublicKeyPEM(&kp.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	schema := map[string]interface{}{
		"name":        "calculate_sum",
		"description": "Calculates the sum of two numbers",
		"parameters":  map[string]interface{}{"a": "integer", "b": "integer"},
	}
	c := core.NewSchemaPinCore()
	schemaHash, err := c.CanonicalizeAndHash(schema)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := crypto.NewSignatureManager().SignHash(schemaHash, kp)
	if err != nil {
		t.Fatal(err)
	}
	return &signedFixture{
		schema: schema,
		sig:    sig,
		disc: &discovery.WellKnownResponse{
			SchemaVersion: "1.2",
			DeveloperName: "Test Developer",
			PublicKeyPEM:  pubPEM,
		},
	}
}

func ctxFor(trusted []string, depth uint8) *A2AVerificationContext {
	return &A2AVerificationContext{
		CallerAgentID:     "urn:agentpin:caller.com:test",
		DelegationDepth:   depth,
		OriginatingDomain: "caller.com",
		TrustedDomains:    trusted,
	}
}

// ──────────────────────────────────────────────────────────────────────
// verifySchemaOfflineWithCanonicalization
// ──────────────────────────────────────────────────────────────────────

func TestVerifySchemaOfflineCanonicalizationAbsent(t *testing.T) {
	f := setupSignedSchema(t)
	result := VerifySchemaOfflineWithCanonicalization(
		f.schema, f.sig, "example.com", "calculate_sum",
		f.disc, nil, NewKeyPinStore(), "",
	)
	if !result.Valid {
		t.Fatalf("expected valid, got %+v", result)
	}
}

func TestVerifySchemaOfflineCanonicalizationV1(t *testing.T) {
	f := setupSignedSchema(t)
	result := VerifySchemaOfflineWithCanonicalization(
		f.schema, f.sig, "example.com", "calculate_sum",
		f.disc, nil, NewKeyPinStore(), CanonicalizationV1,
	)
	if !result.Valid {
		t.Fatalf("expected valid, got %+v", result)
	}
}

func TestVerifySchemaOfflineCanonicalizationUnknown(t *testing.T) {
	f := setupSignedSchema(t)
	result := VerifySchemaOfflineWithCanonicalization(
		f.schema, f.sig, "example.com", "calculate_sum",
		f.disc, nil, NewKeyPinStore(), "schemapin-v999",
	)
	if result.Valid {
		t.Fatal("expected invalid")
	}
	if result.ErrorCode != ErrCanonicalizationUnsupported {
		t.Errorf("expected %s, got %s", ErrCanonicalizationUnsupported, result.ErrorCode)
	}
}

// ──────────────────────────────────────────────────────────────────────
// VerifySchemaForA2A
// ──────────────────────────────────────────────────────────────────────

func TestVerifySchemaForA2AUnrestrictedCaller(t *testing.T) {
	f := setupSignedSchema(t)
	result := VerifySchemaForA2A(
		f.schema, f.sig, "example.com", "calculate_sum",
		f.disc, nil, NewKeyPinStore(),
		ctxFor(nil, 0), "",
	)
	if !result.Valid {
		t.Fatalf("expected valid, got %+v", result)
	}
}

func TestVerifySchemaForA2ACallerAllowsProvider(t *testing.T) {
	f := setupSignedSchema(t)
	result := VerifySchemaForA2A(
		f.schema, f.sig, "example.com", "calculate_sum",
		f.disc, nil, NewKeyPinStore(),
		ctxFor([]string{"example.com", "other.com"}, 1), "",
	)
	if !result.Valid {
		t.Fatalf("expected valid, got %+v", result)
	}
}

func TestVerifySchemaForA2AProviderOutsideScope(t *testing.T) {
	f := setupSignedSchema(t)
	result := VerifySchemaForA2A(
		f.schema, f.sig, "example.com", "calculate_sum",
		f.disc, nil, NewKeyPinStore(),
		ctxFor([]string{"other.com"}, 0), "",
	)
	if result.Valid {
		t.Fatal("expected invalid")
	}
	if result.ErrorCode != ErrA2AScopeViolation {
		t.Errorf("expected %s, got %s", ErrA2AScopeViolation, result.ErrorCode)
	}
}

func TestVerifySchemaForA2ADelegationDepthCap(t *testing.T) {
	f := setupSignedSchema(t)
	result := VerifySchemaForA2A(
		f.schema, f.sig, "example.com", "calculate_sum",
		f.disc, nil, NewKeyPinStore(),
		ctxFor(nil, A2AMaxDelegationDepth+1), "",
	)
	if result.Valid {
		t.Fatal("expected invalid")
	}
	if result.ErrorCode != ErrA2AScopeViolation {
		t.Errorf("expected %s, got %s", ErrA2AScopeViolation, result.ErrorCode)
	}
}

func TestVerifySchemaForA2AUnderlyingFailurePassesThrough(t *testing.T) {
	f := setupSignedSchema(t)
	result := VerifySchemaForA2A(
		f.schema, "bm90LWEtdmFsaWQtc2lnbmF0dXJl", "example.com", "calculate_sum",
		f.disc, nil, NewKeyPinStore(),
		ctxFor(nil, 0), "",
	)
	if result.Valid {
		t.Fatal("expected invalid")
	}
	if result.ErrorCode != ErrSignatureInvalid {
		t.Errorf("expected %s (underlying failure), got %s", ErrSignatureInvalid, result.ErrorCode)
	}
}

func TestVerifySchemaForA2ACanonicalizationUnknownPropagates(t *testing.T) {
	f := setupSignedSchema(t)
	result := VerifySchemaForA2A(
		f.schema, f.sig, "example.com", "calculate_sum",
		f.disc, nil, NewKeyPinStore(),
		ctxFor(nil, 0), "schemapin-v999",
	)
	if result.Valid {
		t.Fatal("expected invalid")
	}
	if result.ErrorCode != ErrCanonicalizationUnsupported {
		t.Errorf("expected %s, got %s", ErrCanonicalizationUnsupported, result.ErrorCode)
	}
}

func TestVerifySchemaForA2AWildcardCallerAllowList(t *testing.T) {
	f := setupSignedSchema(t)
	result := VerifySchemaForA2A(
		f.schema, f.sig, "api.example.com", "calculate_sum",
		f.disc, nil, NewKeyPinStore(),
		ctxFor([]string{"*.example.com"}, 0), "",
	)
	if !result.Valid {
		t.Fatalf("expected valid, got %+v", result)
	}
}
