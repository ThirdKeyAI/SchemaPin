package skill

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ThirdKeyAi/schemapin/go/pkg/verification"
)

// TestSignWithTTLWritesExpiresAt confirms that providing a positive
// ExpiresIn yields a signature with an expires_at field and bumps the
// schemapin_version to "1.4". It also verifies the value survives a
// disk round-trip.
func TestSignWithTTLWritesExpiresAt(t *testing.T) {
	privPEM, _ := makeKeypair(t)
	dir := createSkillDir(t, map[string]string{
		"SKILL.md": "---\nname: ttl\n---\n",
	})

	sig, err := SignSkillWithOptions(dir, privPEM, "example.com", SignOptions{
		ExpiresIn: 30 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}

	if sig.ExpiresAt == "" {
		t.Error("expected ExpiresAt to be set")
	}
	if sig.SchemapinVersion != "1.4" {
		t.Errorf("expected schemapin_version '1.4', got %q", sig.SchemapinVersion)
	}
	if _, err := time.Parse(time.RFC3339, sig.ExpiresAt); err != nil {
		t.Errorf("ExpiresAt %q is not RFC 3339: %v", sig.ExpiresAt, err)
	}

	// Round-trip through disk.
	loaded, err := LoadSignature(dir)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.ExpiresAt != sig.ExpiresAt {
		t.Errorf("on-disk ExpiresAt mismatch: got %q want %q", loaded.ExpiresAt, sig.ExpiresAt)
	}
	if loaded.SchemapinVersion != "1.4" {
		t.Errorf("on-disk version mismatch: got %q want '1.4'", loaded.SchemapinVersion)
	}
}

// TestSignWithoutTTLOmitsExpiresAt ensures that the v1.3 default behaviour
// is byte-compatible: no expires_at field, schemapin_version stays at "1.3".
func TestSignWithoutTTLOmitsExpiresAt(t *testing.T) {
	privPEM, _ := makeKeypair(t)
	dir := createSkillDir(t, map[string]string{
		"SKILL.md": "---\nname: no-ttl\n---\n",
	})

	sig, err := SignSkill(dir, privPEM, "example.com", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if sig.ExpiresAt != "" {
		t.Errorf("expected ExpiresAt to be empty, got %q", sig.ExpiresAt)
	}
	if sig.SchemapinVersion != "1.3" {
		t.Errorf("expected schemapin_version '1.3', got %q", sig.SchemapinVersion)
	}

	raw, err := os.ReadFile(filepath.Join(dir, SignatureFilename))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "expires_at") {
		t.Errorf("on-disk JSON must not contain 'expires_at'; got: %s", raw)
	}
}

// TestVerifyWithFutureTTLPassesNoWarnings exercises the happy path: a
// signature with a future expires_at must verify cleanly with no expired
// flag and no expiration warning.
func TestVerifyWithFutureTTLPassesNoWarnings(t *testing.T) {
	privPEM, pubPEM := makeKeypair(t)
	dir := createSkillDir(t, map[string]string{
		"SKILL.md": "---\nname: future\n---\n",
	})

	sig, err := SignSkillWithOptions(dir, privPEM, "example.com", SignOptions{
		ExpiresIn: 30 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}

	disc := makeDiscovery(pubPEM)
	result := VerifySkillOffline(dir, disc, sig, nil, nil, "future")

	if !result.Valid {
		t.Errorf("expected valid, got error: %s", result.ErrorMessage)
	}
	if result.Expired {
		t.Error("expected Expired=false for future ttl")
	}
	if result.ExpiresAt == "" {
		t.Error("expected ExpiresAt to be populated on the result")
	}
	for _, w := range result.Warnings {
		if w == verification.WarningSignatureExpired {
			t.Error("did not expect signature_expired warning for future ttl")
		}
	}
}

// TestVerifyWithPastTTLPassesWithExpiredWarning rewrites a fresh signature
// on disk with a past expires_at and confirms the verifier degrades:
// Valid stays true, Expired becomes true, and a "signature_expired"
// warning is emitted.
func TestVerifyWithPastTTLPassesWithExpiredWarning(t *testing.T) {
	privPEM, pubPEM := makeKeypair(t)
	dir := createSkillDir(t, map[string]string{
		"SKILL.md": "---\nname: past\n---\n",
	})

	sig, err := SignSkill(dir, privPEM, "example.com", "", "")
	if err != nil {
		t.Fatal(err)
	}

	// Mutate to past expiration and rewrite the .schemapin.sig.
	sig.ExpiresAt = time.Now().UTC().Add(-24 * time.Hour).Format(time.RFC3339)
	sig.SchemapinVersion = "1.4"
	data, err := json.MarshalIndent(sig, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, SignatureFilename), append(data, '\n'), 0600); err != nil {
		t.Fatal(err)
	}

	disc := makeDiscovery(pubPEM)
	result := VerifySkillOffline(dir, disc, nil, nil, nil, "past")

	if !result.Valid {
		t.Errorf("expired signatures should degrade, not fail; got error: %s", result.ErrorMessage)
	}
	if !result.Expired {
		t.Error("expected Expired=true for past ttl")
	}
	if result.ExpiresAt == "" {
		t.Error("expected ExpiresAt to be populated on the result")
	}

	found := false
	for _, w := range result.Warnings {
		if w == verification.WarningSignatureExpired {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected warnings to contain %q; got %v", verification.WarningSignatureExpired, result.Warnings)
	}
}

// TestVerifyWithUnparseableExpiresAtWarns confirms fail-open semantics:
// a malformed expires_at is reported as a warning, not a hard failure or
// an Expired flag.
func TestVerifyWithUnparseableExpiresAtWarns(t *testing.T) {
	privPEM, pubPEM := makeKeypair(t)
	dir := createSkillDir(t, map[string]string{
		"SKILL.md": "---\nname: bad\n---\n",
	})

	sig, err := SignSkill(dir, privPEM, "example.com", "", "")
	if err != nil {
		t.Fatal(err)
	}
	sig.ExpiresAt = "not-a-timestamp"
	data, err := json.MarshalIndent(sig, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, SignatureFilename), append(data, '\n'), 0600); err != nil {
		t.Fatal(err)
	}

	disc := makeDiscovery(pubPEM)
	result := VerifySkillOffline(dir, disc, nil, nil, nil, "bad")

	if !result.Valid {
		t.Errorf("expected valid (fail-open) for unparseable expires_at; got error: %s", result.ErrorMessage)
	}
	if result.Expired {
		t.Error("expected Expired=false for unparseable expires_at")
	}

	found := false
	for _, w := range result.Warnings {
		if w == verification.WarningSignatureExpiresAtUnparseable {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected warning %q; got %v", verification.WarningSignatureExpiresAtUnparseable, result.Warnings)
	}
}
