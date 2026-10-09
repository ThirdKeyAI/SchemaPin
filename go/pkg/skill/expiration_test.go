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

// TestSignWithoutTTLOmitsExpiresAt ensures that the default signature writes
// no expires_at field and uses the signed-document format ("1.4").
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
	if sig.SchemapinVersion != "1.4" {
		t.Errorf("expected schemapin_version '1.4', got %q", sig.SchemapinVersion)
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

// TestVerifyWithPastTTLFailsClosed signs with a TTL already in the past and
// confirms the verifier fails closed with ErrSignatureExpired by default, and
// degrades (Valid, Expired, warning) only when AllowExpired is set.
func TestVerifyWithPastTTLFailsClosed(t *testing.T) {
	privPEM, pubPEM := makeKeypair(t)
	dir := createSkillDir(t, map[string]string{
		"SKILL.md": "---\nname: past\n---\n",
	})

	if _, err := SignSkillWithOptions(dir, privPEM, "example.com", SignOptions{ExpiresIn: -24 * time.Hour}); err != nil {
		t.Fatal(err)
	}

	disc := makeDiscovery(pubPEM)
	result := VerifySkillOffline(dir, disc, nil, nil, nil, "past")
	if result.Valid {
		t.Fatal("expired signatures must fail closed by default")
	}
	if result.ErrorCode != verification.ErrSignatureExpired {
		t.Errorf("expected ErrSignatureExpired, got %q", result.ErrorCode)
	}
	if !result.Expired {
		t.Error("expected Expired=true")
	}

	degraded := VerifySkillOfflineWithOptions(dir, disc, nil, nil, nil, VerifyOptions{ToolID: "past", AllowExpired: true})
	if !degraded.Valid || !degraded.Expired {
		t.Fatalf("AllowExpired should degrade, not fail: %+v", degraded)
	}
	found := false
	for _, w := range degraded.Warnings {
		if w == verification.WarningSignatureExpired {
			found = true
		}
	}
	if !found {
		t.Errorf("expected warnings to contain %q; got %v", verification.WarningSignatureExpired, degraded.Warnings)
	}
}

// TestUnparseableExpiresAtFailsClosed confirms that a malformed or
// non-RFC-3339 expires_at is a hard failure unless AllowExpired is set.
func TestUnparseableExpiresAtFailsClosed(t *testing.T) {
	for _, bad := range []string{"not-a-timestamp", "2020-01-01", "2020-01-01T00:00:00", "2020-01-01 00:00:00Z"} {
		r := (&verification.VerificationResult{Valid: true}).WithExpirationPolicy(bad, false)
		if r.Valid || r.ErrorCode != verification.ErrSignatureExpired {
			t.Errorf("%q: expected ErrSignatureExpired, got %+v", bad, r)
		}
		lenient := (&verification.VerificationResult{Valid: true}).WithExpirationPolicy(bad, true)
		if !lenient.Valid || len(lenient.Warnings) == 0 || lenient.Warnings[0] != verification.WarningSignatureExpiresAtUnparseable {
			t.Errorf("%q: expected unparseable warning with AllowExpired, got %+v", bad, lenient)
		}
	}
	justNow := time.Now().UTC().Add(-60 * time.Second).Format(time.RFC3339)
	if r := (&verification.VerificationResult{Valid: true}).WithExpirationPolicy(justNow, false); !r.Valid || r.Expired {
		t.Errorf("timestamp inside the skew window must not be expired: %+v", r)
	}
}

// TestExpiresAtIsCoveredBySignature is the SP-1 regression: deleting
// expires_at (and downgrading the version) after signing must invalidate.
func TestExpiresAtIsCoveredBySignature(t *testing.T) {
	privPEM, pubPEM := makeKeypair(t)
	dir := createSkillDir(t, map[string]string{
		"SKILL.md": "---\nname: strip\n---\n",
	})
	sig, err := SignSkillWithOptions(dir, privPEM, "example.com", SignOptions{ExpiresIn: -24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	sig.ExpiresAt = ""
	writeSig(t, dir, sig)
	if r := VerifySkillOffline(dir, makeDiscovery(pubPEM), nil, nil, nil, "strip"); r.Valid || r.ErrorCode != verification.ErrSignatureInvalid {
		t.Fatalf("stripping expires_at must invalidate: %+v", r)
	}
	sig.SchemapinVersion = "1.3"
	writeSig(t, dir, sig)
	if r := VerifySkillOffline(dir, makeDiscovery(pubPEM), nil, nil, nil, "strip"); r.Valid {
		t.Fatalf("downgrade to 1.3 must invalidate: %+v", r)
	}
}

func writeSig(t *testing.T, dir string, sig *SkillSignature) {
	t.Helper()
	data, err := json.MarshalIndent(sig, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, SignatureFilename), append(data, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
}
