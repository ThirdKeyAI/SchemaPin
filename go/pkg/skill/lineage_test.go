package skill

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestSignWithSchemaVersionWritesField confirms a non-empty SchemaVersion is
// written and bumps schemapin_version to "1.4".
func TestSignWithSchemaVersionWritesField(t *testing.T) {
	privPEM, _ := makeKeypair(t)
	dir := createSkillDir(t, map[string]string{
		"SKILL.md": "---\nname: ver\n---\n",
	})

	sig, err := SignSkillWithOptions(dir, privPEM, "example.com", SignOptions{
		SchemaVersion: "2.1.0",
	})
	if err != nil {
		t.Fatalf("SignSkillWithOptions: %v", err)
	}
	if sig.SchemaVersion != "2.1.0" {
		t.Fatalf("SchemaVersion = %q, want 2.1.0", sig.SchemaVersion)
	}
	if sig.SchemapinVersion != "1.4" {
		t.Fatalf("SchemapinVersion = %q, want 1.4", sig.SchemapinVersion)
	}

	onDisk, err := LoadSignature(dir)
	if err != nil {
		t.Fatalf("LoadSignature: %v", err)
	}
	if onDisk.SchemaVersion != "2.1.0" {
		t.Fatalf("on-disk SchemaVersion = %q, want 2.1.0", onDisk.SchemaVersion)
	}
}

// TestSignWithoutLineageOmitsFields confirms v1.3 sigs (no lineage opts) keep
// the schema_version and previous_hash fields out of the JSON entirely.
func TestSignWithoutLineageOmitsFields(t *testing.T) {
	privPEM, _ := makeKeypair(t)
	dir := createSkillDir(t, map[string]string{
		"SKILL.md": "---\nname: nv\n---\n",
	})

	sig, err := SignSkill(dir, privPEM, "example.com", "", "")
	if err != nil {
		t.Fatalf("SignSkill: %v", err)
	}
	if sig.SchemaVersion != "" {
		t.Fatalf("SchemaVersion should be empty, got %q", sig.SchemaVersion)
	}
	if sig.PreviousHash != "" {
		t.Fatalf("PreviousHash should be empty, got %q", sig.PreviousHash)
	}

	raw, err := os.ReadFile(filepath.Join(dir, SignatureFilename))
	if err != nil {
		t.Fatalf("read sig file: %v", err)
	}
	if strings.Contains(string(raw), "schema_version") {
		t.Fatalf("JSON should omit schema_version, got %s", raw)
	}
	if strings.Contains(string(raw), "previous_hash") {
		t.Fatalf("JSON should omit previous_hash, got %s", raw)
	}
}

// TestSignWithPreviousHashWritesField confirms PreviousHash is written and
// bumps schemapin_version to "1.4".
func TestSignWithPreviousHashWritesField(t *testing.T) {
	privPEM, _ := makeKeypair(t)
	dir := createSkillDir(t, map[string]string{
		"SKILL.md": "---\nname: ch\n---\n",
	})

	sig, err := SignSkillWithOptions(dir, privPEM, "example.com", SignOptions{
		PreviousHash: "sha256:abcdef",
	})
	if err != nil {
		t.Fatalf("SignSkillWithOptions: %v", err)
	}
	if sig.PreviousHash != "sha256:abcdef" {
		t.Fatalf("PreviousHash = %q, want sha256:abcdef", sig.PreviousHash)
	}
	if sig.SchemapinVersion != "1.4" {
		t.Fatalf("SchemapinVersion = %q, want 1.4", sig.SchemapinVersion)
	}
}

// TestVerifyChainMatches accepts a valid lineage.
func TestVerifyChainMatches(t *testing.T) {
	privPEM, _ := makeKeypair(t)
	dir1 := createSkillDir(t, map[string]string{
		"SKILL.md": "---\nname: v1\n---\n",
	})
	v1, err := SignSkill(dir1, privPEM, "example.com", "", "")
	if err != nil {
		t.Fatalf("SignSkill v1: %v", err)
	}

	dir2 := createSkillDir(t, map[string]string{
		"SKILL.md": "---\nname: v2\n---\n",
	})
	v2, err := SignSkillWithOptions(dir2, privPEM, "example.com", SignOptions{
		PreviousHash: v1.SkillHash,
	})
	if err != nil {
		t.Fatalf("SignSkillWithOptions v2: %v", err)
	}

	if err := VerifyChain(v2, v1); err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
}

// TestVerifyChainNoPreviousHashErrors rejects a sig without PreviousHash.
func TestVerifyChainNoPreviousHashErrors(t *testing.T) {
	privPEM, _ := makeKeypair(t)
	dir1 := createSkillDir(t, map[string]string{
		"SKILL.md": "---\nname: v1\n---\n",
	})
	dir2 := createSkillDir(t, map[string]string{
		"SKILL.md": "---\nname: v2\n---\n",
	})
	v1, err := SignSkill(dir1, privPEM, "example.com", "", "")
	if err != nil {
		t.Fatalf("SignSkill v1: %v", err)
	}
	v2, err := SignSkill(dir2, privPEM, "example.com", "", "")
	if err != nil {
		t.Fatalf("SignSkill v2: %v", err)
	}

	err = VerifyChain(v2, v1)
	var ce *ChainError
	if !errors.As(err, &ce) {
		t.Fatalf("expected *ChainError, got %T: %v", err, err)
	}
	if ce.Kind != ChainErrorNoPreviousHash {
		t.Fatalf("Kind = %v, want ChainErrorNoPreviousHash", ce.Kind)
	}
}

// TestVerifyChainMismatchErrors rejects a sig whose PreviousHash points elsewhere.
func TestVerifyChainMismatchErrors(t *testing.T) {
	privPEM, _ := makeKeypair(t)
	dir1 := createSkillDir(t, map[string]string{
		"SKILL.md": "---\nname: v1\n---\n",
	})
	dir2 := createSkillDir(t, map[string]string{
		"SKILL.md": "---\nname: v2\n---\n",
	})
	v1, err := SignSkill(dir1, privPEM, "example.com", "", "")
	if err != nil {
		t.Fatalf("SignSkill v1: %v", err)
	}
	v2, err := SignSkillWithOptions(dir2, privPEM, "example.com", SignOptions{
		PreviousHash: "sha256:not-the-real-prior-hash",
	})
	if err != nil {
		t.Fatalf("SignSkillWithOptions v2: %v", err)
	}

	err = VerifyChain(v2, v1)
	var ce *ChainError
	if !errors.As(err, &ce) {
		t.Fatalf("expected *ChainError, got %T: %v", err, err)
	}
	if ce.Kind != ChainErrorMismatch {
		t.Fatalf("Kind = %v, want ChainErrorMismatch", ce.Kind)
	}
	if ce.Expected != v1.SkillHash {
		t.Fatalf("Expected = %q, want %q", ce.Expected, v1.SkillHash)
	}
	if ce.Got != "sha256:not-the-real-prior-hash" {
		t.Fatalf("Got = %q, want sha256:not-the-real-prior-hash", ce.Got)
	}
}

// TestVerifySkillOfflineSurfacesLineage confirms lineage metadata flows from
// the signature into VerificationResult fields.
func TestVerifySkillOfflineSurfacesLineage(t *testing.T) {
	privPEM, pubPEM := makeKeypair(t)
	dir := createSkillDir(t, map[string]string{
		"SKILL.md": "---\nname: lin\n---\n",
	})
	if _, err := SignSkillWithOptions(dir, privPEM, "example.com", SignOptions{
		SchemaVersion: "3.2.1",
		PreviousHash:  "sha256:deadbeef",
	}); err != nil {
		t.Fatalf("SignSkillWithOptions: %v", err)
	}

	disc := makeDiscovery(pubPEM)
	result := VerifySkillOffline(dir, disc, nil, nil, nil, "lin")
	if !result.Valid {
		t.Fatalf("expected Valid=true, got %+v", result)
	}
	if result.SchemaVersion != "3.2.1" {
		t.Fatalf("SchemaVersion = %q, want 3.2.1", result.SchemaVersion)
	}
	if result.PreviousHash != "sha256:deadbeef" {
		t.Fatalf("PreviousHash = %q, want sha256:deadbeef", result.PreviousHash)
	}
}

// TestCombinedV14FieldsRoundTrip exercises all v1.4 alpha.{1,2} optional
// fields together: expires_at + schema_version + previous_hash.
func TestCombinedV14FieldsRoundTrip(t *testing.T) {
	privPEM, _ := makeKeypair(t)
	dir := createSkillDir(t, map[string]string{
		"SKILL.md": "---\nname: combo\n---\n",
	})
	sig, err := SignSkillWithOptions(dir, privPEM, "example.com", SignOptions{
		ExpiresIn:     180 * 24 * time.Hour,
		SchemaVersion: "1.0.0",
		PreviousHash:  "sha256:cafebabe",
	})
	if err != nil {
		t.Fatalf("SignSkillWithOptions: %v", err)
	}
	if sig.SchemapinVersion != "1.4" {
		t.Fatalf("SchemapinVersion = %q, want 1.4", sig.SchemapinVersion)
	}
	if sig.ExpiresAt == "" {
		t.Fatalf("ExpiresAt should be set")
	}
	if sig.SchemaVersion != "1.0.0" {
		t.Fatalf("SchemaVersion = %q, want 1.0.0", sig.SchemaVersion)
	}
	if sig.PreviousHash != "sha256:cafebabe" {
		t.Fatalf("PreviousHash = %q, want sha256:cafebabe", sig.PreviousHash)
	}

	onDisk, err := LoadSignature(dir)
	if err != nil {
		t.Fatalf("LoadSignature: %v", err)
	}
	if onDisk.ExpiresAt != sig.ExpiresAt {
		t.Fatalf("on-disk ExpiresAt = %q, want %q", onDisk.ExpiresAt, sig.ExpiresAt)
	}
	if onDisk.SchemaVersion != "1.0.0" {
		t.Fatalf("on-disk SchemaVersion = %q, want 1.0.0", onDisk.SchemaVersion)
	}
	if onDisk.PreviousHash != "sha256:cafebabe" {
		t.Fatalf("on-disk PreviousHash = %q, want sha256:cafebabe", onDisk.PreviousHash)
	}
}
