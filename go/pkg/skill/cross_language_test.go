package skill

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/ThirdKeyAi/schemapin/go/pkg/discovery"
	"github.com/ThirdKeyAi/schemapin/go/pkg/verification"
)

type skillFixtureExpected struct {
	Domain    string                      `json:"domain"`
	Discovery discovery.WellKnownResponse `json:"discovery"`
	V14       struct {
		SkillDir     string            `json:"skill_dir"`
		SkillHash    string            `json:"skill_hash"`
		FileManifest map[string]string `json:"file_manifest"`
		TamperFields []string          `json:"signed_fields_tamper_must_fail"`
	} `json:"v14"`
	LegacyV13 struct {
		SkillDir     string            `json:"skill_dir"`
		SkillHash    string            `json:"skill_hash"`
		FileManifest map[string]string `json:"file_manifest"`
	} `json:"legacy_v13"`
}

func skillFixtureDir(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 8; i++ {
		candidate := filepath.Join(dir, "tests", "cross-language", "skill")
		if st, err := os.Stat(candidate); err == nil && st.IsDir() {
			return candidate
		}
		dir = filepath.Dir(dir)
	}
	t.Fatal("could not locate tests/cross-language/skill")
	return ""
}

func loadSkillFixture(t *testing.T) (string, *skillFixtureExpected) {
	t.Helper()
	root := skillFixtureDir(t)
	raw, err := os.ReadFile(filepath.Join(root, "expected.json")) // #nosec G304
	if err != nil {
		t.Fatal(err)
	}
	var exp skillFixtureExpected
	if err := json.Unmarshal(raw, &exp); err != nil {
		t.Fatal(err)
	}
	return root, &exp
}

func TestCrossLanguageSkillFixtureV14(t *testing.T) {
	root, exp := loadSkillFixture(t)
	dir := filepath.Join(root, exp.V14.SkillDir)
	rootHash, manifest, err := CanonicalizeSkill(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := "sha256:" + hex.EncodeToString(rootHash); got != exp.V14.SkillHash {
		t.Fatalf("skill_hash mismatch: %s != %s", got, exp.V14.SkillHash)
	}
	if !reflect.DeepEqual(manifest, exp.V14.FileManifest) {
		t.Fatalf("manifest mismatch:\n got %v\nwant %v", manifest, exp.V14.FileManifest)
	}
	r := VerifySkillOfflineWithOptions(dir, &exp.Discovery, nil, nil, nil, VerifyOptions{Domain: exp.Domain})
	if !r.Valid {
		t.Fatalf("fixture must verify: %+v", r)
	}
	for _, w := range r.Warnings {
		if w == verification.WarningLegacySignatureFormat {
			t.Fatal("v1.4 fixture must not be treated as legacy")
		}
	}
	if r.SchemaVersion != "1.0.0" {
		t.Fatalf("expected schema_version 1.0.0, got %q", r.SchemaVersion)
	}
}

func TestCrossLanguageSkillFixtureV14Tamper(t *testing.T) {
	root, exp := loadSkillFixture(t)
	src := filepath.Join(root, exp.V14.SkillDir)
	for _, field := range exp.V14.TamperFields {
		dst := filepath.Join(t.TempDir(), field)
		if err := os.CopyFS(dst, os.DirFS(src)); err != nil {
			t.Fatal(err)
		}
		raw, err := os.ReadFile(filepath.Join(dst, SignatureFilename)) // #nosec G304
		if err != nil {
			t.Fatal(err)
		}
		var doc map[string]interface{}
		_ = json.Unmarshal(raw, &doc)
		if field == "skill_hash" {
			doc[field] = "sha256:" + hex.EncodeToString(make([]byte, 32))
		} else {
			doc[field] = "tampered"
		}
		out, _ := json.Marshal(doc)
		if err := os.WriteFile(filepath.Join(dst, SignatureFilename), out, 0600); err != nil {
			t.Fatal(err)
		}
		if r := VerifySkillOffline(dst, &exp.Discovery, nil, nil, nil, ""); r.Valid {
			t.Errorf("tampering %s must fail", field)
		}
	}
	dst := filepath.Join(t.TempDir(), "content")
	if err := os.CopyFS(dst, os.DirFS(src)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dst, "scripts", "run.sh"), []byte("#!/bin/sh\nrm -rf /\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if r := VerifySkillOffline(dst, &exp.Discovery, nil, nil, nil, ""); r.Valid {
		t.Fatal("content tamper must fail")
	}
}

func TestCrossLanguageSkillFixtureLegacyV13(t *testing.T) {
	root, exp := loadSkillFixture(t)
	dir := filepath.Join(root, exp.LegacyV13.SkillDir)
	rootHash, manifest, err := CanonicalizeSkillV1(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := "sha256:" + hex.EncodeToString(rootHash); got != exp.LegacyV13.SkillHash {
		t.Fatalf("legacy skill_hash mismatch: %s != %s", got, exp.LegacyV13.SkillHash)
	}
	if !reflect.DeepEqual(manifest, exp.LegacyV13.FileManifest) {
		t.Fatalf("legacy manifest mismatch")
	}
	r := VerifySkillOfflineWithOptions(dir, &exp.Discovery, nil, nil, nil, VerifyOptions{Domain: exp.Domain})
	if !r.Valid {
		t.Fatalf("legacy fixture must verify: %+v", r)
	}
	found := false
	for _, w := range r.Warnings {
		if w == verification.WarningLegacySignatureFormat {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected legacy warning: %v", r.Warnings)
	}
}
