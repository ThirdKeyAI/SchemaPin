package skill

import (
	"errors"
	"testing"
)

func lineageDoc(hash, previous, version, schemapin string) *SkillSignature {
	return &SkillSignature{SchemapinVersion: schemapin, SkillHash: hash, PreviousHash: previous, SchemaVersion: version}
}

func TestLineageStoreFlow(t *testing.T) {
	s := NewLineageStore()
	if r, err := s.CheckAndAdvance("calc", "example.com", lineageDoc("sha256:a", "", "1.0.0", "1.4"), true); err != nil || r != LineageFirstUse {
		t.Fatalf("first use: %v %v", r, err)
	}
	if r, _ := s.CheckAndAdvance("calc", "example.com", lineageDoc("sha256:a", "", "1.0.0", "1.4"), true); r != LineageUnchanged {
		t.Fatalf("expected unchanged, got %v", r)
	}
	if r, err := s.CheckAndAdvance("calc", "example.com", lineageDoc("sha256:b", "sha256:a", "1.1.0", "1.4"), true); err != nil || r != LineageAdvanced {
		t.Fatalf("advance: %v %v", r, err)
	}
	if rec, _ := s.Get("calc", "example.com"); rec.SkillHash != "sha256:b" {
		t.Fatalf("head not advanced: %+v", rec)
	}
	// Fork from the old head and missing previous_hash are rejected.
	var le *LineageError
	if _, err := s.CheckAndAdvance("calc", "example.com", lineageDoc("sha256:bx", "sha256:a", "", "1.4"), true); !errors.As(err, &le) {
		t.Fatalf("fork must be rejected, got %v", err)
	}
	if _, err := s.CheckAndAdvance("calc", "example.com", lineageDoc("sha256:c", "", "", "1.4"), true); !errors.As(err, &le) {
		t.Fatalf("missing previous_hash must be rejected, got %v", err)
	}
	if r, err := s.CheckAndAdvance("calc", "example.com", lineageDoc("sha256:c", "", "", "1.4"), false); err != nil || r != LineageAdvanced {
		t.Fatalf("requireChain=false must advance: %v %v", r, err)
	}
}

func TestLineageVersionAndLegacy(t *testing.T) {
	s := NewLineageStore()
	_, _ = s.CheckAndAdvance("calc", "example.com", lineageDoc("sha256:a", "", "1.9.0", "1.4"), true)
	if _, err := s.CheckAndAdvance("calc", "example.com", lineageDoc("sha256:b", "sha256:a", "1.9.0", "1.4"), true); err == nil {
		t.Fatal("equal schema_version must be rejected")
	}
	if _, err := s.CheckAndAdvance("calc", "example.com", lineageDoc("sha256:b", "sha256:a", "1.2.0", "1.4"), true); err == nil {
		t.Fatal("lower schema_version must be rejected")
	}
	if r, err := s.CheckAndAdvance("calc", "example.com", lineageDoc("sha256:b", "sha256:a", "1.10.0", "1.4"), true); err != nil || r != LineageAdvanced {
		t.Fatalf("1.10.0 must sort after 1.9.0: %v %v", r, err)
	}
	if !VersionIncreases("1.9.0", "1.10.0") || VersionIncreases("2.0.0", "2.0.0") || !VersionIncreases("abc", "abd") {
		t.Fatal("VersionIncreases semantics")
	}
	if _, err := s.CheckAndAdvance("calc", "example.com", lineageDoc("sha256:z", "sha256:b", "", "1.3"), true); err == nil {
		t.Fatal("legacy documents must be refused")
	}
	js, err := s.ToJSON()
	if err != nil {
		t.Fatal(err)
	}
	restored, err := LineageStoreFromJSON(js)
	if err != nil {
		t.Fatal(err)
	}
	if rec, ok := restored.Get("calc", "example.com"); !ok || rec.SchemaVersion != "1.10.0" {
		t.Fatalf("round trip lost state: %+v", rec)
	}
	if _, err := LineageStoreFromJSON("[]"); err == nil {
		t.Fatal("array must be rejected")
	}
}
