package skill

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
)

// LineageRecord is the latest accepted lineage state for a tool_id@domain.
type LineageRecord struct {
	SkillHash     string `json:"skill_hash"`
	SchemaVersion string `json:"schema_version,omitempty"`
}

// LineageResult is the outcome of LineageStore.CheckAndAdvance.
type LineageResult string

const (
	// LineageFirstUse — nothing was recorded; the document becomes the head.
	LineageFirstUse LineageResult = "first_use"
	// LineageUnchanged — the document's skill_hash is already the head.
	LineageUnchanged LineageResult = "unchanged"
	// LineageAdvanced — the document is a valid successor and is now the head.
	LineageAdvanced LineageResult = "advanced"
)

// LineageError is returned when a signature does not descend from the
// recorded lineage.
type LineageError struct {
	Message string
}

func (e *LineageError) Error() string { return e.Message }

func lineageErr(format string, args ...interface{}) error {
	return &LineageError{Message: fmt.Sprintf(format, args...)}
}

var semverRe = regexp.MustCompile(`^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?`)

func versionKey(version string) ([3]int, bool) {
	m := semverRe.FindStringSubmatch(version)
	if m == nil {
		return [3]int{}, false
	}
	var key [3]int
	for i := 0; i < 3; i++ {
		if m[i+1] != "" {
			key[i], _ = strconv.Atoi(m[i+1])
		}
	}
	return key, true
}

// VersionIncreases reports whether current sorts strictly after previous.
// Numeric major.minor.patch prefixes compare numerically ("1.10.0" > "1.9.0");
// when either side is not semver-like the comparison falls back to a plain
// string comparison, which still rejects reuse of the same value.
func VersionIncreases(previous, current string) bool {
	p, pok := versionKey(previous)
	c, cok := versionKey(current)
	if pok && cok && p != c {
		for i := 0; i < 3; i++ {
			if c[i] != p[i] {
				return c[i] > p[i]
			}
		}
	}
	return current > previous
}

// LineageStore is the verifier-side latest_known_hash store (spec section
// 18.4) keyed by tool_id@domain.
//
// VerifyChain compares two signature documents the caller already holds. A
// verifier that wants protection against rollback and forks needs to remember
// the latest accepted skill_hash for each tool and insist that every new
// signature descends from it. Only feed it documents that VerifySkillOffline
// has already accepted, and only schemapin_version >= "1.4" documents: their
// skill_hash, previous_hash and schema_version are covered by the signature.
// Legacy 1.3 documents are refused.
type LineageStore struct {
	latest map[string]LineageRecord
}

// NewLineageStore creates an empty LineageStore.
func NewLineageStore() *LineageStore {
	return &LineageStore{latest: map[string]LineageRecord{}}
}

func lineageKey(toolID, domain string) string { return toolID + "@" + domain }

// Get returns the latest accepted record for toolID@domain.
func (s *LineageStore) Get(toolID, domain string) (LineageRecord, bool) {
	r, ok := s.latest[lineageKey(toolID, domain)]
	return r, ok
}

// Seed pre-seeds the latest accepted state (for example from a trusted manifest).
func (s *LineageStore) Seed(toolID, domain, skillHash, schemaVersion string) {
	s.latest[lineageKey(toolID, domain)] = LineageRecord{SkillHash: skillHash, SchemaVersion: schemaVersion}
}

// CheckAndAdvance checks sig against the lineage and advances on success.
// With requireChain a document for a known tool must carry previous_hash.
func (s *LineageStore) CheckAndAdvance(toolID, domain string, sig *SkillSignature, requireChain bool) (LineageResult, error) {
	if sig == nil {
		return "", lineageErr("signature document is nil")
	}
	if isLegacyVersion(sig.SchemapinVersion) {
		return "", lineageErr("legacy 1.3 signature documents carry an unsigned skill_hash and cannot anchor a lineage")
	}
	if sig.SkillHash == "" {
		return "", lineageErr("signature document has no skill_hash")
	}
	key := lineageKey(toolID, domain)
	record, ok := s.latest[key]
	if !ok {
		s.latest[key] = LineageRecord{SkillHash: sig.SkillHash, SchemaVersion: sig.SchemaVersion}
		return LineageFirstUse, nil
	}
	if record.SkillHash == sig.SkillHash {
		return LineageUnchanged, nil
	}
	if sig.PreviousHash == "" {
		if requireChain {
			return "", lineageErr("signature for %s has no previous_hash; expected a descendant of %s", key, record.SkillHash)
		}
	} else if sig.PreviousHash != record.SkillHash {
		return "", lineageErr("previous_hash %s does not match the latest accepted skill_hash %s for %s (fork or rollback)", sig.PreviousHash, record.SkillHash, key)
	}
	if sig.SchemaVersion != "" && record.SchemaVersion != "" && !VersionIncreases(record.SchemaVersion, sig.SchemaVersion) {
		return "", lineageErr("schema_version %q does not increase over %q for %s", sig.SchemaVersion, record.SchemaVersion, key)
	}
	s.latest[key] = LineageRecord{SkillHash: sig.SkillHash, SchemaVersion: sig.SchemaVersion}
	return LineageAdvanced, nil
}

// ToJSON serializes the store.
func (s *LineageStore) ToJSON() (string, error) {
	data, err := json.Marshal(s.latest)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// LineageStoreFromJSON deserializes a store.
func LineageStoreFromJSON(jsonStr string) (*LineageStore, error) {
	store := NewLineageStore()
	if err := json.Unmarshal([]byte(jsonStr), &store.latest); err != nil {
		return nil, err
	}
	if store.latest == nil {
		return nil, fmt.Errorf("lineage store JSON must be an object")
	}
	for key, rec := range store.latest {
		if rec.SkillHash == "" {
			return nil, fmt.Errorf("lineage store entry %q has no skill_hash", key)
		}
	}
	return store, nil
}
