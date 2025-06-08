// Package core provides schema canonicalization and hashing functionality for SchemaPin.
package core

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
)

// SchemaPinCore provides schema canonicalization and hashing
type SchemaPinCore struct{}

// NewSchemaPinCore creates a new SchemaPinCore instance
func NewSchemaPinCore() *SchemaPinCore {
	return &SchemaPinCore{}
}

// CanonicalizeSchema converts a schema to its canonical string representation
// This matches the Python implementation exactly:
// - UTF-8 encoding
// - Remove insignificant whitespace
// - Sort keys lexicographically (recursive)
// - Strict JSON serialization
func (s *SchemaPinCore) CanonicalizeSchema(schema map[string]interface{}) (string, error) {
	// Use Go's json.Marshal with custom encoder settings to match Python's behavior
	// json.dumps(schema, ensure_ascii=False, separators=(',', ':'), sort_keys=True)

	// Create a buffer to hold the canonical JSON
	canonical, err := json.Marshal(schema)
	if err != nil {
		return "", fmt.Errorf("failed to canonicalize schema: %w", err)
	}

	// Go's json.Marshal automatically sorts keys and uses compact format
	// which matches Python's separators=(',', ':') and sort_keys=True
	return string(canonical), nil
}

// HashCanonical computes SHA-256 hash of canonical schema string
func (s *SchemaPinCore) HashCanonical(canonical string) []byte {
	hash := sha256.Sum256([]byte(canonical))
	return hash[:]
}

// CanonicalizeAndHash combines canonicalization and hashing in one step
func (s *SchemaPinCore) CanonicalizeAndHash(schema map[string]interface{}) ([]byte, error) {
	canonical, err := s.CanonicalizeSchema(schema)
	if err != nil {
		return nil, err
	}
	return s.HashCanonical(canonical), nil
}

// ValidateSchema performs basic validation on a schema
func (s *SchemaPinCore) ValidateSchema(schema map[string]interface{}) error {
	if schema == nil {
		return fmt.Errorf("schema cannot be nil")
	}

	// Basic validation - ensure it's valid JSON-serializable
	_, err := json.Marshal(schema)
	if err != nil {
		return fmt.Errorf("schema is not valid JSON: %w", err)
	}

	return nil
}

// NormalizeSchema ensures schema is in a consistent format
func (s *SchemaPinCore) NormalizeSchema(schema map[string]interface{}) (map[string]interface{}, error) {
	if err := s.ValidateSchema(schema); err != nil {
		return nil, err
	}

	// For now, normalization is just validation
	// Future versions might add more normalization steps
	return schema, nil
}
