// Package core provides schema canonicalization and hashing functionality for SchemaPin.
package core

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sort"
)

// SchemaPinCore provides schema canonicalization and hashing
type SchemaPinCore struct{}

// NewSchemaPinCore creates a new SchemaPinCore instance
func NewSchemaPinCore() *SchemaPinCore {
	return &SchemaPinCore{}
}

// CanonicalizeSchema converts a schema to its canonical string representation
func (s *SchemaPinCore) CanonicalizeSchema(schema map[string]interface{}) (string, error) {
	// TODO: Implement JSON canonicalization with sorted keys
	// This should match the Python/JavaScript implementations exactly
	canonical, err := json.Marshal(s.sortKeys(schema))
	if err != nil {
		return "", fmt.Errorf("failed to canonicalize schema: %w", err)
	}
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

// sortKeys recursively sorts all keys in a map for canonical representation
func (s *SchemaPinCore) sortKeys(obj interface{}) interface{} {
	switch v := obj.(type) {
	case map[string]interface{}:
		sorted := make(map[string]interface{})
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			sorted[k] = s.sortKeys(v[k])
		}
		return sorted
	case []interface{}:
		for i, item := range v {
			v[i] = s.sortKeys(item)
		}
		return v
	default:
		return v
	}
}