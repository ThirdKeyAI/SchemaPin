package core

import (
	"crypto/sha256"
	"encoding/json"
	"testing"
)

func TestSchemaPinCore_CanonicalizeSchema(t *testing.T) {
	core := NewSchemaPinCore()

	tests := []struct {
		name     string
		schema   map[string]interface{}
		expected string
		wantErr  bool
	}{
		{
			name: "simple schema",
			schema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"name": map[string]interface{}{
						"type": "string",
					},
				},
			},
			expected: `{"properties":{"name":{"type":"string"}},"type":"object"}`,
			wantErr:  false,
		},
		{
			name:     "empty schema",
			schema:   map[string]interface{}{},
			expected: `{}`,
			wantErr:  false,
		},
		{
			name: "complex nested schema",
			schema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"user": map[string]interface{}{
						"type": "object",
						"properties": map[string]interface{}{
							"name": map[string]interface{}{
								"type": "string",
							},
							"age": map[string]interface{}{
								"type": "integer",
							},
						},
					},
					"tags": map[string]interface{}{
						"type": "array",
						"items": map[string]interface{}{
							"type": "string",
						},
					},
				},
			},
			expected: `{"properties":{"tags":{"items":{"type":"string"},"type":"array"},"user":{"properties":{"age":{"type":"integer"},"name":{"type":"string"}},"type":"object"}},"type":"object"}`,
			wantErr:  false,
		},
		{
			name: "schema with various types",
			schema: map[string]interface{}{
				"string_field":  "test",
				"number_field":  42,
				"boolean_field": true,
				"null_field":    nil,
				"array_field":   []interface{}{"a", "b", "c"},
			},
			expected: `{"array_field":["a","b","c"],"boolean_field":true,"null_field":null,"number_field":42,"string_field":"test"}`,
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			canonical, err := core.CanonicalizeSchema(tt.schema)
			if (err != nil) != tt.wantErr {
				t.Errorf("CanonicalizeSchema() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if canonical != tt.expected {
					t.Errorf("CanonicalizeSchema() = %v, want %v", canonical, tt.expected)
				}
			}
		})
	}
}

func TestSchemaPinCore_HashCanonical(t *testing.T) {
	core := NewSchemaPinCore()

	tests := []struct {
		name      string
		canonical string
	}{
		{
			name:      "simple object",
			canonical: `{"type":"object"}`,
		},
		{
			name:      "empty object",
			canonical: `{}`,
		},
		{
			name:      "complex object",
			canonical: `{"properties":{"name":{"type":"string"}},"type":"object"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash := core.HashCanonical(tt.canonical)

			if len(hash) != 32 { // SHA-256 produces 32 bytes
				t.Errorf("HashCanonical() returned hash of length %d, expected 32", len(hash))
			}

			// Verify it matches Go's standard SHA-256
			expected := sha256.Sum256([]byte(tt.canonical))
			for i := 0; i < 32; i++ {
				if hash[i] != expected[i] {
					t.Errorf("HashCanonical() hash mismatch at byte %d", i)
					break
				}
			}
		})
	}
}

func TestSchemaPinCore_CanonicalizeAndHash(t *testing.T) {
	core := NewSchemaPinCore()

	schema := map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"name": map[string]interface{}{
				"type": "string",
			},
		},
	}

	hash, err := core.CanonicalizeAndHash(schema)
	if err != nil {
		t.Errorf("CanonicalizeAndHash() error = %v", err)
		return
	}

	if len(hash) != 32 {
		t.Errorf("CanonicalizeAndHash() returned hash of length %d, expected 32", len(hash))
	}

	// Verify it matches manual canonicalization + hashing
	canonical, err := core.CanonicalizeSchema(schema)
	if err != nil {
		t.Fatalf("Manual canonicalization failed: %v", err)
	}

	expectedHash := core.HashCanonical(canonical)
	for i := 0; i < 32; i++ {
		if hash[i] != expectedHash[i] {
			t.Errorf("CanonicalizeAndHash() hash mismatch at byte %d", i)
			break
		}
	}
}

func TestSchemaPinCore_ValidateSchema(t *testing.T) {
	core := NewSchemaPinCore()

	tests := []struct {
		name    string
		schema  map[string]interface{}
		wantErr bool
	}{
		{
			name: "valid simple schema",
			schema: map[string]interface{}{
				"type": "object",
			},
			wantErr: false,
		},
		{
			name:    "nil schema",
			schema:  nil,
			wantErr: true,
		},
		{
			name: "valid complex schema",
			schema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"name": map[string]interface{}{
						"type": "string",
					},
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := core.ValidateSchema(tt.schema)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateSchema() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestSchemaPinCore_NormalizeSchema(t *testing.T) {
	core := NewSchemaPinCore()

	tests := []struct {
		name    string
		schema  map[string]interface{}
		wantErr bool
	}{
		{
			name: "valid schema",
			schema: map[string]interface{}{
				"type": "object",
			},
			wantErr: false,
		},
		{
			name:    "nil schema",
			schema:  nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			normalized, err := core.NormalizeSchema(tt.schema)
			if (err != nil) != tt.wantErr {
				t.Errorf("NormalizeSchema() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && normalized == nil {
				t.Error("NormalizeSchema() returned nil for valid schema")
			}
		})
	}
}

// Test cross-compatibility with Python implementation
func TestCrossCompatibilityWithPython(t *testing.T) {
	core := NewSchemaPinCore()

	// Test cases that should produce identical results to Python
	testCases := []struct {
		name     string
		schema   map[string]interface{}
		expected string
	}{
		{
			name: "python_compatible_simple",
			schema: map[string]interface{}{
				"type": "object",
			},
			expected: `{"type":"object"}`,
		},
		{
			name: "python_compatible_with_properties",
			schema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"name": map[string]interface{}{
						"type": "string",
					},
				},
			},
			expected: `{"properties":{"name":{"type":"string"}},"type":"object"}`,
		},
		{
			name: "python_compatible_array",
			schema: map[string]interface{}{
				"type": "array",
				"items": map[string]interface{}{
					"type": "string",
				},
			},
			expected: `{"items":{"type":"string"},"type":"array"}`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			canonical, err := core.CanonicalizeSchema(tc.schema)
			if err != nil {
				t.Fatalf("CanonicalizeSchema() error = %v", err)
			}

			if canonical != tc.expected {
				t.Errorf("Cross-compatibility test failed.\nGot:      %s\nExpected: %s", canonical, tc.expected)
			}

			// Also verify that Go's standard library produces the same result
			goStandard, err := json.Marshal(tc.schema)
			if err != nil {
				t.Fatalf("json.Marshal() error = %v", err)
			}

			if string(goStandard) != tc.expected {
				t.Errorf("Go standard library mismatch.\nGot:      %s\nExpected: %s", string(goStandard), tc.expected)
			}
		})
	}
}

// Test deterministic hashing
func TestDeterministicHashing(t *testing.T) {
	core := NewSchemaPinCore()

	schema := map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"name": map[string]interface{}{
				"type": "string",
			},
			"age": map[string]interface{}{
				"type": "integer",
			},
		},
	}

	// Hash the same schema multiple times
	hash1, err := core.CanonicalizeAndHash(schema)
	if err != nil {
		t.Fatalf("First hash failed: %v", err)
	}

	hash2, err := core.CanonicalizeAndHash(schema)
	if err != nil {
		t.Fatalf("Second hash failed: %v", err)
	}

	// Hashes should be identical
	if len(hash1) != len(hash2) {
		t.Fatalf("Hash lengths differ: %d vs %d", len(hash1), len(hash2))
	}

	for i := 0; i < len(hash1); i++ {
		if hash1[i] != hash2[i] {
			t.Errorf("Hashes differ at byte %d: %02x vs %02x", i, hash1[i], hash2[i])
		}
	}
}

// Test key ordering consistency
func TestKeyOrderingConsistency(t *testing.T) {
	core := NewSchemaPinCore()

	// Create the same schema with keys in different orders
	schema1 := map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"name": map[string]interface{}{
				"type": "string",
			},
			"age": map[string]interface{}{
				"type": "integer",
			},
		},
	}

	schema2 := map[string]interface{}{
		"properties": map[string]interface{}{
			"age": map[string]interface{}{
				"type": "integer",
			},
			"name": map[string]interface{}{
				"type": "string",
			},
		},
		"type": "object",
	}

	canonical1, err := core.CanonicalizeSchema(schema1)
	if err != nil {
		t.Fatalf("First canonicalization failed: %v", err)
	}

	canonical2, err := core.CanonicalizeSchema(schema2)
	if err != nil {
		t.Fatalf("Second canonicalization failed: %v", err)
	}

	if canonical1 != canonical2 {
		t.Errorf("Key ordering inconsistency:\nSchema1: %s\nSchema2: %s", canonical1, canonical2)
	}
}
