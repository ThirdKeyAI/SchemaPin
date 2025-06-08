package core

import (
	"testing"
)

func TestSchemaPinCore_CanonicalizeSchema(t *testing.T) {
	core := NewSchemaPinCore()

	tests := []struct {
		name    string
		schema  map[string]interface{}
		wantErr bool
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
			wantErr: false,
		},
		{
			name:    "empty schema",
			schema:  map[string]interface{}{},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			canonical, err := core.CanonicalizeSchema(tt.schema)
			if (err != nil) != tt.wantErr {
				t.Errorf("CanonicalizeSchema() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && canonical == "" {
				t.Errorf("CanonicalizeSchema() returned empty string")
			}
		})
	}
}

func TestSchemaPinCore_HashCanonical(t *testing.T) {
	core := NewSchemaPinCore()

	canonical := `{"type":"object"}`
	hash := core.HashCanonical(canonical)

	if len(hash) != 32 { // SHA-256 produces 32 bytes
		t.Errorf("HashCanonical() returned hash of length %d, expected 32", len(hash))
	}
}

func TestSchemaPinCore_CanonicalizeAndHash(t *testing.T) {
	core := NewSchemaPinCore()

	schema := map[string]interface{}{
		"type": "object",
	}

	hash, err := core.CanonicalizeAndHash(schema)
	if err != nil {
		t.Errorf("CanonicalizeAndHash() error = %v", err)
		return
	}

	if len(hash) != 32 {
		t.Errorf("CanonicalizeAndHash() returned hash of length %d, expected 32", len(hash))
	}
}
