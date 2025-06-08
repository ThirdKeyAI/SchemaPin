package crypto

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/ThirdKeyAi/schemapin/go/pkg/core"
)

// TestCrossCompatibilityWithPython tests that Go implementation produces
// identical results to Python implementation for key operations
func TestCrossCompatibilityWithPython(t *testing.T) {
	km := NewKeyManager()
	sm := NewSignatureManager()
	schemaPinCore := core.NewSchemaPinCore()

	// Test schema canonicalization matches Python exactly
	testSchema := map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"name": map[string]interface{}{
				"type": "string",
			},
			"age": map[string]interface{}{
				"type": "integer",
			},
		},
		"required": []interface{}{"name"},
	}

	canonical, err := schemaPinCore.CanonicalizeSchema(testSchema)
	if err != nil {
		t.Fatalf("CanonicalizeSchema() error = %v", err)
	}

	// This should match Python's json.dumps(schema, ensure_ascii=False, separators=(',', ':'), sort_keys=True)
	expectedCanonical := `{"properties":{"age":{"type":"integer"},"name":{"type":"string"}},"required":["name"],"type":"object"}`
	if canonical != expectedCanonical {
		t.Errorf("Canonical form mismatch.\nGot:      %s\nExpected: %s", canonical, expectedCanonical)
	}

	// Test hash calculation
	hash := schemaPinCore.HashCanonical(canonical)
	expectedHash := sha256.Sum256([]byte(canonical))

	for i := 0; i < 32; i++ {
		if hash[i] != expectedHash[i] {
			t.Errorf("Hash mismatch at byte %d: got %02x, expected %02x", i, hash[i], expectedHash[i])
		}
	}

	// Test key generation and PEM format
	privateKey, err := km.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair() error = %v", err)
	}

	publicKey := &privateKey.PublicKey

	// Test PEM export format matches Python
	privatePEM, err := km.ExportPrivateKeyPEM(privateKey)
	if err != nil {
		t.Fatalf("ExportPrivateKeyPEM() error = %v", err)
	}

	publicPEM, err := km.ExportPublicKeyPEM(publicKey)
	if err != nil {
		t.Fatalf("ExportPublicKeyPEM() error = %v", err)
	}

	// Verify PEM format matches Python's expectations
	if !strings.HasPrefix(privatePEM, "-----BEGIN PRIVATE KEY-----") {
		t.Error("Private key PEM should use PKCS#8 format (BEGIN PRIVATE KEY)")
	}

	if !strings.HasPrefix(publicPEM, "-----BEGIN PUBLIC KEY-----") {
		t.Error("Public key PEM should use standard format (BEGIN PUBLIC KEY)")
	}

	// Test fingerprint format matches Python
	fingerprint, err := km.CalculateKeyFingerprint(publicKey)
	if err != nil {
		t.Fatalf("CalculateKeyFingerprint() error = %v", err)
	}

	if !strings.HasPrefix(fingerprint, "sha256:") {
		t.Error("Fingerprint should start with 'sha256:'")
	}

	// Test signature format is compatible
	testHash := []byte("test_hash_32_bytes_exactly_here!")
	signature, err := sm.SignHash(testHash, privateKey)
	if err != nil {
		t.Fatalf("SignHash() error = %v", err)
	}

	// Signature should be base64 encoded
	_, err = base64.StdEncoding.DecodeString(signature)
	if err != nil {
		t.Errorf("Signature should be valid base64: %v", err)
	}

	// Verify signature
	if !sm.VerifySignature(testHash, signature, publicKey) {
		t.Error("Signature verification failed")
	}

	// Test that we can load keys exported by this implementation
	loadedPrivate, err := km.LoadPrivateKeyPEM(privatePEM)
	if err != nil {
		t.Fatalf("LoadPrivateKeyPEM() error = %v", err)
	}

	loadedPublic, err := km.LoadPublicKeyPEM(publicPEM)
	if err != nil {
		t.Fatalf("LoadPublicKeyPEM() error = %v", err)
	}

	// Test that loaded keys work for signing/verification
	signature2, err := sm.SignHash(testHash, loadedPrivate)
	if err != nil {
		t.Fatalf("SignHash() with loaded key error = %v", err)
	}

	if !sm.VerifySignature(testHash, signature2, loadedPublic) {
		t.Error("Signature verification with loaded keys failed")
	}
}

// TestKnownTestVectors tests against known good values that should be
// identical across Python, JavaScript, and Go implementations
func TestKnownTestVectors(t *testing.T) {
	schemaPinCore := core.NewSchemaPinCore()

	// Known test vectors that should produce identical results
	testVectors := []struct {
		name     string
		schema   map[string]interface{}
		expected string
	}{
		{
			name:     "empty_object",
			schema:   map[string]interface{}{},
			expected: `{}`,
		},
		{
			name: "simple_type",
			schema: map[string]interface{}{
				"type": "string",
			},
			expected: `{"type":"string"}`,
		},
		{
			name: "object_with_properties",
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
			name: "array_type",
			schema: map[string]interface{}{
				"type": "array",
				"items": map[string]interface{}{
					"type": "string",
				},
			},
			expected: `{"items":{"type":"string"},"type":"array"}`,
		},
		{
			name: "complex_nested",
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
								"type":    "integer",
								"minimum": 0,
							},
						},
						"required": []interface{}{"name"},
					},
					"tags": map[string]interface{}{
						"type": "array",
						"items": map[string]interface{}{
							"type": "string",
						},
					},
				},
				"required": []interface{}{"user"},
			},
			expected: `{"properties":{"tags":{"items":{"type":"string"},"type":"array"},"user":{"properties":{"age":{"minimum":0,"type":"integer"},"name":{"type":"string"}},"required":["name"],"type":"object"}},"required":["user"],"type":"object"}`,
		},
	}

	for _, tv := range testVectors {
		t.Run(tv.name, func(t *testing.T) {
			canonical, err := schemaPinCore.CanonicalizeSchema(tv.schema)
			if err != nil {
				t.Fatalf("CanonicalizeSchema() error = %v", err)
			}

			if canonical != tv.expected {
				t.Errorf("Test vector %s failed.\nGot:      %s\nExpected: %s", tv.name, canonical, tv.expected)
			}

			// Also verify hash is deterministic
			hash1 := schemaPinCore.HashCanonical(canonical)
			hash2 := schemaPinCore.HashCanonical(canonical)

			for i := 0; i < len(hash1); i++ {
				if hash1[i] != hash2[i] {
					t.Errorf("Hash not deterministic for test vector %s", tv.name)
					break
				}
			}
		})
	}
}

// TestEdgeCases tests edge cases that might cause cross-compatibility issues
func TestEdgeCases(t *testing.T) {
	schemaPinCore := core.NewSchemaPinCore()

	edgeCases := []struct {
		name   string
		schema map[string]interface{}
	}{
		{
			name: "unicode_strings",
			schema: map[string]interface{}{
				"description": "Test with unicode: 你好世界 🌍",
				"type":        "string",
			},
		},
		{
			name: "special_characters",
			schema: map[string]interface{}{
				"pattern": "^[a-zA-Z0-9_\\-\\.]+$",
				"type":    "string",
			},
		},
		{
			name: "numbers_and_booleans",
			schema: map[string]interface{}{
				"minimum":          0,
				"maximum":          100.5,
				"exclusiveMinimum": true,
				"exclusiveMaximum": false,
				"type":             "number",
			},
		},
		{
			name: "null_values",
			schema: map[string]interface{}{
				"default": nil,
				"type":    "null",
			},
		},
	}

	for _, ec := range edgeCases {
		t.Run(ec.name, func(t *testing.T) {
			canonical, err := schemaPinCore.CanonicalizeSchema(ec.schema)
			if err != nil {
				t.Fatalf("CanonicalizeSchema() error = %v", err)
			}

			// Should be able to hash without issues
			hash := schemaPinCore.HashCanonical(canonical)
			if len(hash) != 32 {
				t.Errorf("Hash should be 32 bytes, got %d", len(hash))
			}

			// Should be deterministic
			hash2 := schemaPinCore.HashCanonical(canonical)
			for i := 0; i < 32; i++ {
				if hash[i] != hash2[i] {
					t.Error("Hash not deterministic for edge case")
					break
				}
			}
		})
	}
}
