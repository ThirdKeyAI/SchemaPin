package crypto

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/ThirdKeyAi/schemapin/go/pkg/core"
)

func fixtureRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 8; i++ {
		candidate := filepath.Join(dir, "tests", "cross-language")
		if st, err := os.Stat(candidate); err == nil && st.IsDir() {
			return candidate
		}
		dir = filepath.Dir(dir)
	}
	t.Fatal("could not locate tests/cross-language")
	return ""
}

type schemaSignatureVector struct {
	PublicKeyPEM              string                 `json:"public_key_pem"`
	KeyFingerprint            string                 `json:"key_fingerprint"`
	Schema                    map[string]interface{} `json:"schema"`
	Canonical                 string                 `json:"canonical"`
	SHA256                    string                 `json:"sha256"`
	Signature                 string                 `json:"signature"`
	SignatureWithTrailingByte string                 `json:"signature_with_trailing_byte"`
	TamperedSchema            map[string]interface{} `json:"tampered_schema"`
}

// TestCrossLanguageSchemaSignature proves SP-2: the Go SDK accepts a signature
// produced by another SDK (ECDSA over SHA-256 of the canonical digest) and
// rejects tampering and DER trailing bytes, like every other SDK.
func TestCrossLanguageSchemaSignature(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(fixtureRoot(t), "signatures", "schema-signature.json")) // #nosec G304
	if err != nil {
		t.Fatal(err)
	}
	var v schemaSignatureVector
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}

	c := core.NewSchemaPinCore()
	canonical, err := c.CanonicalizeSchema(v.Schema)
	if err != nil {
		t.Fatal(err)
	}
	if canonical != v.Canonical {
		t.Fatalf("canonical mismatch:\n got %q\nwant %q", canonical, v.Canonical)
	}
	digest := c.HashCanonical(canonical)
	if hex.EncodeToString(digest) != v.SHA256 {
		t.Fatalf("digest mismatch")
	}

	km := NewKeyManager()
	pub, err := km.LoadPublicKeyPEM(v.PublicKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	if fp, _ := km.CalculateKeyFingerprint(pub); fp != v.KeyFingerprint {
		t.Fatalf("fingerprint mismatch: %s", fp)
	}

	sm := NewSignatureManager()
	if !sm.VerifySchemaSignature(digest, v.Signature, pub) {
		t.Fatal("fixed cross-language signature must verify in Go")
	}
	tampered, _ := c.CanonicalizeAndHash(v.TamperedSchema)
	if sm.VerifySchemaSignature(tampered, v.Signature, pub) {
		t.Fatal("tampered schema must not verify")
	}
	if sm.VerifySchemaSignature(digest, v.SignatureWithTrailingByte, pub) {
		t.Fatal("DER signature with trailing bytes must not verify (SP-19)")
	}
}

// TestNonP256KeysRejected proves SP-10 for Go.
func TestNonP256KeysRejected(t *testing.T) {
	km := NewKeyManager()
	for _, name := range []string{"reject-p384-public.pem", "reject-rsa2048-public.pem"} {
		pem, err := os.ReadFile(filepath.Join(fixtureRoot(t), "keys", name)) // #nosec G304
		if err != nil {
			t.Fatal(err)
		}
		if _, err := km.LoadPublicKeyPEM(string(pem)); err == nil {
			t.Errorf("%s: expected rejection", name)
		}
		if _, err := km.CalculateKeyFingerprintFromPEM(string(pem)); err == nil {
			t.Errorf("%s: fingerprint must fail", name)
		}
	}
}
