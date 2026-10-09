package skill

import (
	"os"
	"path/filepath"
	"testing"
)

// FuzzLoadSignature asserts .schemapin.sig parsing never panics and that any
// document it accepts can be turned into a signing input or is rejected
// cleanly.
func FuzzLoadSignature(f *testing.F) {
	f.Add(`{"schemapin_version":"1.4","skill_name":"x","skill_hash":"sha256:00","signature":"","signed_at":"2026-01-01T00:00:00Z","domain":"example.com","signer_kid":"k","file_manifest":{"a":"sha256:00"}}`)
	f.Add(`{"canonicalization":""}`)
	f.Add(`[]`)
	f.Add(``)
	f.Fuzz(func(t *testing.T, doc string) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, SignatureFilename), []byte(doc), 0600); err != nil {
			t.Fatal(err)
		}
		sig, err := LoadSignature(dir)
		if err != nil {
			return
		}
		_, _ = SigningInput(sig)
	})
}
