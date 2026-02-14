package skill

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/ThirdKeyAi/schemapin/go/pkg/bundle"
	"github.com/ThirdKeyAi/schemapin/go/pkg/crypto"
	"github.com/ThirdKeyAi/schemapin/go/pkg/discovery"
	"github.com/ThirdKeyAi/schemapin/go/pkg/resolver"
	"github.com/ThirdKeyAi/schemapin/go/pkg/verification"
)

// --- Test helpers ---

func makeKeypair(t *testing.T) (string, string) {
	t.Helper()
	km := crypto.NewKeyManager()
	priv, err := km.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	privPEM, err := km.ExportPrivateKeyPEM(priv)
	if err != nil {
		t.Fatal(err)
	}
	pubPEM, err := km.ExportPublicKeyPEM(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return privPEM, pubPEM
}

func createSkillDir(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for relPath, content := range files {
		full := filepath.Join(dir, filepath.FromSlash(relPath))
		if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func makeDiscovery(pubPEM string) *discovery.WellKnownResponse {
	return &discovery.WellKnownResponse{
		SchemaVersion: "1.3",
		DeveloperName: "Test Dev",
		PublicKeyPEM:  pubPEM,
	}
}

// --- Canonicalization tests ---

func TestCanonicalizeSortedDeterministic(t *testing.T) {
	dir := createSkillDir(t, map[string]string{
		"b.txt": "bravo",
		"a.txt": "alpha",
		"c.txt": "charlie",
	})

	hash1, manifest1, err := CanonicalizeSkill(dir)
	if err != nil {
		t.Fatal(err)
	}
	hash2, manifest2, err := CanonicalizeSkill(dir)
	if err != nil {
		t.Fatal(err)
	}

	if string(hash1) != string(hash2) {
		t.Error("root hash is not deterministic")
	}
	if len(manifest1) != len(manifest2) {
		t.Error("manifests differ in length")
	}
	for k, v := range manifest1 {
		if manifest2[k] != v {
			t.Errorf("manifest mismatch for %s: %s vs %s", k, v, manifest2[k])
		}
	}
}

func TestCanonicalizeSkipSigFile(t *testing.T) {
	dir := createSkillDir(t, map[string]string{
		"main.py":       "print('hello')",
		".schemapin.sig": `{"signature":"old"}`,
	})

	_, manifest, err := CanonicalizeSkill(dir)
	if err != nil {
		t.Fatal(err)
	}

	if _, ok := manifest[".schemapin.sig"]; ok {
		t.Error("manifest should not include .schemapin.sig")
	}
	if _, ok := manifest["main.py"]; !ok {
		t.Error("manifest should include main.py")
	}
}

func TestCanonicalizeNestedDirs(t *testing.T) {
	dir := createSkillDir(t, map[string]string{
		"src/lib.rs":    "fn main() {}",
		"src/util.rs":   "fn util() {}",
		"tests/test.rs": "fn test() {}",
		"README.md":     "# Hello",
	})

	_, manifest, err := CanonicalizeSkill(dir)
	if err != nil {
		t.Fatal(err)
	}

	expected := []string{"README.md", "src/lib.rs", "src/util.rs", "tests/test.rs"}
	if len(manifest) != len(expected) {
		t.Fatalf("expected %d files, got %d", len(expected), len(manifest))
	}
	for _, key := range expected {
		if _, ok := manifest[key]; !ok {
			t.Errorf("missing manifest key: %s", key)
		}
	}
}

func TestCanonicalizeForwardSlashes(t *testing.T) {
	dir := createSkillDir(t, map[string]string{
		"sub/deep/file.txt": "content",
	})

	_, manifest, err := CanonicalizeSkill(dir)
	if err != nil {
		t.Fatal(err)
	}

	if _, ok := manifest["sub/deep/file.txt"]; !ok {
		t.Error("expected forward-slash path sub/deep/file.txt in manifest")
	}
}

func TestCanonicalizeEmptyDir(t *testing.T) {
	dir := t.TempDir()

	_, _, err := CanonicalizeSkill(dir)
	if err == nil {
		t.Error("expected error for empty directory")
	}
}

func TestCanonicalizeBinaryFiles(t *testing.T) {
	dir := t.TempDir()

	binaryContent := make([]byte, 256)
	for i := range binaryContent {
		binaryContent[i] = byte(i)
	}
	if err := os.WriteFile(filepath.Join(dir, "data.bin"), binaryContent, 0644); err != nil {
		t.Fatal(err)
	}

	hash, manifest, err := CanonicalizeSkill(dir)
	if err != nil {
		t.Fatal(err)
	}

	if len(hash) != 32 {
		t.Errorf("expected 32-byte hash, got %d", len(hash))
	}
	if _, ok := manifest["data.bin"]; !ok {
		t.Error("manifest should include data.bin")
	}
}

func TestCanonicalizeContentAffectsHash(t *testing.T) {
	dir1 := createSkillDir(t, map[string]string{
		"file.txt": "content_a",
	})
	dir2 := createSkillDir(t, map[string]string{
		"file.txt": "content_b",
	})

	hash1, _, err := CanonicalizeSkill(dir1)
	if err != nil {
		t.Fatal(err)
	}
	hash2, _, err := CanonicalizeSkill(dir2)
	if err != nil {
		t.Fatal(err)
	}

	if string(hash1) == string(hash2) {
		t.Error("different content should produce different root hashes")
	}
}

// --- Manifest tests ---

func TestManifestAllFilesIncluded(t *testing.T) {
	dir := createSkillDir(t, map[string]string{
		"a.txt": "aaa",
		"b.txt": "bbb",
		"c.txt": "ccc",
	})

	_, manifest, err := CanonicalizeSkill(dir)
	if err != nil {
		t.Fatal(err)
	}

	if len(manifest) != 3 {
		t.Errorf("expected 3 manifest entries, got %d", len(manifest))
	}
}

func TestManifestSha256Format(t *testing.T) {
	dir := createSkillDir(t, map[string]string{
		"file.txt": "hello",
	})

	_, manifest, err := CanonicalizeSkill(dir)
	if err != nil {
		t.Fatal(err)
	}

	val, ok := manifest["file.txt"]
	if !ok {
		t.Fatal("missing file.txt in manifest")
	}
	if len(val) < 8 || val[:7] != "sha256:" {
		t.Errorf("manifest value should start with 'sha256:', got %s", val)
	}
	hexPart := val[7:]
	if len(hexPart) != 64 {
		t.Errorf("expected 64-char hex digest, got %d chars", len(hexPart))
	}
}

func TestManifestExcludesSigFile(t *testing.T) {
	dir := createSkillDir(t, map[string]string{
		"main.py":        "code",
		".schemapin.sig": "sig",
	})

	_, manifest, err := CanonicalizeSkill(dir)
	if err != nil {
		t.Fatal(err)
	}

	if _, ok := manifest[".schemapin.sig"]; ok {
		t.Error("manifest should exclude .schemapin.sig")
	}
}

// --- ParseSkillName tests ---

func TestParseSkillNameFrontmatter(t *testing.T) {
	dir := createSkillDir(t, map[string]string{
		"SKILL.md": "---\nname: My Cool Skill\nversion: 1.0\n---\n# Hello\n",
	})

	name := ParseSkillName(dir)
	if name != "My Cool Skill" {
		t.Errorf("expected 'My Cool Skill', got %q", name)
	}
}

func TestParseSkillNameQuoted(t *testing.T) {
	dir := createSkillDir(t, map[string]string{
		"SKILL.md": "---\nname: \"Quoted Skill\"\n---\n# Body\n",
	})

	name := ParseSkillName(dir)
	if name != "Quoted Skill" {
		t.Errorf("expected 'Quoted Skill', got %q", name)
	}
}

func TestParseSkillNameFallback(t *testing.T) {
	dir := createSkillDir(t, map[string]string{
		"main.py": "code",
	})

	name := ParseSkillName(dir)
	// Should fall back to directory basename
	if name == "" {
		t.Error("expected non-empty fallback name")
	}
}

// --- LoadSignature test ---

func TestLoadSignature(t *testing.T) {
	sig := SkillSignature{
		SchemapinVersion: "1.3",
		SkillName:        "test-skill",
		SkillHash:        "sha256:abc123",
		Signature:        "base64sig==",
		SignedAt:         "2024-01-01T00:00:00Z",
		Domain:           "example.com",
		SignerKid:        "sha256:kid123",
		FileManifest:     map[string]string{"a.txt": "sha256:aaa"},
	}
	data, err := json.MarshalIndent(sig, "", "  ")
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, SignatureFilename), data, 0644); err != nil {
		t.Fatal(err)
	}

	loaded, err := LoadSignature(dir)
	if err != nil {
		t.Fatal(err)
	}

	if loaded.SkillName != "test-skill" {
		t.Errorf("expected skill_name 'test-skill', got %q", loaded.SkillName)
	}
	if loaded.Domain != "example.com" {
		t.Errorf("expected domain 'example.com', got %q", loaded.Domain)
	}
	if loaded.SchemapinVersion != "1.3" {
		t.Errorf("expected version '1.3', got %q", loaded.SchemapinVersion)
	}
}

// --- Sign tests ---

func TestSignCreatesFile(t *testing.T) {
	privPEM, _ := makeKeypair(t)
	dir := createSkillDir(t, map[string]string{
		"main.py": "print('hello')",
	})

	sig, err := SignSkill(dir, privPEM, "example.com", "", "")
	if err != nil {
		t.Fatal(err)
	}

	if sig.Domain != "example.com" {
		t.Errorf("expected domain 'example.com', got %q", sig.Domain)
	}
	if sig.SchemapinVersion != "1.3" {
		t.Errorf("expected version '1.3', got %q", sig.SchemapinVersion)
	}

	// Check file was written
	sigPath := filepath.Join(dir, SignatureFilename)
	if _, err := os.Stat(sigPath); os.IsNotExist(err) {
		t.Error("expected .schemapin.sig file to be created")
	}
}

func TestSignRoundtrip(t *testing.T) {
	privPEM, pubPEM := makeKeypair(t)
	dir := createSkillDir(t, map[string]string{
		"main.py":  "print('hello')",
		"utils.py": "def helper(): pass",
	})

	sig, err := SignSkill(dir, privPEM, "example.com", "", "")
	if err != nil {
		t.Fatal(err)
	}

	disc := makeDiscovery(pubPEM)
	result := VerifySkillOffline(dir, disc, sig, nil, nil, "")

	if !result.Valid {
		t.Errorf("expected valid verification, got error: %s", result.ErrorMessage)
	}
}

// --- Verification failure tests ---

func TestWrongKeyFails(t *testing.T) {
	privPEM, _ := makeKeypair(t)
	_, otherPubPEM := makeKeypair(t) // different keypair

	dir := createSkillDir(t, map[string]string{
		"main.py": "print('hello')",
	})

	sig, err := SignSkill(dir, privPEM, "example.com", "", "")
	if err != nil {
		t.Fatal(err)
	}

	disc := makeDiscovery(otherPubPEM)
	result := VerifySkillOffline(dir, disc, sig, nil, nil, "")

	if result.Valid {
		t.Error("expected verification to fail with wrong key")
	}
	if result.ErrorCode != verification.ErrSignatureInvalid {
		t.Errorf("expected error code %s, got %s", verification.ErrSignatureInvalid, result.ErrorCode)
	}
}

func TestTamperedFileFails(t *testing.T) {
	privPEM, pubPEM := makeKeypair(t)
	dir := createSkillDir(t, map[string]string{
		"main.py": "original content",
	})

	sig, err := SignSkill(dir, privPEM, "example.com", "", "")
	if err != nil {
		t.Fatal(err)
	}

	// Tamper with file content
	if err := os.WriteFile(filepath.Join(dir, "main.py"), []byte("tampered content"), 0644); err != nil {
		t.Fatal(err)
	}

	disc := makeDiscovery(pubPEM)
	result := VerifySkillOffline(dir, disc, sig, nil, nil, "")

	if result.Valid {
		t.Error("expected verification to fail after tampering")
	}
	if result.ErrorCode != verification.ErrSignatureInvalid {
		t.Errorf("expected error code %s, got %s", verification.ErrSignatureInvalid, result.ErrorCode)
	}
}

func TestAddedFileFails(t *testing.T) {
	privPEM, pubPEM := makeKeypair(t)
	dir := createSkillDir(t, map[string]string{
		"main.py": "original",
	})

	sig, err := SignSkill(dir, privPEM, "example.com", "", "")
	if err != nil {
		t.Fatal(err)
	}

	// Add a new file
	if err := os.WriteFile(filepath.Join(dir, "extra.py"), []byte("extra"), 0644); err != nil {
		t.Fatal(err)
	}

	disc := makeDiscovery(pubPEM)
	result := VerifySkillOffline(dir, disc, sig, nil, nil, "")

	if result.Valid {
		t.Error("expected verification to fail with added file")
	}
}

func TestRemovedFileFails(t *testing.T) {
	privPEM, pubPEM := makeKeypair(t)
	dir := createSkillDir(t, map[string]string{
		"main.py":  "main",
		"utils.py": "utils",
	})

	sig, err := SignSkill(dir, privPEM, "example.com", "", "")
	if err != nil {
		t.Fatal(err)
	}

	// Remove a file
	if err := os.Remove(filepath.Join(dir, "utils.py")); err != nil {
		t.Fatal(err)
	}

	disc := makeDiscovery(pubPEM)
	result := VerifySkillOffline(dir, disc, sig, nil, nil, "")

	if result.Valid {
		t.Error("expected verification to fail with removed file")
	}
}

// --- Offline verification tests ---

func TestVerifyOfflineHappyPath(t *testing.T) {
	privPEM, pubPEM := makeKeypair(t)
	dir := createSkillDir(t, map[string]string{
		"main.py": "print('hello')",
	})

	sig, err := SignSkill(dir, privPEM, "example.com", "", "test-skill")
	if err != nil {
		t.Fatal(err)
	}

	disc := makeDiscovery(pubPEM)
	pinStore := verification.NewKeyPinStore()
	result := VerifySkillOffline(dir, disc, sig, nil, pinStore, "test-skill")

	if !result.Valid {
		t.Errorf("expected valid, got error: %s", result.ErrorMessage)
	}
	if result.Domain != "example.com" {
		t.Errorf("expected domain 'example.com', got %q", result.Domain)
	}
	if result.DeveloperName != "Test Dev" {
		t.Errorf("expected developer 'Test Dev', got %q", result.DeveloperName)
	}
	if result.KeyPinning == nil {
		t.Fatal("expected key pinning status")
	}
	if result.KeyPinning.Status != string(verification.PinFirstUse) {
		t.Errorf("expected pin status 'first_use', got %q", result.KeyPinning.Status)
	}

	// Second call should show "pinned"
	result2 := VerifySkillOffline(dir, disc, sig, nil, pinStore, "test-skill")
	if !result2.Valid {
		t.Errorf("expected valid on second call, got error: %s", result2.ErrorMessage)
	}
	if result2.KeyPinning == nil || result2.KeyPinning.Status != string(verification.PinPinned) {
		t.Error("expected pin status 'pinned' on second call")
	}
}

func TestVerifyOfflineRevokedKey(t *testing.T) {
	privPEM, pubPEM := makeKeypair(t)
	dir := createSkillDir(t, map[string]string{
		"main.py": "code",
	})

	sig, err := SignSkill(dir, privPEM, "example.com", "", "")
	if err != nil {
		t.Fatal(err)
	}

	// Compute the fingerprint for the key to revoke
	km := crypto.NewKeyManager()
	fingerprint, err := km.CalculateKeyFingerprintFromPEM(pubPEM)
	if err != nil {
		t.Fatal(err)
	}

	disc := makeDiscovery(pubPEM)
	disc.RevokedKeys = []string{fingerprint}

	result := VerifySkillOffline(dir, disc, sig, nil, nil, "")

	if result.Valid {
		t.Error("expected verification to fail with revoked key")
	}
	if result.ErrorCode != verification.ErrKeyRevoked {
		t.Errorf("expected error code %s, got %s", verification.ErrKeyRevoked, result.ErrorCode)
	}
}

func TestVerifyOfflinePinMismatch(t *testing.T) {
	privPEM1, pubPEM1 := makeKeypair(t)
	_, pubPEM2 := makeKeypair(t)

	dir := createSkillDir(t, map[string]string{
		"main.py": "code",
	})

	sig, err := SignSkill(dir, privPEM1, "example.com", "", "test-skill")
	if err != nil {
		t.Fatal(err)
	}

	// First, pin with key 1
	disc1 := makeDiscovery(pubPEM1)
	pinStore := verification.NewKeyPinStore()
	result := VerifySkillOffline(dir, disc1, sig, nil, pinStore, "test-skill")
	if !result.Valid {
		t.Fatalf("first verification should succeed: %s", result.ErrorMessage)
	}

	// Now try to verify with key 2 (different key, pin mismatch)
	disc2 := makeDiscovery(pubPEM2)
	result2 := VerifySkillOffline(dir, disc2, sig, nil, pinStore, "test-skill")

	if result2.Valid {
		t.Error("expected pin mismatch failure")
	}
	if result2.ErrorCode != verification.ErrKeyPinMismatch {
		t.Errorf("expected error code %s, got %s", verification.ErrKeyPinMismatch, result2.ErrorCode)
	}
}

func TestVerifyOfflineInvalidDiscovery(t *testing.T) {
	privPEM, _ := makeKeypair(t)
	dir := createSkillDir(t, map[string]string{
		"main.py": "code",
	})

	sig, err := SignSkill(dir, privPEM, "example.com", "", "")
	if err != nil {
		t.Fatal(err)
	}

	// Invalid discovery: no public key
	disc := &discovery.WellKnownResponse{
		SchemaVersion: "1.3",
		DeveloperName: "Test Dev",
	}

	result := VerifySkillOffline(dir, disc, sig, nil, nil, "")

	if result.Valid {
		t.Error("expected verification to fail with invalid discovery")
	}
	if result.ErrorCode != verification.ErrDiscoveryInvalid {
		t.Errorf("expected error code %s, got %s", verification.ErrDiscoveryInvalid, result.ErrorCode)
	}
}

func TestVerifyOfflineMissingSig(t *testing.T) {
	_, pubPEM := makeKeypair(t)
	dir := createSkillDir(t, map[string]string{
		"main.py": "code",
	})

	disc := makeDiscovery(pubPEM)
	result := VerifySkillOffline(dir, disc, nil, nil, nil, "")

	if result.Valid {
		t.Error("expected verification to fail with missing signature")
	}
	if result.ErrorCode != verification.ErrSignatureInvalid {
		t.Errorf("expected error code %s, got %s", verification.ErrSignatureInvalid, result.ErrorCode)
	}
}

// --- DetectTamperedFiles test ---

func TestDetectTamperedFiles(t *testing.T) {
	signed := map[string]string{
		"a.txt": "sha256:aaa",
		"b.txt": "sha256:bbb",
		"c.txt": "sha256:ccc",
	}
	current := map[string]string{
		"a.txt": "sha256:aaa",       // unchanged
		"b.txt": "sha256:modified",  // modified
		"d.txt": "sha256:ddd",       // added
	}

	result := DetectTamperedFiles(current, signed)

	if len(result.Modified) != 1 || result.Modified[0] != "b.txt" {
		t.Errorf("expected modified=[b.txt], got %v", result.Modified)
	}
	if len(result.Added) != 1 || result.Added[0] != "d.txt" {
		t.Errorf("expected added=[d.txt], got %v", result.Added)
	}
	if len(result.Removed) != 1 || result.Removed[0] != "c.txt" {
		t.Errorf("expected removed=[c.txt], got %v", result.Removed)
	}
}

// --- Resolver-based verification test ---

func TestVerifyWithResolver(t *testing.T) {
	privPEM, pubPEM := makeKeypair(t)
	dir := createSkillDir(t, map[string]string{
		"main.py": "print('hello')",
	})

	_, err := SignSkill(dir, privPEM, "example.com", "", "test-skill")
	if err != nil {
		t.Fatal(err)
	}

	// Build a trust bundle
	bundleJSON := buildTrustBundleJSON(t, pubPEM, "example.com")
	b, err := bundle.ParseTrustBundle(bundleJSON)
	if err != nil {
		t.Fatal(err)
	}
	r := resolver.NewTrustBundleResolver(b)

	pinStore := verification.NewKeyPinStore()
	result := VerifySkillWithResolver(dir, "example.com", r, pinStore, "test-skill")

	if !result.Valid {
		t.Errorf("expected valid verification via resolver, got error: %s", result.ErrorMessage)
	}
	if result.Domain != "example.com" {
		t.Errorf("expected domain 'example.com', got %q", result.Domain)
	}
}

// buildTrustBundleJSON creates a minimal trust bundle JSON for testing.
func buildTrustBundleJSON(t *testing.T, pubPEM, domain string) string {
	t.Helper()
	bundleData := map[string]interface{}{
		"schemapin_bundle_version": "1.2",
		"created_at":              "2024-01-01T00:00:00Z",
		"documents": []map[string]interface{}{
			{
				"domain":         domain,
				"schema_version": "1.3",
				"developer_name": "Test Dev",
				"public_key_pem": pubPEM,
			},
		},
		"revocations": []interface{}{},
	}
	data, err := json.Marshal(bundleData)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}
