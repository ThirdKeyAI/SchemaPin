package skill

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ThirdKeyAi/schemapin/go/pkg/crypto"
	"github.com/ThirdKeyAi/schemapin/go/pkg/discovery"
	"github.com/ThirdKeyAi/schemapin/go/pkg/resolver"
	"github.com/ThirdKeyAi/schemapin/go/pkg/revocation"
	"github.com/ThirdKeyAi/schemapin/go/pkg/verification"
)

// signLegacyV13 writes a pre-1.4 root-hash-only signature document.
func signLegacyV13(t *testing.T, dir, privPEM, domain string) *SkillSignature {
	t.Helper()
	rootHash, manifest, err := CanonicalizeSkillV1(dir)
	if err != nil {
		t.Fatal(err)
	}
	km := crypto.NewKeyManager()
	priv, err := km.LoadPrivateKeyPEM(privPEM)
	if err != nil {
		t.Fatal(err)
	}
	pubPEM, _ := km.ExportPublicKeyPEM(&priv.PublicKey)
	kid, _ := km.CalculateKeyFingerprintFromPEM(pubPEM)
	sigB64, err := crypto.NewSignatureManager().SignHash(rootHash, priv)
	if err != nil {
		t.Fatal(err)
	}
	sig := &SkillSignature{
		SchemapinVersion: "1.3",
		SkillName:        "legacy",
		SkillHash:        "sha256:" + hex.EncodeToString(rootHash),
		Signature:        sigB64,
		SignedAt:         "2026-01-01T00:00:00Z",
		Domain:           domain,
		SignerKid:        kid,
		FileManifest:     manifest,
	}
	writeSig(t, dir, sig)
	return sig
}

func TestSignedDocumentMetadataTamperInvalidates(t *testing.T) {
	privPEM, pubPEM := makeKeypair(t)
	cases := []struct{ field, value string }{
		{"schema_version", "9.9.9"},
		{"previous_hash", "sha256:" + hex.EncodeToString(make([]byte, 32))},
		{"skill_name", "payments-tool"},
		{"domain", "good.example.com"},
		{"signer_kid", "sha256:" + hex.EncodeToString(make([]byte, 32))},
		{"signed_at", "2030-01-01T00:00:00Z"},
		{"canonicalization", "schemapin-v1"},
	}
	for _, c := range cases {
		dir := createSkillDir(t, map[string]string{"SKILL.md": "---\nname: s\n---\n"})
		sig, err := SignSkillWithOptions(dir, privPEM, "example.com", SignOptions{SchemaVersion: "1.0.0"})
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(sig)
		var doc map[string]interface{}
		_ = json.Unmarshal(raw, &doc)
		doc[c.field] = c.value
		out, _ := json.Marshal(doc)
		if err := os.WriteFile(filepath.Join(dir, SignatureFilename), out, 0600); err != nil {
			t.Fatal(err)
		}
		r := VerifySkillOffline(dir, makeDiscovery(pubPEM), nil, nil, nil, "")
		if r.Valid {
			t.Errorf("tampering %s must invalidate the signature", c.field)
		}
	}
}

func TestManifestTamperInvalidates(t *testing.T) {
	privPEM, pubPEM := makeKeypair(t)
	dir := createSkillDir(t, map[string]string{"SKILL.md": "# hi", "a.txt": "A"})
	sig, err := SignSkill(dir, privPEM, "example.com", "", "")
	if err != nil {
		t.Fatal(err)
	}
	sig.FileManifest["extra.txt"] = "sha256:" + hex.EncodeToString(make([]byte, 32))
	writeSig(t, dir, sig)
	if r := VerifySkillOffline(dir, makeDiscovery(pubPEM), nil, nil, nil, ""); r.Valid || r.ErrorCode != verification.ErrSignatureInvalid {
		t.Fatalf("manifest tamper must invalidate: %+v", r)
	}
}

func TestSkillHashIsVerified(t *testing.T) {
	privPEM, pubPEM := makeKeypair(t)
	dir := createSkillDir(t, map[string]string{"SKILL.md": "# hi"})
	sig, err := SignSkill(dir, privPEM, "example.com", "", "")
	if err != nil {
		t.Fatal(err)
	}
	root, _, _ := CanonicalizeSkill(dir)
	if sig.SkillHash != "sha256:"+hex.EncodeToString(root) {
		t.Fatalf("skill_hash must be hex(root): %s", sig.SkillHash)
	}
	// Lineage splice: another validly signed artifact's document on this dir.
	other := createSkillDir(t, map[string]string{"SKILL.md": "# other"})
	otherSig, err := SignSkill(other, privPEM, "example.com", "", "")
	if err != nil {
		t.Fatal(err)
	}
	writeSig(t, dir, otherSig)
	r := VerifySkillOffline(dir, makeDiscovery(pubPEM), nil, nil, nil, "")
	if r.Valid || r.ErrorCode != verification.ErrSignatureInvalid {
		t.Fatalf("spliced document must fail: %+v", r)
	}
}

func TestLegacyV13DocumentStillVerifiesWithWarning(t *testing.T) {
	privPEM, pubPEM := makeKeypair(t)
	dir := createSkillDir(t, map[string]string{"SKILL.md": "# hi", "sub/x.txt": "x"})
	sig := signLegacyV13(t, dir, privPEM, "example.com")
	r := VerifySkillOfflineWithOptions(dir, makeDiscovery(pubPEM), nil, nil, nil, VerifyOptions{Domain: "example.com"})
	if !r.Valid {
		t.Fatalf("legacy document must verify: %+v", r)
	}
	found := false
	for _, w := range r.Warnings {
		if w == verification.WarningLegacySignatureFormat {
			found = true
		}
	}
	if !found {
		t.Errorf("expected legacy warning, got %v", r.Warnings)
	}
	sig.SchemapinVersion = "1.4"
	writeSig(t, dir, sig)
	if r := VerifySkillOffline(dir, makeDiscovery(pubPEM), nil, nil, nil, ""); r.Valid {
		t.Fatal("legacy signature upgraded to 1.4 must fail")
	}
	if err := VerifyChain(&SkillSignature{SchemapinVersion: "1.4", PreviousHash: "sha256:aa"}, &SkillSignature{SchemapinVersion: "1.3", SkillHash: "sha256:aa"}); err == nil {
		t.Fatal("VerifyChain must reject legacy documents")
	}
}

func TestLoadSignatureRejectsEmptyCanonicalization(t *testing.T) {
	dir := t.TempDir()
	doc := `{"schemapin_version":"1.4","skill_name":"x","skill_hash":"sha256:00","signature":"","signed_at":"2026-01-01T00:00:00Z","canonicalization":"","domain":"example.com","signer_kid":"k","file_manifest":{}}`
	if err := os.WriteFile(filepath.Join(dir, SignatureFilename), []byte(doc), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSignature(dir); err == nil {
		t.Fatal("empty canonicalization must be rejected (SP-19)")
	}
}

type explodingResolver struct{ t *testing.T }

func (e explodingResolver) ResolveDiscovery(string) (*discovery.WellKnownResponse, error) {
	e.t.Fatal("network must not be touched on domain mismatch")
	return nil, nil
}

func (e explodingResolver) ResolveRevocation(string, *discovery.WellKnownResponse) (*revocation.RevocationDocument, error) {
	return nil, nil
}

var _ resolver.SchemaResolver = explodingResolver{}

func TestDomainBinding(t *testing.T) {
	privPEM, pubPEM := makeKeypair(t)
	dir := createSkillDir(t, map[string]string{"SKILL.md": "# hi"})
	if _, err := SignSkill(dir, privPEM, "evil.example.com", "", ""); err != nil {
		t.Fatal(err)
	}
	store := verification.NewKeyPinStore()
	r := VerifySkillOfflineWithOptions(dir, makeDiscovery(pubPEM), nil, nil, store, VerifyOptions{Domain: "good.example.com", ToolID: "calc"})
	if r.Valid || r.ErrorCode != verification.ErrDomainMismatch {
		t.Fatalf("expected DOMAIN_MISMATCH: %+v", r)
	}
	if store.GetPinned("calc", "good.example.com") != "" || store.GetPinned("calc", "evil.example.com") != "" {
		t.Fatal("nothing must be pinned on domain mismatch")
	}
	if r := VerifySkillWithResolver(dir, "good.example.com", explodingResolver{t}, nil, ""); r.ErrorCode != verification.ErrDomainMismatch {
		t.Fatalf("resolver path must bind the domain before I/O: %+v", r)
	}
	for _, bad := range []string{"../skills/evil/key", "localhost", "http://example.com", "10.0.0.1"} {
		r := VerifySkillOfflineWithOptions(dir, makeDiscovery(pubPEM), nil, nil, nil, VerifyOptions{Domain: bad})
		if r.Valid || r.ErrorCode != verification.ErrDomainInvalid {
			t.Errorf("%q: expected DOMAIN_INVALID, got %+v", bad, r)
		}
	}
	// Bound domain is reported normalized; unbound surfaces a warning.
	dir2 := createSkillDir(t, map[string]string{"SKILL.md": "# hi"})
	if _, err := SignSkill(dir2, privPEM, "Example.COM", "", ""); err != nil {
		t.Fatal(err)
	}
	r = VerifySkillOfflineWithOptions(dir2, makeDiscovery(pubPEM), nil, nil, nil, VerifyOptions{Domain: "example.com"})
	if !r.Valid || r.Domain != "example.com" {
		t.Fatalf("bound verification failed: %+v", r)
	}
	r = VerifySkillOffline(dir2, makeDiscovery(pubPEM), nil, nil, nil, "")
	if !r.Valid || len(r.Warnings) == 0 || r.Warnings[0] != verification.WarningDomainUnbound {
		t.Fatalf("expected domain_unbound warning: %+v", r)
	}
}

func TestPinAfterVerify(t *testing.T) {
	privPEM, pubPEM := makeKeypair(t)
	_, otherPub := makeKeypair(t)
	dir := createSkillDir(t, map[string]string{"SKILL.md": "# hi"})
	if _, err := SignSkill(dir, privPEM, "example.com", "", ""); err != nil {
		t.Fatal(err)
	}
	store := verification.NewKeyPinStore()
	opts := VerifyOptions{Domain: "example.com", ToolID: "t"}
	if r := VerifySkillOfflineWithOptions(dir, makeDiscovery(otherPub), nil, nil, store, opts); r.Valid || r.ErrorCode != verification.ErrSignatureInvalid {
		t.Fatalf("expected SIGNATURE_INVALID: %+v", r)
	}
	if store.GetPinned("t", "example.com") != "" {
		t.Fatal("a failed verification must not pin")
	}
	r := VerifySkillOfflineWithOptions(dir, makeDiscovery(pubPEM), nil, nil, store, opts)
	if !r.Valid || r.KeyPinning == nil || r.KeyPinning.Status != "first_use" || store.GetPinned("t", "example.com") == "" {
		t.Fatalf("expected first_use pin after success: %+v", r)
	}
	// Expired must not pin either.
	dir2 := createSkillDir(t, map[string]string{"SKILL.md": "# hi"})
	if _, err := SignSkillWithOptions(dir2, privPEM, "example.com", SignOptions{ExpiresIn: -24 * time.Hour}); err != nil {
		t.Fatal(err)
	}
	store2 := verification.NewKeyPinStore()
	if r := VerifySkillOfflineWithOptions(dir2, makeDiscovery(pubPEM), nil, nil, store2, opts); r.Valid || store2.GetPinned("t", "example.com") != "" {
		t.Fatalf("expired signature must not pin: %+v", r)
	}
}

func TestSymlinksRejected(t *testing.T) {
	privPEM, pubPEM := makeKeypair(t)
	base := t.TempDir()
	dir := filepath.Join(base, "skill")
	if err := os.MkdirAll(dir, 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte("# hi"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := SignSkill(dir, privPEM, "example.com", "", ""); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(base, "outside.txt"), []byte("unsigned"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(base, "outside.txt"), filepath.Join(dir, "helper.sh")); err != nil {
		t.Skip("symlinks not supported")
	}
	if _, _, err := CanonicalizeSkill(dir); !errors.Is(err, ErrSkillCanonicalization) {
		t.Fatalf("expected canonicalization error, got %v", err)
	}
	if r := VerifySkillOffline(dir, makeDiscovery(pubPEM), nil, nil, nil, ""); r.Valid || r.ErrorCode != verification.ErrSchemaCanonicalizationFailed {
		t.Fatalf("symlink added after signing must fail: %+v", r)
	}
	_ = os.Remove(filepath.Join(dir, "helper.sh"))
	if err := os.Mkdir(filepath.Join(base, "other"), 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(base, "other"), filepath.Join(dir, "examples")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := CanonicalizeSkill(dir); err == nil {
		t.Fatal("symlinked directory must be rejected")
	}
}

func TestPathContentBoundaryNotMalleable(t *testing.T) {
	a := createSkillDir(t, map[string]string{"run.sh.disabled": "\necho hi"})
	b := createSkillDir(t, map[string]string{"run.sh": ".disabled\necho hi"})
	ha, _, _ := CanonicalizeSkill(a)
	hb, _, _ := CanonicalizeSkill(b)
	if hex.EncodeToString(ha) == hex.EncodeToString(hb) {
		t.Fatal("v2 hashing must separate path and content")
	}
	la, _, _ := CanonicalizeSkillV1(a)
	lb, _, _ := CanonicalizeSkillV1(b)
	if hex.EncodeToString(la) != hex.EncodeToString(lb) {
		t.Fatal("legacy hashing is expected to collide on this re-split (documents the SP-13 defect)")
	}
	_ = sha256.New
}

func TestNestedSigFileIsContent(t *testing.T) {
	dir := createSkillDir(t, map[string]string{"SKILL.md": "# hi", "nested/.schemapin.sig": "{}"})
	_, manifest, err := CanonicalizeSkill(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := manifest["nested/.schemapin.sig"]; !ok {
		t.Error("nested .schemapin.sig must be hashed as content")
	}
	if _, ok := manifest[".schemapin.sig"]; ok {
		t.Error("top-level .schemapin.sig must be excluded")
	}
}
