package skill

import (
	"strings"
	"testing"

	"github.com/ThirdKeyAi/schemapin/go/pkg/crypto"
	"github.com/ThirdKeyAi/schemapin/go/pkg/dns"
	"github.com/ThirdKeyAi/schemapin/go/pkg/verification"
)

// TestVerifyWithDNSMatchPasses confirms that a matching DNS TXT record
// leaves the verification result unchanged from the offline path.
func TestVerifyWithDNSMatchPasses(t *testing.T) {
	privPEM, pubPEM := makeKeypair(t)
	dir := createSkillDir(t, map[string]string{
		"SKILL.md": "---\nname: dnsok\n---\n",
	})
	if _, err := SignSkill(dir, privPEM, "example.com", "", ""); err != nil {
		t.Fatal(err)
	}

	disc := makeDiscovery(pubPEM)
	disc.SchemaVersion = "1.4"

	km := crypto.NewKeyManager()
	fp, err := km.CalculateKeyFingerprintFromPEM(pubPEM)
	if err != nil {
		t.Fatal(err)
	}
	txt := &dns.DnsTxtRecord{
		Version:     "schemapin1",
		Fingerprint: strings.ToLower(fp),
	}

	result := VerifySkillOfflineWithDNS(dir, disc, nil, nil, nil, "dnsok", txt)
	if !result.Valid {
		t.Errorf("expected valid, got error: %s", result.ErrorMessage)
	}
}

// TestVerifyWithDNSMismatchFails confirms that a mismatched DNS TXT
// fingerprint converts a successful verification into a hard failure
// with ErrDomainMismatch.
func TestVerifyWithDNSMismatchFails(t *testing.T) {
	privPEM, pubPEM := makeKeypair(t)
	dir := createSkillDir(t, map[string]string{
		"SKILL.md": "---\nname: dnsbad\n---\n",
	})
	if _, err := SignSkill(dir, privPEM, "example.com", "", ""); err != nil {
		t.Fatal(err)
	}

	disc := makeDiscovery(pubPEM)
	disc.SchemaVersion = "1.4"

	txt := &dns.DnsTxtRecord{
		Version:     "schemapin1",
		Fingerprint: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
	}

	result := VerifySkillOfflineWithDNS(dir, disc, nil, nil, nil, "dnsbad", txt)
	if result.Valid {
		t.Error("expected verification to fail with DNS mismatch")
	}
	if result.ErrorCode != verification.ErrDomainMismatch {
		t.Errorf("expected ErrorCode %s, got %s", verification.ErrDomainMismatch, result.ErrorCode)
	}
}

// TestVerifyWithDNSNilIsNoOp confirms that passing a nil DNS TXT record
// behaves identically to VerifySkillOffline.
func TestVerifyWithDNSNilIsNoOp(t *testing.T) {
	privPEM, pubPEM := makeKeypair(t)
	dir := createSkillDir(t, map[string]string{
		"SKILL.md": "---\nname: nodns\n---\n",
	})
	if _, err := SignSkill(dir, privPEM, "example.com", "", ""); err != nil {
		t.Fatal(err)
	}

	disc := makeDiscovery(pubPEM)
	disc.SchemaVersion = "1.4"

	result := VerifySkillOfflineWithDNS(dir, disc, nil, nil, nil, "nodns", nil)
	if !result.Valid {
		t.Errorf("expected valid (nil dnsTxt should be no-op), got error: %s", result.ErrorMessage)
	}
}

// TestVerifyWithDNSDoesNotPromoteFailure confirms that when the underlying
// verification fails (e.g. wrong key), the DNS check is skipped and the
// original failure is returned unchanged.
func TestVerifyWithDNSDoesNotPromoteFailure(t *testing.T) {
	privPEM, _ := makeKeypair(t)
	_, otherPubPEM := makeKeypair(t)

	dir := createSkillDir(t, map[string]string{
		"SKILL.md": "---\nname: badkey\n---\n",
	})
	if _, err := SignSkill(dir, privPEM, "example.com", "", ""); err != nil {
		t.Fatal(err)
	}

	disc := makeDiscovery(otherPubPEM)
	disc.SchemaVersion = "1.4"

	// Even with a matching DNS record (matching the wrong key), the
	// underlying signature failure should win and DNS should not be
	// consulted.
	km := crypto.NewKeyManager()
	fp, err := km.CalculateKeyFingerprintFromPEM(otherPubPEM)
	if err != nil {
		t.Fatal(err)
	}
	txt := &dns.DnsTxtRecord{
		Version:     "schemapin1",
		Fingerprint: strings.ToLower(fp),
	}

	result := VerifySkillOfflineWithDNS(dir, disc, nil, nil, nil, "badkey", txt)
	if result.Valid {
		t.Error("expected underlying verification to fail")
	}
	if result.ErrorCode != verification.ErrSignatureInvalid {
		t.Errorf("expected ErrorCode %s, got %s", verification.ErrSignatureInvalid, result.ErrorCode)
	}
}
