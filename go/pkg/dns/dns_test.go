package dns

import (
	"strings"
	"testing"

	"github.com/ThirdKeyAi/schemapin/go/pkg/crypto"
	"github.com/ThirdKeyAi/schemapin/go/pkg/discovery"
)

// --- ParseTxtRecord tests ---

func TestParseFullRecord(t *testing.T) {
	r, err := ParseTxtRecord("v=schemapin1; kid=acme-2026-01; fp=sha256:abcd1234")
	if err != nil {
		t.Fatal(err)
	}
	if r.Version != "schemapin1" {
		t.Errorf("expected version 'schemapin1', got %q", r.Version)
	}
	if r.Kid != "acme-2026-01" {
		t.Errorf("expected kid 'acme-2026-01', got %q", r.Kid)
	}
	if r.Fingerprint != "sha256:abcd1234" {
		t.Errorf("expected fingerprint 'sha256:abcd1234', got %q", r.Fingerprint)
	}
}

func TestParseMinimalRecord(t *testing.T) {
	r, err := ParseTxtRecord("v=schemapin1;fp=sha256:abc")
	if err != nil {
		t.Fatal(err)
	}
	if r.Version != "schemapin1" {
		t.Errorf("expected version 'schemapin1', got %q", r.Version)
	}
	if r.Kid != "" {
		t.Errorf("expected empty kid, got %q", r.Kid)
	}
	if r.Fingerprint != "sha256:abc" {
		t.Errorf("expected fingerprint 'sha256:abc', got %q", r.Fingerprint)
	}
}

func TestParseLowercasesFingerprint(t *testing.T) {
	r, err := ParseTxtRecord("v=schemapin1; fp=SHA256:ABCDEF")
	if err != nil {
		t.Fatal(err)
	}
	if r.Fingerprint != "sha256:abcdef" {
		t.Errorf("expected fingerprint 'sha256:abcdef', got %q", r.Fingerprint)
	}
}

func TestParseToleratesWhitespaceAndOrder(t *testing.T) {
	r, err := ParseTxtRecord("  fp = sha256:beef ;  v = schemapin1  ")
	if err != nil {
		t.Fatal(err)
	}
	if r.Version != "schemapin1" {
		t.Errorf("expected version 'schemapin1', got %q", r.Version)
	}
	if r.Fingerprint != "sha256:beef" {
		t.Errorf("expected fingerprint 'sha256:beef', got %q", r.Fingerprint)
	}
}

func TestParseIgnoresUnknownFields(t *testing.T) {
	r, err := ParseTxtRecord("v=schemapin1; fp=sha256:abc; future=ignoreme; another=value")
	if err != nil {
		t.Fatal(err)
	}
	if r.Fingerprint != "sha256:abc" {
		t.Errorf("expected fingerprint 'sha256:abc', got %q", r.Fingerprint)
	}
}

func TestParseMissingVFails(t *testing.T) {
	_, err := ParseTxtRecord("fp=sha256:abc")
	if err == nil {
		t.Fatal("expected error for missing 'v' field")
	}
	if !strings.Contains(err.Error(), "'v'") {
		t.Errorf("error should mention 'v'; got: %v", err)
	}
}

func TestParseMissingFpFails(t *testing.T) {
	_, err := ParseTxtRecord("v=schemapin1")
	if err == nil {
		t.Fatal("expected error for missing 'fp' field")
	}
	if !strings.Contains(err.Error(), "'fp'") {
		t.Errorf("error should mention 'fp'; got: %v", err)
	}
}

func TestParseUnsupportedVersionFails(t *testing.T) {
	_, err := ParseTxtRecord("v=schemapin99; fp=sha256:abc")
	if err == nil {
		t.Fatal("expected error for unsupported version")
	}
	if !strings.Contains(err.Error(), "unsupported version") {
		t.Errorf("error should mention 'unsupported version'; got: %v", err)
	}
}

func TestParseFpWithoutSha256PrefixFails(t *testing.T) {
	_, err := ParseTxtRecord("v=schemapin1; fp=abc")
	if err == nil {
		t.Fatal("expected error for fp without sha256: prefix")
	}
	if !strings.Contains(err.Error(), "sha256:") {
		t.Errorf("error should mention 'sha256:' prefix; got: %v", err)
	}
}

func TestParseFieldWithoutEqualsFails(t *testing.T) {
	_, err := ParseTxtRecord("v=schemapin1; broken")
	if err == nil {
		t.Fatal("expected error for field without '='")
	}
	if !strings.Contains(err.Error(), "'='") {
		t.Errorf("error should mention '='; got: %v", err)
	}
}

// --- VerifyDnsMatch tests ---

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

func TestVerifyMatch(t *testing.T) {
	_, pubPEM := makeKeypair(t)
	km := crypto.NewKeyManager()
	fp, err := km.CalculateKeyFingerprintFromPEM(pubPEM)
	if err != nil {
		t.Fatal(err)
	}

	disc := &discovery.WellKnownResponse{
		SchemaVersion: "1.4",
		PublicKeyPEM:  pubPEM,
		DeveloperName: "Test Dev",
	}
	txt := &DnsTxtRecord{
		Version:     "schemapin1",
		Fingerprint: strings.ToLower(fp),
	}
	if err := VerifyDnsMatch(disc, txt); err != nil {
		t.Errorf("expected match, got error: %v", err)
	}
}

func TestVerifyMismatch(t *testing.T) {
	_, pubPEM := makeKeypair(t)
	disc := &discovery.WellKnownResponse{
		SchemaVersion: "1.4",
		PublicKeyPEM:  pubPEM,
		DeveloperName: "Test Dev",
	}
	txt := &DnsTxtRecord{
		Version:     "schemapin1",
		Fingerprint: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
	}
	err := VerifyDnsMatch(disc, txt)
	if err == nil {
		t.Fatal("expected mismatch error")
	}
	if !strings.Contains(err.Error(), "mismatch") {
		t.Errorf("error should mention 'mismatch'; got: %v", err)
	}
}

// --- TxtRecordName tests ---

func TestTxtRecordName(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"example.com", "_schemapin.example.com"},
		{"example.com.", "_schemapin.example.com"},
		{"sub.example.com", "_schemapin.sub.example.com"},
	}
	for _, c := range cases {
		got := TxtRecordName(c.in)
		if got != c.want {
			t.Errorf("TxtRecordName(%q): got %q, want %q", c.in, got, c.want)
		}
	}
}
