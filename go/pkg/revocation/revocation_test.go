package revocation

import (
	"encoding/json"
	"testing"
)

func TestBuildRevocationDocument(t *testing.T) {
	doc := BuildRevocationDocument("example.com")
	if doc.Domain != "example.com" {
		t.Errorf("expected domain example.com, got %s", doc.Domain)
	}
	if doc.SchemapinVersion != "1.2" {
		t.Errorf("expected version 1.2, got %s", doc.SchemapinVersion)
	}
	if len(doc.RevokedKeys) != 0 {
		t.Errorf("expected empty revoked keys, got %d", len(doc.RevokedKeys))
	}
	if doc.UpdatedAt == "" {
		t.Error("expected non-empty updated_at")
	}
}

func TestAddRevokedKey(t *testing.T) {
	doc := BuildRevocationDocument("example.com")
	AddRevokedKey(doc, "sha256:abc123", ReasonKeyCompromise)

	if len(doc.RevokedKeys) != 1 {
		t.Fatalf("expected 1 revoked key, got %d", len(doc.RevokedKeys))
	}
	if doc.RevokedKeys[0].Fingerprint != "sha256:abc123" {
		t.Errorf("expected fingerprint sha256:abc123, got %s", doc.RevokedKeys[0].Fingerprint)
	}
	if doc.RevokedKeys[0].Reason != ReasonKeyCompromise {
		t.Errorf("expected reason key_compromise, got %s", doc.RevokedKeys[0].Reason)
	}
}

func TestAddMultipleRevokedKeys(t *testing.T) {
	doc := BuildRevocationDocument("example.com")
	AddRevokedKey(doc, "sha256:aaa", ReasonKeyCompromise)
	AddRevokedKey(doc, "sha256:bbb", ReasonSuperseded)
	AddRevokedKey(doc, "sha256:ccc", ReasonCessationOfOperation)

	if len(doc.RevokedKeys) != 3 {
		t.Errorf("expected 3 revoked keys, got %d", len(doc.RevokedKeys))
	}
}

func TestCheckRevocationClean(t *testing.T) {
	doc := BuildRevocationDocument("example.com")
	AddRevokedKey(doc, "sha256:abc123", ReasonKeyCompromise)

	if err := CheckRevocation(doc, "sha256:other"); err != nil {
		t.Errorf("expected no error for clean key, got %v", err)
	}
}

func TestCheckRevocationRevoked(t *testing.T) {
	doc := BuildRevocationDocument("example.com")
	AddRevokedKey(doc, "sha256:abc123", ReasonKeyCompromise)

	err := CheckRevocation(doc, "sha256:abc123")
	if err == nil {
		t.Fatal("expected error for revoked key")
	}
}

func TestCheckRevocationEmptyDoc(t *testing.T) {
	doc := BuildRevocationDocument("example.com")
	if err := CheckRevocation(doc, "sha256:anything"); err != nil {
		t.Errorf("expected no error for empty doc, got %v", err)
	}
}

func TestCheckRevocationCombinedSimpleList(t *testing.T) {
	err := CheckRevocationCombined([]string{"sha256:abc123"}, nil, "sha256:abc123")
	if err == nil {
		t.Fatal("expected error for key in simple list")
	}
}

func TestCheckRevocationCombinedStandaloneDoc(t *testing.T) {
	doc := BuildRevocationDocument("example.com")
	AddRevokedKey(doc, "sha256:abc123", ReasonSuperseded)

	err := CheckRevocationCombined([]string{}, doc, "sha256:abc123")
	if err == nil {
		t.Fatal("expected error for key in standalone doc")
	}
}

func TestCheckRevocationCombinedClean(t *testing.T) {
	doc := BuildRevocationDocument("example.com")
	AddRevokedKey(doc, "sha256:other", ReasonSuperseded)

	err := CheckRevocationCombined([]string{"sha256:other2"}, doc, "sha256:clean")
	if err != nil {
		t.Errorf("expected no error for clean key, got %v", err)
	}
}

func TestCheckRevocationCombinedNilInputs(t *testing.T) {
	err := CheckRevocationCombined(nil, nil, "sha256:anything")
	if err != nil {
		t.Errorf("expected no error for nil inputs, got %v", err)
	}
}

func TestRevocationReasonValues(t *testing.T) {
	if ReasonKeyCompromise != "key_compromise" {
		t.Errorf("unexpected value: %s", ReasonKeyCompromise)
	}
	if ReasonSuperseded != "superseded" {
		t.Errorf("unexpected value: %s", ReasonSuperseded)
	}
	if ReasonCessationOfOperation != "cessation_of_operation" {
		t.Errorf("unexpected value: %s", ReasonCessationOfOperation)
	}
	if ReasonPrivilegeWithdrawn != "privilege_withdrawn" {
		t.Errorf("unexpected value: %s", ReasonPrivilegeWithdrawn)
	}
}

func TestDocumentJSONRoundtrip(t *testing.T) {
	doc := BuildRevocationDocument("example.com")
	AddRevokedKey(doc, "sha256:aaa", ReasonKeyCompromise)
	AddRevokedKey(doc, "sha256:bbb", ReasonSuperseded)

	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var restored RevocationDocument
	if err := json.Unmarshal(data, &restored); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if restored.Domain != "example.com" {
		t.Errorf("expected domain example.com, got %s", restored.Domain)
	}
	if len(restored.RevokedKeys) != 2 {
		t.Errorf("expected 2 revoked keys, got %d", len(restored.RevokedKeys))
	}
	if restored.RevokedKeys[0].Fingerprint != "sha256:aaa" {
		t.Errorf("expected fingerprint sha256:aaa, got %s", restored.RevokedKeys[0].Fingerprint)
	}
	if restored.RevokedKeys[1].Reason != ReasonSuperseded {
		t.Errorf("expected reason superseded, got %s", restored.RevokedKeys[1].Reason)
	}
}
