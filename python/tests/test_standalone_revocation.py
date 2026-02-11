"""Tests for standalone revocation documents."""

import json

import pytest

from schemapin.revocation import (
    RevocationDocument,
    RevocationReason,
    RevokedKey,
    add_revoked_key,
    build_revocation_document,
    check_revocation,
    check_revocation_combined,
)


class TestRevocationDocument:
    """Tests for standalone revocation document operations."""

    def test_build_revocation_document(self):
        """Build an empty revocation document."""
        doc = build_revocation_document("example.com")
        assert doc.domain == "example.com"
        assert doc.schemapin_version == "1.2"
        assert doc.revoked_keys == []
        assert doc.updated_at is not None

    def test_add_revoked_key(self):
        """Add a revoked key entry."""
        doc = build_revocation_document("example.com")
        add_revoked_key(doc, "sha256:abc123", RevocationReason.KEY_COMPROMISE)
        assert len(doc.revoked_keys) == 1
        assert doc.revoked_keys[0].fingerprint == "sha256:abc123"
        assert doc.revoked_keys[0].reason == RevocationReason.KEY_COMPROMISE

    def test_add_multiple_revoked_keys(self):
        """Add multiple revoked keys."""
        doc = build_revocation_document("example.com")
        add_revoked_key(doc, "sha256:aaa", RevocationReason.KEY_COMPROMISE)
        add_revoked_key(doc, "sha256:bbb", RevocationReason.SUPERSEDED)
        add_revoked_key(
            doc, "sha256:ccc", RevocationReason.CESSATION_OF_OPERATION
        )
        assert len(doc.revoked_keys) == 3

    def test_check_revocation_clean(self):
        """Check a non-revoked fingerprint does not raise."""
        doc = build_revocation_document("example.com")
        add_revoked_key(doc, "sha256:abc123", RevocationReason.KEY_COMPROMISE)
        # Should not raise
        check_revocation(doc, "sha256:other")

    def test_check_revocation_revoked(self):
        """Check a revoked fingerprint raises ValueError."""
        doc = build_revocation_document("example.com")
        add_revoked_key(doc, "sha256:abc123", RevocationReason.KEY_COMPROMISE)
        with pytest.raises(ValueError, match="revoked"):
            check_revocation(doc, "sha256:abc123")

    def test_check_revocation_empty_doc(self):
        """Check against an empty document does not raise."""
        doc = build_revocation_document("example.com")
        check_revocation(doc, "sha256:anything")

    def test_check_revocation_combined_simple_list(self):
        """Combined check catches revocation in simple list."""
        with pytest.raises(ValueError, match="simple revocation list"):
            check_revocation_combined(
                ["sha256:abc123"], None, "sha256:abc123"
            )

    def test_check_revocation_combined_standalone_doc(self):
        """Combined check catches revocation in standalone doc."""
        doc = build_revocation_document("example.com")
        add_revoked_key(doc, "sha256:abc123", RevocationReason.SUPERSEDED)
        with pytest.raises(ValueError, match="revoked"):
            check_revocation_combined([], doc, "sha256:abc123")

    def test_check_revocation_combined_clean(self):
        """Combined check passes for non-revoked key."""
        doc = build_revocation_document("example.com")
        add_revoked_key(doc, "sha256:other", RevocationReason.SUPERSEDED)
        check_revocation_combined(["sha256:other2"], doc, "sha256:clean")

    def test_check_revocation_combined_none_inputs(self):
        """Combined check handles None inputs gracefully."""
        check_revocation_combined(None, None, "sha256:anything")

    def test_revocation_reason_values(self):
        """Verify all revocation reason values."""
        assert RevocationReason.KEY_COMPROMISE.value == "key_compromise"
        assert RevocationReason.SUPERSEDED.value == "superseded"
        assert (
            RevocationReason.CESSATION_OF_OPERATION.value
            == "cessation_of_operation"
        )
        assert (
            RevocationReason.PRIVILEGE_WITHDRAWN.value == "privilege_withdrawn"
        )


class TestRevocationSerialization:
    """Tests for revocation document serialization."""

    def test_revoked_key_roundtrip(self):
        """RevokedKey serializes and deserializes correctly."""
        key = RevokedKey(
            fingerprint="sha256:abc123",
            revoked_at="2026-01-01T00:00:00+00:00",
            reason=RevocationReason.KEY_COMPROMISE,
        )
        d = key.to_dict()
        restored = RevokedKey.from_dict(d)
        assert restored.fingerprint == key.fingerprint
        assert restored.revoked_at == key.revoked_at
        assert restored.reason == key.reason

    def test_document_roundtrip(self):
        """RevocationDocument serializes and deserializes correctly."""
        doc = build_revocation_document("example.com")
        add_revoked_key(doc, "sha256:aaa", RevocationReason.KEY_COMPROMISE)
        add_revoked_key(doc, "sha256:bbb", RevocationReason.SUPERSEDED)

        d = doc.to_dict()
        json_str = json.dumps(d)
        restored = RevocationDocument.from_dict(json.loads(json_str))

        assert restored.domain == doc.domain
        assert restored.schemapin_version == doc.schemapin_version
        assert len(restored.revoked_keys) == 2
        assert restored.revoked_keys[0].fingerprint == "sha256:aaa"
        assert restored.revoked_keys[1].reason == RevocationReason.SUPERSEDED

    def test_document_json_structure(self):
        """Verify the JSON structure matches the spec."""
        doc = build_revocation_document("example.com")
        add_revoked_key(
            doc, "sha256:abc", RevocationReason.PRIVILEGE_WITHDRAWN
        )
        d = doc.to_dict()

        assert "schemapin_version" in d
        assert "domain" in d
        assert "updated_at" in d
        assert "revoked_keys" in d
        assert len(d["revoked_keys"]) == 1
        rk = d["revoked_keys"][0]
        assert rk["reason"] == "privilege_withdrawn"
