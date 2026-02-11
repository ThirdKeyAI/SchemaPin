"""Tests for trust bundles."""

import json

from schemapin.bundle import SchemaPinTrustBundle, create_bundled_discovery
from schemapin.revocation import (
    RevocationReason,
    add_revoked_key,
    build_revocation_document,
)


class TestTrustBundle:
    """Tests for SchemaPinTrustBundle."""

    def _make_bundle(self):
        """Create a sample trust bundle."""
        well_known = {
            "schema_version": "1.2",
            "developer_name": "Test Dev",
            "public_key_pem": "-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----",
        }
        doc = create_bundled_discovery("example.com", well_known)

        rev = build_revocation_document("example.com")
        add_revoked_key(rev, "sha256:old", RevocationReason.SUPERSEDED)

        bundle = SchemaPinTrustBundle(
            schemapin_bundle_version="1.2",
            created_at="2026-01-01T00:00:00+00:00",
            documents=[doc],
            revocations=[rev],
        )
        return bundle

    def test_create_bundle(self):
        """Create a trust bundle with documents and revocations."""
        bundle = self._make_bundle()
        assert bundle.schemapin_bundle_version == "1.2"
        assert len(bundle.documents) == 1
        assert len(bundle.revocations) == 1

    def test_find_discovery_hit(self):
        """Find a known domain's discovery document."""
        bundle = self._make_bundle()
        disc = bundle.find_discovery("example.com")
        assert disc is not None
        assert disc["developer_name"] == "Test Dev"
        assert disc["public_key_pem"].startswith("-----BEGIN PUBLIC KEY-----")
        # domain key should not be in the returned dict
        assert "domain" not in disc

    def test_find_discovery_miss(self):
        """Finding an unknown domain returns None."""
        bundle = self._make_bundle()
        assert bundle.find_discovery("unknown.com") is None

    def test_find_revocation_hit(self):
        """Find a known domain's revocation document."""
        bundle = self._make_bundle()
        rev = bundle.find_revocation("example.com")
        assert rev is not None
        assert rev.domain == "example.com"
        assert len(rev.revoked_keys) == 1

    def test_find_revocation_miss(self):
        """Finding an unknown domain's revocation returns None."""
        bundle = self._make_bundle()
        assert bundle.find_revocation("unknown.com") is None

    def test_serde_roundtrip(self):
        """Serialize and deserialize a bundle."""
        bundle = self._make_bundle()
        d = bundle.to_dict()
        json_str = json.dumps(d)
        restored = SchemaPinTrustBundle.from_json(json_str)

        assert restored.schemapin_bundle_version == "1.2"
        assert len(restored.documents) == 1
        assert len(restored.revocations) == 1
        assert restored.documents[0]["domain"] == "example.com"
        assert restored.revocations[0].domain == "example.com"

    def test_flattened_format(self):
        """Verify BundledDiscovery uses flattened format."""
        well_known = {
            "schema_version": "1.2",
            "developer_name": "Dev",
            "public_key_pem": "PEM",
            "contact": "dev@example.com",
        }
        entry = create_bundled_discovery("example.com", well_known)

        # All fields at the same level
        assert entry["domain"] == "example.com"
        assert entry["schema_version"] == "1.2"
        assert entry["developer_name"] == "Dev"
        assert entry["public_key_pem"] == "PEM"
        assert entry["contact"] == "dev@example.com"

    def test_from_dict(self):
        """from_dict correctly parses a bundle dictionary."""
        data = {
            "schemapin_bundle_version": "1.2",
            "created_at": "2026-01-01T00:00:00+00:00",
            "documents": [
                {
                    "domain": "a.com",
                    "schema_version": "1.2",
                    "developer_name": "A",
                    "public_key_pem": "PEM_A",
                }
            ],
            "revocations": [],
        }
        bundle = SchemaPinTrustBundle.from_dict(data)
        assert bundle.find_discovery("a.com") is not None
        assert bundle.find_discovery("a.com")["developer_name"] == "A"

    def test_empty_bundle(self):
        """An empty bundle returns None for all lookups."""
        bundle = SchemaPinTrustBundle(
            schemapin_bundle_version="1.2",
            created_at="2026-01-01T00:00:00+00:00",
        )
        assert bundle.find_discovery("example.com") is None
        assert bundle.find_revocation("example.com") is None
