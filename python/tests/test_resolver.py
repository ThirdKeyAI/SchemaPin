"""Tests for resolver implementations."""

import json
import os
import tempfile

from schemapin.bundle import SchemaPinTrustBundle, create_bundled_discovery
from schemapin.resolver import (
    ChainResolver,
    LocalFileResolver,
    TrustBundleResolver,
)
from schemapin.revocation import (
    RevocationReason,
    add_revoked_key,
    build_revocation_document,
)


def _make_bundle():
    """Create a sample trust bundle."""
    well_known = {
        "schema_version": "1.2",
        "developer_name": "Test Dev",
        "public_key_pem": "-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----",
    }
    doc = create_bundled_discovery("example.com", well_known)

    rev = build_revocation_document("example.com")
    add_revoked_key(rev, "sha256:old", RevocationReason.SUPERSEDED)

    return SchemaPinTrustBundle(
        schemapin_bundle_version="1.2",
        created_at="2026-01-01T00:00:00+00:00",
        documents=[doc],
        revocations=[rev],
    )


class TestTrustBundleResolver:
    """Tests for TrustBundleResolver."""

    def test_resolve_discovery_hit(self):
        """Resolve a known domain."""
        resolver = TrustBundleResolver(_make_bundle())
        disc = resolver.resolve_discovery("example.com")
        assert disc is not None
        assert disc["developer_name"] == "Test Dev"

    def test_resolve_discovery_miss(self):
        """Resolve an unknown domain returns None."""
        resolver = TrustBundleResolver(_make_bundle())
        assert resolver.resolve_discovery("unknown.com") is None

    def test_resolve_revocation(self):
        """Resolve revocation for a known domain."""
        resolver = TrustBundleResolver(_make_bundle())
        disc = resolver.resolve_discovery("example.com")
        rev = resolver.resolve_revocation("example.com", disc)
        assert rev is not None
        assert rev.domain == "example.com"
        assert len(rev.revoked_keys) == 1

    def test_from_json(self):
        """Create resolver from JSON string."""
        bundle = _make_bundle()
        json_str = json.dumps(bundle.to_dict())
        resolver = TrustBundleResolver.from_json(json_str)
        disc = resolver.resolve_discovery("example.com")
        assert disc is not None


class TestLocalFileResolver:
    """Tests for LocalFileResolver."""

    def test_resolve_discovery_from_file(self):
        """Read discovery from a local JSON file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            well_known = {
                "schema_version": "1.2",
                "developer_name": "File Dev",
                "public_key_pem": "PEM_DATA",
            }
            path = os.path.join(tmpdir, "example.com.json")
            with open(path, "w") as f:
                json.dump(well_known, f)

            resolver = LocalFileResolver(tmpdir)
            disc = resolver.resolve_discovery("example.com")
            assert disc is not None
            assert disc["developer_name"] == "File Dev"

    def test_resolve_discovery_missing(self):
        """Missing file returns None."""
        with tempfile.TemporaryDirectory() as tmpdir:
            resolver = LocalFileResolver(tmpdir)
            assert resolver.resolve_discovery("missing.com") is None

    def test_resolve_revocation_from_file(self):
        """Read revocation from a local JSON file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            rev = build_revocation_document("example.com")
            add_revoked_key(
                rev, "sha256:bad", RevocationReason.KEY_COMPROMISE
            )
            path = os.path.join(tmpdir, "example.com.revocations.json")
            with open(path, "w") as f:
                json.dump(rev.to_dict(), f)

            resolver = LocalFileResolver(".", revocation_dir=tmpdir)
            revocation = resolver.resolve_revocation("example.com", {})
            assert revocation is not None
            assert revocation.domain == "example.com"

    def test_resolve_revocation_no_dir(self):
        """No revocation dir returns None."""
        resolver = LocalFileResolver(".")
        assert resolver.resolve_revocation("example.com", {}) is None


class TestChainResolver:
    """Tests for ChainResolver."""

    def test_first_wins(self):
        """First resolver that returns a result wins."""
        bundle1 = SchemaPinTrustBundle(
            schemapin_bundle_version="1.2",
            created_at="2026-01-01T00:00:00+00:00",
            documents=[
                create_bundled_discovery(
                    "a.com",
                    {
                        "schema_version": "1.2",
                        "developer_name": "First",
                        "public_key_pem": "PEM1",
                    },
                )
            ],
        )
        bundle2 = SchemaPinTrustBundle(
            schemapin_bundle_version="1.2",
            created_at="2026-01-01T00:00:00+00:00",
            documents=[
                create_bundled_discovery(
                    "a.com",
                    {
                        "schema_version": "1.2",
                        "developer_name": "Second",
                        "public_key_pem": "PEM2",
                    },
                )
            ],
        )
        chain = ChainResolver(
            [TrustBundleResolver(bundle1), TrustBundleResolver(bundle2)]
        )
        disc = chain.resolve_discovery("a.com")
        assert disc["developer_name"] == "First"

    def test_fallthrough(self):
        """Falls through to second resolver if first misses."""
        bundle1 = SchemaPinTrustBundle(
            schemapin_bundle_version="1.2",
            created_at="2026-01-01T00:00:00+00:00",
            documents=[
                create_bundled_discovery(
                    "a.com",
                    {
                        "schema_version": "1.2",
                        "developer_name": "First",
                        "public_key_pem": "PEM1",
                    },
                )
            ],
        )
        bundle2 = SchemaPinTrustBundle(
            schemapin_bundle_version="1.2",
            created_at="2026-01-01T00:00:00+00:00",
            documents=[
                create_bundled_discovery(
                    "b.com",
                    {
                        "schema_version": "1.2",
                        "developer_name": "Second",
                        "public_key_pem": "PEM2",
                    },
                )
            ],
        )
        chain = ChainResolver(
            [TrustBundleResolver(bundle1), TrustBundleResolver(bundle2)]
        )
        disc = chain.resolve_discovery("b.com")
        assert disc is not None
        assert disc["developer_name"] == "Second"

    def test_all_miss(self):
        """Returns None if all resolvers miss."""
        bundle = SchemaPinTrustBundle(
            schemapin_bundle_version="1.2",
            created_at="2026-01-01T00:00:00+00:00",
        )
        chain = ChainResolver([TrustBundleResolver(bundle)])
        assert chain.resolve_discovery("missing.com") is None
