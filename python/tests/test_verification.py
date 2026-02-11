"""Tests for offline and resolver-based verification."""



from schemapin.bundle import SchemaPinTrustBundle, create_bundled_discovery
from schemapin.core import SchemaPinCore
from schemapin.crypto import KeyManager, SignatureManager
from schemapin.resolver import TrustBundleResolver
from schemapin.revocation import (
    RevocationReason,
    add_revoked_key,
    build_revocation_document,
)
from schemapin.verification import (
    ErrorCode,
    KeyPinStore,
    verify_schema_offline,
    verify_schema_with_resolver,
)


def _make_key_and_sign(schema):
    """Generate a key pair, sign the schema, and return (pub_pem, sig, fingerprint)."""
    private_key, public_key = KeyManager.generate_keypair()
    pub_pem = KeyManager.export_public_key_pem(public_key)
    schema_hash = SchemaPinCore.canonicalize_and_hash(schema)
    sig = SignatureManager.sign_schema_hash(schema_hash, private_key)
    fp = KeyManager.calculate_key_fingerprint(public_key)
    return pub_pem, sig, fp


class TestKeyPinStore:
    """Tests for the in-memory key pin store."""

    def test_first_use(self):
        """First use of a tool@domain returns 'first_use'."""
        store = KeyPinStore()
        result = store.check_and_pin("tool1", "example.com", "sha256:aaa")
        assert result == "first_use"

    def test_pinned(self):
        """Same fingerprint returns 'pinned'."""
        store = KeyPinStore()
        store.check_and_pin("tool1", "example.com", "sha256:aaa")
        result = store.check_and_pin("tool1", "example.com", "sha256:aaa")
        assert result == "pinned"

    def test_changed(self):
        """Different fingerprint returns 'changed'."""
        store = KeyPinStore()
        store.check_and_pin("tool1", "example.com", "sha256:aaa")
        result = store.check_and_pin("tool1", "example.com", "sha256:bbb")
        assert result == "changed"

    def test_different_tools(self):
        """Different tool_ids are independent."""
        store = KeyPinStore()
        store.check_and_pin("tool1", "example.com", "sha256:aaa")
        result = store.check_and_pin("tool2", "example.com", "sha256:bbb")
        assert result == "first_use"

    def test_different_domains(self):
        """Different domains are independent."""
        store = KeyPinStore()
        store.check_and_pin("tool1", "a.com", "sha256:aaa")
        result = store.check_and_pin("tool1", "b.com", "sha256:bbb")
        assert result == "first_use"

    def test_serde_roundtrip(self):
        """Serialize and deserialize the pin store."""
        store = KeyPinStore()
        store.check_and_pin("tool1", "example.com", "sha256:aaa")
        store.check_and_pin("tool2", "other.com", "sha256:bbb")

        json_str = store.to_json()
        restored = KeyPinStore.from_json(json_str)

        assert restored.check_and_pin("tool1", "example.com", "sha256:aaa") == "pinned"
        assert restored.check_and_pin("tool2", "other.com", "sha256:bbb") == "pinned"

    def test_get_pinned(self):
        """Get a pinned fingerprint."""
        store = KeyPinStore()
        store.check_and_pin("tool1", "example.com", "sha256:aaa")
        assert store.get_pinned("tool1", "example.com") == "sha256:aaa"
        assert store.get_pinned("tool2", "example.com") is None


class TestVerifySchemaOffline:
    """Tests for verify_schema_offline."""

    def test_happy_path(self):
        """Valid schema, signature, and key passes verification."""
        schema = {"name": "test_tool", "description": "A test"}
        pub_pem, sig, fp = _make_key_and_sign(schema)

        discovery = {
            "schema_version": "1.2",
            "developer_name": "Test Dev",
            "public_key_pem": pub_pem,
        }
        store = KeyPinStore()
        result = verify_schema_offline(
            schema, sig, "example.com", "tool1", discovery, None, store
        )
        assert result.valid is True
        assert result.domain == "example.com"
        assert result.developer_name == "Test Dev"
        assert result.key_pinning is not None
        assert result.key_pinning.status == "first_use"
        assert result.error_code is None

    def test_pinned_on_second_call(self):
        """Second call with same key returns pinned status."""
        schema = {"name": "test_tool", "description": "A test"}
        pub_pem, sig, fp = _make_key_and_sign(schema)

        discovery = {
            "schema_version": "1.2",
            "developer_name": "Test Dev",
            "public_key_pem": pub_pem,
        }
        store = KeyPinStore()
        verify_schema_offline(
            schema, sig, "example.com", "tool1", discovery, None, store
        )
        result = verify_schema_offline(
            schema, sig, "example.com", "tool1", discovery, None, store
        )
        assert result.valid is True
        assert result.key_pinning.status == "pinned"

    def test_invalid_signature(self):
        """Invalid signature fails."""
        schema = {"name": "test_tool", "description": "A test"}
        pub_pem, sig, fp = _make_key_and_sign(schema)

        discovery = {
            "schema_version": "1.2",
            "developer_name": "Test Dev",
            "public_key_pem": pub_pem,
        }
        store = KeyPinStore()
        result = verify_schema_offline(
            schema, "invalid_signature_base64", "example.com", "tool1",
            discovery, None, store
        )
        assert result.valid is False
        assert result.error_code == ErrorCode.SIGNATURE_INVALID

    def test_tampered_schema(self):
        """Tampered schema fails verification."""
        schema = {"name": "test_tool", "description": "A test"}
        pub_pem, sig, fp = _make_key_and_sign(schema)

        tampered_schema = {"name": "test_tool", "description": "TAMPERED"}
        discovery = {
            "schema_version": "1.2",
            "developer_name": "Test Dev",
            "public_key_pem": pub_pem,
        }
        store = KeyPinStore()
        result = verify_schema_offline(
            tampered_schema, sig, "example.com", "tool1",
            discovery, None, store
        )
        assert result.valid is False
        assert result.error_code == ErrorCode.SIGNATURE_INVALID

    def test_revoked_key_simple_list(self):
        """Key in simple revocation list fails."""
        schema = {"name": "test_tool", "description": "A test"}
        pub_pem, sig, fp = _make_key_and_sign(schema)

        discovery = {
            "schema_version": "1.2",
            "developer_name": "Test Dev",
            "public_key_pem": pub_pem,
            "revoked_keys": [fp],
        }
        store = KeyPinStore()
        result = verify_schema_offline(
            schema, sig, "example.com", "tool1", discovery, None, store
        )
        assert result.valid is False
        assert result.error_code == ErrorCode.KEY_REVOKED

    def test_revoked_key_standalone_doc(self):
        """Key in standalone revocation doc fails."""
        schema = {"name": "test_tool", "description": "A test"}
        pub_pem, sig, fp = _make_key_and_sign(schema)

        discovery = {
            "schema_version": "1.2",
            "developer_name": "Test Dev",
            "public_key_pem": pub_pem,
        }
        rev = build_revocation_document("example.com")
        add_revoked_key(rev, fp, RevocationReason.KEY_COMPROMISE)

        store = KeyPinStore()
        result = verify_schema_offline(
            schema, sig, "example.com", "tool1", discovery, rev, store
        )
        assert result.valid is False
        assert result.error_code == ErrorCode.KEY_REVOKED

    def test_key_pin_change_rejected(self):
        """Key change is rejected."""
        schema = {"name": "test_tool", "description": "A test"}
        pub_pem1, sig1, fp1 = _make_key_and_sign(schema)
        pub_pem2, sig2, fp2 = _make_key_and_sign(schema)

        disc1 = {
            "schema_version": "1.2",
            "developer_name": "Dev",
            "public_key_pem": pub_pem1,
        }
        disc2 = {
            "schema_version": "1.2",
            "developer_name": "Dev",
            "public_key_pem": pub_pem2,
        }

        store = KeyPinStore()
        # Pin first key
        result1 = verify_schema_offline(
            schema, sig1, "example.com", "tool1", disc1, None, store
        )
        assert result1.valid is True

        # Try with different key
        result2 = verify_schema_offline(
            schema, sig2, "example.com", "tool1", disc2, None, store
        )
        assert result2.valid is False
        assert result2.error_code == ErrorCode.KEY_PIN_MISMATCH

    def test_invalid_discovery(self):
        """Invalid discovery document fails."""
        schema = {"name": "test_tool"}
        store = KeyPinStore()
        result = verify_schema_offline(
            schema, "sig", "example.com", "tool1",
            {"schema_version": "1.2"}, None, store
        )
        assert result.valid is False
        assert result.error_code == ErrorCode.DISCOVERY_INVALID

    def test_missing_domain_in_discovery(self):
        """Discovery without public_key_pem fails."""
        schema = {"name": "test_tool"}
        store = KeyPinStore()
        result = verify_schema_offline(
            schema, "sig", "example.com", "tool1", {}, None, store
        )
        assert result.valid is False
        assert result.error_code == ErrorCode.DISCOVERY_INVALID

    def test_result_to_dict(self):
        """VerificationResult serializes correctly."""
        schema = {"name": "test_tool", "description": "A test"}
        pub_pem, sig, fp = _make_key_and_sign(schema)

        discovery = {
            "schema_version": "1.2",
            "developer_name": "Test Dev",
            "public_key_pem": pub_pem,
        }
        store = KeyPinStore()
        result = verify_schema_offline(
            schema, sig, "example.com", "tool1", discovery, None, store
        )
        d = result.to_dict()
        assert d["valid"] is True
        assert d["domain"] == "example.com"
        assert d["developer_name"] == "Test Dev"
        assert d["key_pinning"]["status"] == "first_use"


class TestVerifySchemaWithResolver:
    """Tests for verify_schema_with_resolver."""

    def test_happy_path_with_resolver(self):
        """Verify using a TrustBundleResolver."""
        schema = {"name": "test_tool", "description": "A test"}
        pub_pem, sig, fp = _make_key_and_sign(schema)

        well_known = {
            "schema_version": "1.2",
            "developer_name": "Bundle Dev",
            "public_key_pem": pub_pem,
        }
        doc = create_bundled_discovery("example.com", well_known)
        bundle = SchemaPinTrustBundle(
            schemapin_bundle_version="1.2",
            created_at="2026-01-01T00:00:00+00:00",
            documents=[doc],
            revocations=[],
        )
        resolver = TrustBundleResolver(bundle)
        store = KeyPinStore()

        result = verify_schema_with_resolver(
            schema, sig, "example.com", "tool1", resolver, store
        )
        assert result.valid is True
        assert result.developer_name == "Bundle Dev"

    def test_missing_domain(self):
        """Missing domain in resolver fails."""
        schema = {"name": "test_tool"}
        bundle = SchemaPinTrustBundle(
            schemapin_bundle_version="1.2",
            created_at="2026-01-01T00:00:00+00:00",
        )
        resolver = TrustBundleResolver(bundle)
        store = KeyPinStore()

        result = verify_schema_with_resolver(
            schema, "sig", "missing.com", "tool1", resolver, store
        )
        assert result.valid is False
        assert result.error_code == ErrorCode.DISCOVERY_FETCH_FAILED
