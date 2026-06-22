"""Tests for v1.4 A2A trust-bundle distribution (sign/verify/merge/JSON-RPC).

Mirrors ``rust/src/bundle.rs`` tests. The cross-language fixture test is the
key interop proof: it loads ``tests/cross-language/signed_bundle.json`` (signed
by the Rust SDK) and asserts it verifies here, confirming the four SDKs agree
on the bundle canonicalization and signing input.
"""

import os

import pytest

from schemapin.bundle import SchemaPinTrustBundle, create_bundled_discovery
from schemapin.bundle_distribution import (
    BundleVerificationError,
    build_trust_bundle_request,
    build_trust_bundle_response,
    merge_trust_bundles,
    parse_trust_bundle_response,
    sign_trust_bundle,
    verify_trust_bundle,
)
from schemapin.crypto import KeyManager
from schemapin.verification import ErrorCode, KeyPinStore


def _keypair_pem():
    priv, _pub = KeyManager.generate_keypair()
    return KeyManager.export_private_key_pem(priv)


def _make_bundle(domain="example.com", created_at="2026-05-15T00:00:00Z",
                 developer_name="Example"):
    well_known = {
        "schema_version": "1.2",
        "developer_name": developer_name,
        "public_key_pem": "-----BEGIN PUBLIC KEY-----\nx\n-----END PUBLIC KEY-----",
        "revoked_keys": [],
    }
    doc = create_bundled_discovery(domain, well_known)
    return SchemaPinTrustBundle(
        schemapin_bundle_version="1.2",
        created_at=created_at,
        documents=[doc],
    )


class TestSignVerify:
    def test_sign_verify_roundtrip(self):
        priv = _keypair_pem()
        bundle = _make_bundle()
        signed = sign_trust_bundle(
            bundle, priv, "auth-2026-05", "2026-05-15T00:00:00Z"
        )

        assert signed.schemapin_bundle_version == "1.4"
        assert signed.signature is not None
        assert signed.bundle_authority.kid == "auth-2026-05"

        store = KeyPinStore()
        # Returns None on success, does not raise.
        assert verify_trust_bundle(signed, store) is None

    def test_tampered_bundle_fails(self):
        priv = _keypair_pem()
        signed = sign_trust_bundle(
            _make_bundle(), priv, "auth", "2026-05-15T00:00:00Z"
        )
        # Mutate a signed field.
        signed.documents[0]["domain"] = "evil.com"

        store = KeyPinStore()
        with pytest.raises(BundleVerificationError) as ei:
            verify_trust_bundle(signed, store)
        assert ei.value.code == ErrorCode.SIGNATURE_INVALID

    def test_unsigned_bundle_rejected(self):
        bundle = _make_bundle()
        store = KeyPinStore()
        with pytest.raises(BundleVerificationError) as ei:
            verify_trust_bundle(bundle, store)
        assert ei.value.code == ErrorCode.BUNDLE_UNSIGNED

    def test_expired_bundle_rejected(self):
        priv = _keypair_pem()
        signed = sign_trust_bundle(
            _make_bundle(created_at="2020-01-01T00:00:00Z"),
            priv,
            "auth",
            "2020-01-01T00:00:00Z",
            expires_at="2020-02-01T00:00:00Z",
        )
        store = KeyPinStore()
        with pytest.raises(BundleVerificationError) as ei:
            verify_trust_bundle(signed, store)
        assert ei.value.code == ErrorCode.BUNDLE_EXPIRED

    def test_unparseable_expires_at_rejected(self):
        priv = _keypair_pem()
        signed = sign_trust_bundle(
            _make_bundle(), priv, "auth", "2026-05-15T00:00:00Z",
            expires_at="not-a-date",
        )
        store = KeyPinStore()
        with pytest.raises(BundleVerificationError) as ei:
            verify_trust_bundle(signed, store)
        assert ei.value.code == ErrorCode.BUNDLE_EXPIRED

    def test_authority_tofu_mismatch(self):
        priv1 = _keypair_pem()
        priv2 = _keypair_pem()
        bundle = _make_bundle()

        signed1 = sign_trust_bundle(bundle, priv1, "auth", "2026-05-15T00:00:00Z")
        # Different key, SAME kid -> impersonation attempt.
        signed2 = sign_trust_bundle(bundle, priv2, "auth", "2026-05-16T00:00:00Z")

        store = KeyPinStore()
        verify_trust_bundle(signed1, store)  # pins priv1
        with pytest.raises(BundleVerificationError) as ei:
            verify_trust_bundle(signed2, store)
        assert ei.value.code == ErrorCode.KEY_PIN_MISMATCH


class TestMerge:
    def test_merge_newest_wins(self):
        older = _make_bundle(created_at="2026-01-01T00:00:00Z",
                             developer_name="Old")
        newer = _make_bundle(created_at="2026-05-01T00:00:00Z",
                             developer_name="New")
        other = _make_bundle(domain="other.com",
                             created_at="2026-03-01T00:00:00Z")

        merged = merge_trust_bundles([older, newer, other])
        assert len(merged.documents) == 2
        ex = next(d for d in merged.documents if d["domain"] == "example.com")
        assert ex["developer_name"] == "New"
        assert merged.created_at == "2026-05-01T00:00:00Z"
        assert merged.schemapin_bundle_version == "1.4"
        # Merge result is unsigned.
        assert merged.bundle_authority is None
        assert merged.signature is None
        # Sorted by domain for determinism.
        assert [d["domain"] for d in merged.documents] == ["example.com", "other.com"]

    def test_merge_signed_at_beats_created_at(self):
        a = _make_bundle(created_at="2026-01-01T00:00:00Z",
                        developer_name="Signed-late")
        a.signed_at = "2026-09-01T00:00:00Z"
        b = _make_bundle(created_at="2026-06-01T00:00:00Z",
                        developer_name="Created-mid")

        merged = merge_trust_bundles([b, a])
        assert merged.documents[0]["developer_name"] == "Signed-late"


class TestJsonRpcEnvelope:
    def test_request_shape(self):
        req = build_trust_bundle_request("example.com", id=1)
        assert req["jsonrpc"] == "2.0"
        assert req["method"] == "schemapin/trustBundle"
        assert req["params"]["domain"] == "example.com"
        assert req["id"] == 1

    def test_request_no_domain(self):
        req = build_trust_bundle_request(id=2)
        assert req["params"] == {}

    def test_envelope_roundtrip(self):
        priv = _keypair_pem()
        signed = sign_trust_bundle(
            _make_bundle(), priv, "auth", "2026-05-15T00:00:00Z"
        )

        resp = build_trust_bundle_response(signed, id=1)
        parsed = parse_trust_bundle_response(resp)
        assert parsed.to_dict() == signed.to_dict()

        # The parsed bundle still verifies.
        store = KeyPinStore()
        verify_trust_bundle(parsed, store)

    def test_parse_missing_bundle(self):
        with pytest.raises(BundleVerificationError) as ei:
            parse_trust_bundle_response({"jsonrpc": "2.0", "result": {}, "id": 1})
        assert ei.value.code == ErrorCode.DISCOVERY_INVALID


class TestCrossLanguage:
    def test_rust_signed_bundle_verifies(self):
        """Load the shared Rust-signed fixture and verify it. This proves the
        Python canonicalization / signing input matches the Rust reference.
        """
        # Resolve repo root robustly: this file lives at
        # <root>/python/tests/test_bundle_distribution.py
        here = os.path.dirname(os.path.abspath(__file__))
        root = os.path.abspath(os.path.join(here, "..", ".."))
        fixture = os.path.join(root, "tests", "cross-language", "signed_bundle.json")
        assert os.path.exists(fixture), f"fixture not found: {fixture}"

        with open(fixture, encoding="utf-8") as f:
            bundle = SchemaPinTrustBundle.from_json(f.read())

        store = KeyPinStore()
        # Must not raise — interop proof.
        assert verify_trust_bundle(bundle, store) is None
