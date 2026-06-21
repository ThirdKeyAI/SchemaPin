"""Tests for the v1.4 alpha.3 canonicalization id and A2A context surface."""

from __future__ import annotations

import pytest

from schemapin import (
    A2A_MAX_DELEGATION_DEPTH,
    CANONICALIZATION_V1,
    A2aVerificationContext,
    ErrorCode,
    KeyManager,
    KeyPinStore,
    SchemaPinCore,
    SignatureManager,
    a2a_allows,
    a2a_intersect,
    a2a_is_unrestricted,
    check_canonicalization,
    verify_schema_for_a2a,
    verify_schema_offline,
)


# ──────────────────────────────────────────────────────────────────────
# AllowedDomains helpers (mirrors AgentPin v0.3 §4.11 semantics)
# ──────────────────────────────────────────────────────────────────────


class TestAllowedDomainsHelpers:
    def test_empty_is_unrestricted(self) -> None:
        assert a2a_is_unrestricted([])
        assert a2a_is_unrestricted(None)

    def test_unrestricted_allows_anything(self) -> None:
        assert a2a_allows([], "literally-anything")

    def test_restricted_filters(self) -> None:
        ad = ["api.client.com", "*.partner.com"]
        assert a2a_allows(ad, "api.client.com")
        assert a2a_allows(ad, "tools.partner.com")
        assert not a2a_allows(ad, "partner.com")  # *.partner.com excludes bare
        assert not a2a_allows(ad, "evil.example.com")

    def test_intersect_with_unrestricted_returns_other(self) -> None:
        assert a2a_intersect([], ["a.com", "b.com"]) == ["a.com", "b.com"]
        assert a2a_intersect(["a.com", "b.com"], []) == ["a.com", "b.com"]

    def test_intersect_overlap(self) -> None:
        assert a2a_intersect(["a.com", "b.com", "c.com"], ["b.com", "c.com", "d.com"]) == [
            "b.com",
            "c.com",
        ]

    def test_intersect_empty_overlap_is_unrestricted_per_spec(self) -> None:
        # AgentPin spec §4.11.4 edge case: disjoint non-empty allow-lists
        # intersect to []. Under the convention that's "unrestricted".
        result = a2a_intersect(["a.com"], ["b.com"])
        assert result == []
        assert a2a_is_unrestricted(result)


# ──────────────────────────────────────────────────────────────────────
# Canonicalization algorithm identifier
# ──────────────────────────────────────────────────────────────────────


class TestCheckCanonicalization:
    def test_absent_is_supported(self) -> None:
        assert check_canonicalization(None) is None

    def test_v1_is_supported(self) -> None:
        assert check_canonicalization(CANONICALIZATION_V1) is None
        assert check_canonicalization("schemapin-v1") is None

    def test_unknown_returns_offending_value(self) -> None:
        assert check_canonicalization("schemapin-v999") == "schemapin-v999"


# ──────────────────────────────────────────────────────────────────────
# Verification fixture
# ──────────────────────────────────────────────────────────────────────


@pytest.fixture
def signed_schema():
    """Generate a fresh keypair, sign a tiny schema, return everything callers need."""
    private_key, public_key = KeyManager.generate_keypair()
    public_pem = KeyManager.export_public_key_pem(public_key)
    private_pem = KeyManager.export_private_key_pem(private_key)
    schema = {
        "name": "calculate_sum",
        "description": "Calculates the sum of two numbers",
        "parameters": {"a": "integer", "b": "integer"},
    }
    schema_hash = SchemaPinCore.canonicalize_and_hash(schema)
    signature = SignatureManager.sign_hash(schema_hash, private_key)
    discovery = {
        "schema_version": "1.2",
        "developer_name": "Test Developer",
        "public_key_pem": public_pem,
        "revoked_keys": [],
    }
    return {
        "schema": schema,
        "signature": signature,
        "discovery": discovery,
        "private_pem": private_pem,
        "public_pem": public_pem,
    }


# ──────────────────────────────────────────────────────────────────────
# Canonicalization integration into verify_schema_offline
# ──────────────────────────────────────────────────────────────────────


class TestVerifySchemaOfflineCanonicalization:
    def test_absent_canonicalization_accepted(self, signed_schema) -> None:
        result = verify_schema_offline(
            signed_schema["schema"],
            signed_schema["signature"],
            "example.com",
            "calculate_sum",
            signed_schema["discovery"],
            None,
            KeyPinStore(),
        )
        assert result.valid, result

    def test_v1_canonicalization_accepted(self, signed_schema) -> None:
        result = verify_schema_offline(
            signed_schema["schema"],
            signed_schema["signature"],
            "example.com",
            "calculate_sum",
            signed_schema["discovery"],
            None,
            KeyPinStore(),
            canonicalization=CANONICALIZATION_V1,
        )
        assert result.valid

    def test_unknown_canonicalization_rejected(self, signed_schema) -> None:
        result = verify_schema_offline(
            signed_schema["schema"],
            signed_schema["signature"],
            "example.com",
            "calculate_sum",
            signed_schema["discovery"],
            None,
            KeyPinStore(),
            canonicalization="schemapin-v999",
        )
        assert not result.valid
        assert result.error_code == ErrorCode.CANONICALIZATION_UNSUPPORTED


# ──────────────────────────────────────────────────────────────────────
# verify_schema_for_a2a
# ──────────────────────────────────────────────────────────────────────


def _ctx(trusted, depth=0):
    return A2aVerificationContext(
        caller_agent_id="urn:agentpin:caller.com:test",
        delegation_depth=depth,
        originating_domain="caller.com",
        trusted_domains=list(trusted),
    )


class TestVerifySchemaForA2A:
    def test_unrestricted_caller_allows_any_provider(self, signed_schema) -> None:
        result = verify_schema_for_a2a(
            signed_schema["schema"],
            signed_schema["signature"],
            "example.com",
            "calculate_sum",
            signed_schema["discovery"],
            None,
            KeyPinStore(),
            _ctx([]),
        )
        assert result.valid, result

    def test_caller_allow_list_includes_provider(self, signed_schema) -> None:
        result = verify_schema_for_a2a(
            signed_schema["schema"],
            signed_schema["signature"],
            "example.com",
            "calculate_sum",
            signed_schema["discovery"],
            None,
            KeyPinStore(),
            _ctx(["example.com", "other.com"]),
        )
        assert result.valid

    def test_provider_outside_caller_scope_rejected(self, signed_schema) -> None:
        result = verify_schema_for_a2a(
            signed_schema["schema"],
            signed_schema["signature"],
            "example.com",
            "calculate_sum",
            signed_schema["discovery"],
            None,
            KeyPinStore(),
            _ctx(["other.com"]),
        )
        assert not result.valid
        assert result.error_code == ErrorCode.A2A_SCOPE_VIOLATION

    def test_delegation_depth_cap_enforced(self, signed_schema) -> None:
        result = verify_schema_for_a2a(
            signed_schema["schema"],
            signed_schema["signature"],
            "example.com",
            "calculate_sum",
            signed_schema["discovery"],
            None,
            KeyPinStore(),
            _ctx([], depth=A2A_MAX_DELEGATION_DEPTH + 1),
        )
        assert not result.valid
        assert result.error_code == ErrorCode.A2A_SCOPE_VIOLATION

    def test_underlying_signature_failure_passes_through(self, signed_schema) -> None:
        result = verify_schema_for_a2a(
            signed_schema["schema"],
            "bm90LWEtdmFsaWQtc2lnbmF0dXJl",
            "example.com",
            "calculate_sum",
            signed_schema["discovery"],
            None,
            KeyPinStore(),
            _ctx([]),
        )
        assert not result.valid
        # The cryptographic failure is what surfaces, not A2A_SCOPE_VIOLATION
        assert result.error_code == ErrorCode.SIGNATURE_INVALID

    def test_canonicalization_unknown_rejected_through_a2a(self, signed_schema) -> None:
        result = verify_schema_for_a2a(
            signed_schema["schema"],
            signed_schema["signature"],
            "example.com",
            "calculate_sum",
            signed_schema["discovery"],
            None,
            KeyPinStore(),
            _ctx([]),
            canonicalization="schemapin-v999",
        )
        assert not result.valid
        assert result.error_code == ErrorCode.CANONICALIZATION_UNSUPPORTED

    def test_wildcard_provider_in_caller_trusted_list(self, signed_schema) -> None:
        # *.example.com matches api.example.com via allows() — this is the
        # primary path, not the intersect-becomes-empty edge case.
        result = verify_schema_for_a2a(
            signed_schema["schema"],
            signed_schema["signature"],
            "api.example.com",
            "calculate_sum",
            {
                **signed_schema["discovery"],
            },
            None,
            KeyPinStore(),
            _ctx(["*.example.com"]),
        )
        # Note: the signed schema's "domain" param matches the discovery doc's
        # public key, so signature verification still succeeds here.
        assert result.valid, result
