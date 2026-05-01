"""Tests for DNS TXT cross-verification (v1.4)."""

from pathlib import Path
from typing import Any, Dict, Tuple

import pytest

from schemapin.crypto import KeyManager
from schemapin.dns import (
    DnsTxtRecord,
    parse_txt_record,
    txt_record_name,
    verify_dns_match,
)
from schemapin.skill import SkillSigner
from schemapin.verification import ErrorCode

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_keypair() -> Tuple[str, str]:
    """Generate an ECDSA P-256 keypair and return (private_pem, public_pem)."""
    priv, pub = KeyManager.generate_keypair()
    return (
        KeyManager.export_private_key_pem(priv),
        KeyManager.export_public_key_pem(pub),
    )


def _create_skill_dir(base_path: Path, files: Dict[str, str]) -> Path:
    for rel, content in files.items():
        p = base_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
    return base_path


def _discovery(pub_pem: str) -> Dict[str, Any]:
    return {
        "schema_version": "1.4",
        "developer_name": "Test Dev",
        "public_key_pem": pub_pem,
    }


# ---------------------------------------------------------------------------
# TestParseTxtRecord
# ---------------------------------------------------------------------------


class TestParseTxtRecord:
    """Parser semantics, mirrored from the Rust ``parse_txt_record`` tests."""

    def test_full_record(self) -> None:
        r = parse_txt_record(
            "v=schemapin1; kid=acme-2026-01; fp=sha256:abcd1234"
        )
        assert r.version == "schemapin1"
        assert r.kid == "acme-2026-01"
        assert r.fingerprint == "sha256:abcd1234"

    def test_minimal_record(self) -> None:
        r = parse_txt_record("v=schemapin1;fp=sha256:abc")
        assert r.version == "schemapin1"
        assert r.kid is None
        assert r.fingerprint == "sha256:abc"

    def test_lowercases_fingerprint(self) -> None:
        r = parse_txt_record("v=schemapin1; fp=SHA256:ABCDEF")
        assert r.fingerprint == "sha256:abcdef"

    def test_tolerates_whitespace_and_order(self) -> None:
        r = parse_txt_record("  fp = sha256:beef ;  v = schemapin1  ")
        assert r.version == "schemapin1"
        assert r.fingerprint == "sha256:beef"

    def test_ignores_unknown_fields(self) -> None:
        r = parse_txt_record("v=schemapin1; fp=sha256:abc; future=ignoreme")
        assert r.fingerprint == "sha256:abc"
        assert r.version == "schemapin1"

    def test_missing_v_fails(self) -> None:
        with pytest.raises(ValueError, match="'v'"):
            parse_txt_record("fp=sha256:abc")

    def test_missing_fp_fails(self) -> None:
        with pytest.raises(ValueError, match="'fp'"):
            parse_txt_record("v=schemapin1")

    def test_unsupported_version_fails(self) -> None:
        with pytest.raises(ValueError, match="unsupported version"):
            parse_txt_record("v=schemapin99; fp=sha256:abc")

    def test_fp_without_sha256_prefix_fails(self) -> None:
        with pytest.raises(ValueError, match="sha256"):
            parse_txt_record("v=schemapin1; fp=abc")

    def test_field_without_equals_fails(self) -> None:
        with pytest.raises(ValueError, match="missing '='"):
            parse_txt_record("v=schemapin1; broken")


# ---------------------------------------------------------------------------
# TestTxtRecordName
# ---------------------------------------------------------------------------


class TestTxtRecordName:
    """Tests for the ``_schemapin.{domain}`` lookup name builder."""

    def test_basic(self) -> None:
        assert txt_record_name("example.com") == "_schemapin.example.com"

    def test_strips_trailing_dot(self) -> None:
        assert txt_record_name("example.com.") == "_schemapin.example.com"


# ---------------------------------------------------------------------------
# TestVerifyDnsMatch
# ---------------------------------------------------------------------------


class TestVerifyDnsMatch:
    """Direct tests for the ``verify_dns_match`` cross-check helper."""

    def test_matching_fingerprint_returns_none(self) -> None:
        _priv, pub_pem = _make_keypair()
        fp = KeyManager.calculate_key_fingerprint_from_pem(pub_pem)
        txt = DnsTxtRecord(
            version="schemapin1", fingerprint=fp.lower(), kid=None
        )
        # Should not raise.
        verify_dns_match(_discovery(pub_pem), txt)

    def test_mismatching_fingerprint_raises(self) -> None:
        _priv, pub_pem = _make_keypair()
        txt = DnsTxtRecord(
            version="schemapin1",
            fingerprint=(
                "sha256:0000000000000000000000000000000000000000000000000000000000000000"
            ),
            kid=None,
        )
        with pytest.raises(ValueError, match="mismatch"):
            verify_dns_match(_discovery(pub_pem), txt)

    def test_missing_public_key_raises(self) -> None:
        txt = DnsTxtRecord(
            version="schemapin1", fingerprint="sha256:abc", kid=None
        )
        with pytest.raises(ValueError, match="public_key_pem"):
            verify_dns_match({}, txt)


# ---------------------------------------------------------------------------
# TestVerifySkillOfflineWithDns
# ---------------------------------------------------------------------------


class TestVerifySkillOfflineWithDns:
    """Integration tests for ``SkillSigner.verify_skill_offline_with_dns``."""

    def test_matching_record_passes(self, tmp_path: Path) -> None:
        priv_pem, pub_pem = _make_keypair()
        skill = _create_skill_dir(
            tmp_path / "skill",
            {"SKILL.md": "---\nname: dnsok\n---\n# hi"},
        )
        SkillSigner.sign_skill(skill, priv_pem, "example.com")
        fp = KeyManager.calculate_key_fingerprint_from_pem(pub_pem).lower()
        txt = DnsTxtRecord(version="schemapin1", fingerprint=fp, kid=None)
        result = SkillSigner.verify_skill_offline_with_dns(
            skill, _discovery(pub_pem), tool_id="dnsok", dns_txt=txt
        )
        assert result.valid is True

    def test_mismatching_record_fails_with_domain_mismatch(
        self, tmp_path: Path
    ) -> None:
        priv_pem, pub_pem = _make_keypair()
        skill = _create_skill_dir(
            tmp_path / "skill",
            {"SKILL.md": "---\nname: dnsbad\n---\n# hi"},
        )
        SkillSigner.sign_skill(skill, priv_pem, "example.com")
        txt = DnsTxtRecord(
            version="schemapin1",
            fingerprint=(
                "sha256:0000000000000000000000000000000000000000000000000000000000000000"
            ),
            kid=None,
        )
        result = SkillSigner.verify_skill_offline_with_dns(
            skill, _discovery(pub_pem), tool_id="dnsbad", dns_txt=txt
        )
        assert result.valid is False
        assert result.error_code == ErrorCode.DOMAIN_MISMATCH

    def test_none_dns_txt_is_no_op(self, tmp_path: Path) -> None:
        """``dns_txt=None`` should behave exactly like verify_skill_offline."""
        priv_pem, pub_pem = _make_keypair()
        skill = _create_skill_dir(
            tmp_path / "skill",
            {"SKILL.md": "---\nname: nodns\n---\n# hi"},
        )
        SkillSigner.sign_skill(skill, priv_pem, "example.com")
        result = SkillSigner.verify_skill_offline_with_dns(
            skill, _discovery(pub_pem), tool_id="nodns", dns_txt=None
        )
        assert result.valid is True

    def test_mismatch_does_not_run_when_signature_invalid(
        self, tmp_path: Path
    ) -> None:
        """A failing signature short-circuits before DNS check.

        Otherwise mismatch would mask the real failure code.
        """
        priv1, _pub1 = _make_keypair()
        _priv2, pub2 = _make_keypair()
        skill = _create_skill_dir(
            tmp_path / "skill",
            {"SKILL.md": "# hi"},
        )
        SkillSigner.sign_skill(skill, priv1, "example.com")
        # DNS is correct for pub2 but the sig was made with priv1.
        fp = KeyManager.calculate_key_fingerprint_from_pem(pub2).lower()
        txt = DnsTxtRecord(version="schemapin1", fingerprint=fp, kid=None)
        result = SkillSigner.verify_skill_offline_with_dns(
            skill, _discovery(pub2), tool_id="bad", dns_txt=txt
        )
        assert result.valid is False
        # Signature mismatch is reported, not domain mismatch.
        assert result.error_code == ErrorCode.SIGNATURE_INVALID


# ---------------------------------------------------------------------------
# TestFetchDnsTxtImportError
# ---------------------------------------------------------------------------


class TestFetchDnsTxtImportError:
    """``fetch_dns_txt`` must raise a helpful ImportError when dnspython is absent.

    We can't easily uninstall the dependency mid-test, so we install a
    short-lived meta-path finder that masks the ``dns`` package only for
    this call.
    """

    def test_import_error_message(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import importlib
        import sys

        class _BlockDnsFinder:
            """Meta-path finder that blocks any ``dns`` / ``dns.*`` import."""

            def find_spec(
                self, name: str, path: Any = None, target: Any = None
            ) -> None:
                if name == "dns" or name.startswith("dns."):
                    raise ImportError(f"blocked by test: {name}")
                return None

        # Drop any cached ``dns.*`` modules so the import machinery has to
        # re-resolve through the finder chain.
        for cached in [
            m for m in list(sys.modules) if m == "dns" or m.startswith("dns.")
        ]:
            monkeypatch.delitem(sys.modules, cached, raising=False)

        finder = _BlockDnsFinder()
        sys.meta_path.insert(0, finder)
        try:
            # Reimport ``schemapin.dns`` so its function-local ``import dns``
            # is resolved fresh against the now-blocked path.
            schemapin_dns = importlib.reload(
                importlib.import_module("schemapin.dns")
            )
            with pytest.raises(ImportError, match="schemapin\\[dns\\]"):
                schemapin_dns.fetch_dns_txt("example.com")
        finally:
            sys.meta_path.remove(finder)
            # Restore real dnspython so other tests aren't affected.
            for cached in [
                m for m in list(sys.modules) if m == "dns" or m.startswith("dns.")
            ]:
                del sys.modules[cached]
            importlib.reload(importlib.import_module("schemapin.dns"))
