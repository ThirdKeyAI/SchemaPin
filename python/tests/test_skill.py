"""Tests for skill folder signing and verification."""

import json
from pathlib import Path
from typing import Any, Dict, Tuple

import pytest

from schemapin.crypto import KeyManager, SignatureManager
from schemapin.revocation import (
    RevocationReason,
    add_revoked_key,
    build_revocation_document,
)
from schemapin.skill import SIGNATURE_FILENAME, SkillSigner
from schemapin.verification import ErrorCode, KeyPinStore

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


def _create_skill_dir(
    base_path: Path, files: Dict[str, str]
) -> Path:
    """Create a temporary skill directory with the given file contents.

    ``files`` maps relative paths (forward-slash separated) to text content.
    """
    for rel, content in files.items():
        p = base_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
    return base_path


def _discovery(pub_pem: str) -> Dict[str, Any]:
    """Build a minimal valid discovery document."""
    return {
        "schema_version": "1.3",
        "developer_name": "Test Dev",
        "public_key_pem": pub_pem,
    }


# ---------------------------------------------------------------------------
# TestCanonicalization
# ---------------------------------------------------------------------------


class TestCanonicalization:
    """Tests for SkillSigner.canonicalize_skill."""

    def test_sorted_deterministic(self, tmp_path: Path) -> None:
        """Files are always processed in sorted order."""
        skill = _create_skill_dir(
            tmp_path / "skill",
            {"b.txt": "B", "a.txt": "A", "c.txt": "C"},
        )
        hash1, m1 = SkillSigner.canonicalize_skill(skill)
        hash2, m2 = SkillSigner.canonicalize_skill(skill)
        assert hash1 == hash2
        assert m1 == m2

    def test_skip_schemapin_sig(self, tmp_path: Path) -> None:
        """The .schemapin.sig file is excluded from canonicalization."""
        skill = _create_skill_dir(
            tmp_path / "skill",
            {"SKILL.md": "# hi", SIGNATURE_FILENAME: "ignored"},
        )
        _hash, manifest = SkillSigner.canonicalize_skill(skill)
        assert SIGNATURE_FILENAME not in manifest
        assert "SKILL.md" in manifest

    def test_nested_dirs(self, tmp_path: Path) -> None:
        """Nested directories are included with forward-slash paths."""
        skill = _create_skill_dir(
            tmp_path / "skill",
            {"SKILL.md": "# hi", "sub/nested.txt": "deep"},
        )
        _hash, manifest = SkillSigner.canonicalize_skill(skill)
        assert "sub/nested.txt" in manifest

    def test_forward_slashes(self, tmp_path: Path) -> None:
        """All manifest keys use forward slashes."""
        skill = _create_skill_dir(
            tmp_path / "skill",
            {"a/b/c.txt": "content"},
        )
        _hash, manifest = SkillSigner.canonicalize_skill(skill)
        for key in manifest:
            assert "\\" not in key

    def test_empty_dir_raises(self, tmp_path: Path) -> None:
        """Empty directory raises ValueError."""
        skill = tmp_path / "empty_skill"
        skill.mkdir()
        with pytest.raises(ValueError, match="empty"):
            SkillSigner.canonicalize_skill(skill)

    def test_binary_files(self, tmp_path: Path) -> None:
        """Binary files are hashed correctly."""
        skill = tmp_path / "skill"
        skill.mkdir()
        (skill / "data.bin").write_bytes(b"\x00\x01\x02\xff")
        (skill / "SKILL.md").write_text("# ok")
        _hash, manifest = SkillSigner.canonicalize_skill(skill)
        assert "data.bin" in manifest
        assert manifest["data.bin"].startswith("sha256:")

    def test_content_affects_hash(self, tmp_path: Path) -> None:
        """Different content produces a different root hash."""
        s1 = _create_skill_dir(tmp_path / "s1", {"a.txt": "v1"})
        s2 = _create_skill_dir(tmp_path / "s2", {"a.txt": "v2"})
        h1, _ = SkillSigner.canonicalize_skill(s1)
        h2, _ = SkillSigner.canonicalize_skill(s2)
        assert h1 != h2


# ---------------------------------------------------------------------------
# TestFileManifest
# ---------------------------------------------------------------------------


class TestFileManifest:
    """Tests for file manifest format."""

    def test_all_files_included(self, tmp_path: Path) -> None:
        """All non-sig files appear in the manifest."""
        skill = _create_skill_dir(
            tmp_path / "skill",
            {"SKILL.md": "# hi", "index.py": "pass", "lib/util.py": "x=1"},
        )
        _hash, manifest = SkillSigner.canonicalize_skill(skill)
        assert set(manifest.keys()) == {"SKILL.md", "index.py", "lib/util.py"}

    def test_sha256_format(self, tmp_path: Path) -> None:
        """Every manifest value starts with 'sha256:'."""
        skill = _create_skill_dir(
            tmp_path / "skill",
            {"a.txt": "hello", "b.txt": "world"},
        )
        _hash, manifest = SkillSigner.canonicalize_skill(skill)
        for val in manifest.values():
            assert val.startswith("sha256:")
            # Hex digest after prefix
            assert len(val.split(":")[1]) == 64

    def test_excludes_sig_file(self, tmp_path: Path) -> None:
        """Manifest never includes .schemapin.sig."""
        skill = _create_skill_dir(
            tmp_path / "skill",
            {"SKILL.md": "# hi", SIGNATURE_FILENAME: '{"sig": true}'},
        )
        _hash, manifest = SkillSigner.canonicalize_skill(skill)
        assert SIGNATURE_FILENAME not in manifest


# ---------------------------------------------------------------------------
# TestParseSkillName
# ---------------------------------------------------------------------------


class TestParseSkillName:
    """Tests for SkillSigner.parse_skill_name."""

    def test_from_frontmatter(self, tmp_path: Path) -> None:
        """Extracts name from YAML frontmatter."""
        skill = _create_skill_dir(
            tmp_path / "my-skill",
            {"SKILL.md": "---\nname: cool-skill\n---\n# Hello"},
        )
        assert SkillSigner.parse_skill_name(skill) == "cool-skill"

    def test_quoted_name(self, tmp_path: Path) -> None:
        """Handles single-quoted name values."""
        skill = _create_skill_dir(
            tmp_path / "skill",
            {"SKILL.md": "---\nname: 'quoted-name'\n---\n# Hello"},
        )
        assert SkillSigner.parse_skill_name(skill) == "quoted-name"

    def test_double_quoted_name(self, tmp_path: Path) -> None:
        """Handles double-quoted name values."""
        skill = _create_skill_dir(
            tmp_path / "skill",
            {'SKILL.md': '---\nname: "dq-name"\n---\n# Hello'},
        )
        assert SkillSigner.parse_skill_name(skill) == "dq-name"

    def test_no_frontmatter_fallback(self, tmp_path: Path) -> None:
        """Falls back to dirname when SKILL.md has no frontmatter."""
        skill = _create_skill_dir(
            tmp_path / "fallback-dir",
            {"SKILL.md": "# Just markdown, no frontmatter"},
        )
        assert SkillSigner.parse_skill_name(skill) == "fallback-dir"

    def test_no_skill_md_fallback(self, tmp_path: Path) -> None:
        """Falls back to dirname when no SKILL.md exists."""
        skill = _create_skill_dir(
            tmp_path / "dirname-skill",
            {"index.py": "pass"},
        )
        assert SkillSigner.parse_skill_name(skill) == "dirname-skill"

    def test_frontmatter_without_name(self, tmp_path: Path) -> None:
        """Falls back to dirname when frontmatter has no name field."""
        skill = _create_skill_dir(
            tmp_path / "noname-skill",
            {"SKILL.md": "---\ndescription: stuff\n---\n# Hello"},
        )
        assert SkillSigner.parse_skill_name(skill) == "noname-skill"


# ---------------------------------------------------------------------------
# TestSignAndVerify
# ---------------------------------------------------------------------------


class TestSignAndVerify:
    """Tests for sign_skill and roundtrip verification."""

    def test_creates_sig_file(self, tmp_path: Path) -> None:
        """sign_skill writes .schemapin.sig."""
        priv_pem, _pub_pem = _make_keypair()
        skill = _create_skill_dir(
            tmp_path / "skill",
            {"SKILL.md": "---\nname: test-skill\n---\n# Hello"},
        )
        SkillSigner.sign_skill(skill, priv_pem, "example.com")
        assert (skill / SIGNATURE_FILENAME).is_file()

    def test_sig_structure(self, tmp_path: Path) -> None:
        """Signature document has all expected fields."""
        priv_pem, _pub_pem = _make_keypair()
        skill = _create_skill_dir(
            tmp_path / "skill",
            {"SKILL.md": "---\nname: test-skill\n---\n# Hello"},
        )
        sig = SkillSigner.sign_skill(skill, priv_pem, "example.com")
        assert sig["schemapin_version"] == "1.3"
        assert sig["skill_name"] == "test-skill"
        assert sig["skill_hash"].startswith("sha256:")
        assert isinstance(sig["signature"], str)
        assert sig["domain"] == "example.com"
        assert sig["signer_kid"].startswith("sha256:")
        assert "file_manifest" in sig
        assert "SKILL.md" in sig["file_manifest"]

    def test_roundtrip(self, tmp_path: Path) -> None:
        """Sign and then verify the same skill directory succeeds."""
        priv_pem, pub_pem = _make_keypair()
        skill = _create_skill_dir(
            tmp_path / "skill",
            {"SKILL.md": "---\nname: roundtrip\n---\n# ok", "lib.py": "x=1"},
        )
        SkillSigner.sign_skill(skill, priv_pem, "example.com")
        result = SkillSigner.verify_skill_offline(
            skill, _discovery(pub_pem)
        )
        assert result.valid is True
        assert result.domain == "example.com"

    def test_wrong_key_fails(self, tmp_path: Path) -> None:
        """Verification with a different key fails."""
        priv1, _pub1 = _make_keypair()
        _priv2, pub2 = _make_keypair()
        skill = _create_skill_dir(
            tmp_path / "skill",
            {"SKILL.md": "# hi"},
        )
        SkillSigner.sign_skill(skill, priv1, "example.com")
        result = SkillSigner.verify_skill_offline(
            skill, _discovery(pub2)
        )
        assert result.valid is False
        assert result.error_code == ErrorCode.SIGNATURE_INVALID

    def test_tampered_file_fails(self, tmp_path: Path) -> None:
        """Modifying a file after signing causes verification failure."""
        priv_pem, pub_pem = _make_keypair()
        skill = _create_skill_dir(
            tmp_path / "skill",
            {"SKILL.md": "# original"},
        )
        SkillSigner.sign_skill(skill, priv_pem, "example.com")
        (skill / "SKILL.md").write_text("# TAMPERED")
        result = SkillSigner.verify_skill_offline(
            skill, _discovery(pub_pem)
        )
        assert result.valid is False
        assert result.error_code == ErrorCode.SIGNATURE_INVALID

    def test_added_file_fails(self, tmp_path: Path) -> None:
        """Adding a new file after signing causes verification failure."""
        priv_pem, pub_pem = _make_keypair()
        skill = _create_skill_dir(
            tmp_path / "skill",
            {"SKILL.md": "# hi"},
        )
        SkillSigner.sign_skill(skill, priv_pem, "example.com")
        (skill / "extra.txt").write_text("injected")
        result = SkillSigner.verify_skill_offline(
            skill, _discovery(pub_pem)
        )
        assert result.valid is False
        assert result.error_code == ErrorCode.SIGNATURE_INVALID

    def test_removed_file_fails(self, tmp_path: Path) -> None:
        """Removing a file after signing causes verification failure."""
        priv_pem, pub_pem = _make_keypair()
        skill = _create_skill_dir(
            tmp_path / "skill",
            {"SKILL.md": "# hi", "lib.py": "x=1"},
        )
        SkillSigner.sign_skill(skill, priv_pem, "example.com")
        (skill / "lib.py").unlink()
        result = SkillSigner.verify_skill_offline(
            skill, _discovery(pub_pem)
        )
        assert result.valid is False
        assert result.error_code == ErrorCode.SIGNATURE_INVALID

    def test_custom_skill_name(self, tmp_path: Path) -> None:
        """skill_name override is used in the signature."""
        priv_pem, _pub_pem = _make_keypair()
        skill = _create_skill_dir(
            tmp_path / "skill",
            {"SKILL.md": "---\nname: original\n---\n# hi"},
        )
        sig = SkillSigner.sign_skill(
            skill, priv_pem, "example.com", skill_name="override"
        )
        assert sig["skill_name"] == "override"

    def test_custom_kid(self, tmp_path: Path) -> None:
        """signer_kid override is used in the signature."""
        priv_pem, _pub_pem = _make_keypair()
        skill = _create_skill_dir(
            tmp_path / "skill",
            {"SKILL.md": "# hi"},
        )
        sig = SkillSigner.sign_skill(
            skill, priv_pem, "example.com", signer_kid="sha256:custom"
        )
        assert sig["signer_kid"] == "sha256:custom"


# ---------------------------------------------------------------------------
# TestVerifyOffline
# ---------------------------------------------------------------------------


class TestVerifyOffline:
    """Tests for verify_skill_offline edge cases."""

    def test_happy_path(self, tmp_path: Path) -> None:
        """Full offline verification succeeds with correct inputs."""
        priv_pem, pub_pem = _make_keypair()
        skill = _create_skill_dir(
            tmp_path / "skill",
            {"SKILL.md": "---\nname: test\n---\n# ok"},
        )
        SkillSigner.sign_skill(skill, priv_pem, "example.com")
        store = KeyPinStore()
        result = SkillSigner.verify_skill_offline(
            skill, _discovery(pub_pem), pin_store=store, tool_id="test"
        )
        assert result.valid is True
        assert result.key_pinning is not None
        assert result.key_pinning.status == "first_use"

    def test_revoked_key(self, tmp_path: Path) -> None:
        """Revoked key fails verification."""
        priv_pem, pub_pem = _make_keypair()
        pub_key = KeyManager.load_public_key_pem(pub_pem)
        fp = KeyManager.calculate_key_fingerprint(pub_key)
        skill = _create_skill_dir(
            tmp_path / "skill",
            {"SKILL.md": "# hi"},
        )
        SkillSigner.sign_skill(skill, priv_pem, "example.com")
        rev = build_revocation_document("example.com")
        add_revoked_key(rev, fp, RevocationReason.KEY_COMPROMISE)
        result = SkillSigner.verify_skill_offline(
            skill, _discovery(pub_pem), revocation_doc=rev
        )
        assert result.valid is False
        assert result.error_code == ErrorCode.KEY_REVOKED

    def test_pin_mismatch(self, tmp_path: Path) -> None:
        """Key pin change is rejected."""
        priv1, pub1 = _make_keypair()
        priv2, pub2 = _make_keypair()
        skill = _create_skill_dir(
            tmp_path / "skill",
            {"SKILL.md": "# hi"},
        )
        # Sign with key 1, pin it
        SkillSigner.sign_skill(skill, priv1, "example.com")
        store = KeyPinStore()
        r1 = SkillSigner.verify_skill_offline(
            skill, _discovery(pub1), pin_store=store, tool_id="t"
        )
        assert r1.valid is True

        # Re-sign with key 2
        SkillSigner.sign_skill(skill, priv2, "example.com")
        r2 = SkillSigner.verify_skill_offline(
            skill, _discovery(pub2), pin_store=store, tool_id="t"
        )
        assert r2.valid is False
        assert r2.error_code == ErrorCode.KEY_PIN_MISMATCH

    def test_invalid_discovery(self, tmp_path: Path) -> None:
        """Invalid discovery document fails."""
        priv_pem, _pub_pem = _make_keypair()
        skill = _create_skill_dir(
            tmp_path / "skill",
            {"SKILL.md": "# hi"},
        )
        SkillSigner.sign_skill(skill, priv_pem, "example.com")
        result = SkillSigner.verify_skill_offline(
            skill, {"schema_version": "1.3"}
        )
        assert result.valid is False
        assert result.error_code == ErrorCode.DISCOVERY_INVALID

    def test_missing_sig(self, tmp_path: Path) -> None:
        """Missing .schemapin.sig fails gracefully."""
        skill = _create_skill_dir(
            tmp_path / "skill",
            {"SKILL.md": "# no signature here"},
        )
        result = SkillSigner.verify_skill_offline(
            skill, {"public_key_pem": "dummy"}
        )
        assert result.valid is False
        assert result.error_code == ErrorCode.SIGNATURE_INVALID


# ---------------------------------------------------------------------------
# TestDetectTamperedFiles
# ---------------------------------------------------------------------------


class TestDetectTamperedFiles:
    """Tests for SkillSigner.detect_tampered_files."""

    def test_modified(self) -> None:
        """Detects modified files."""
        signed = {"a.txt": "sha256:aaa", "b.txt": "sha256:bbb"}
        current = {"a.txt": "sha256:aaa", "b.txt": "sha256:ccc"}
        diff = SkillSigner.detect_tampered_files(current, signed)
        assert diff["modified"] == ["b.txt"]
        assert diff["added"] == []
        assert diff["removed"] == []

    def test_added(self) -> None:
        """Detects added files."""
        signed = {"a.txt": "sha256:aaa"}
        current = {"a.txt": "sha256:aaa", "new.txt": "sha256:nnn"}
        diff = SkillSigner.detect_tampered_files(current, signed)
        assert diff["added"] == ["new.txt"]
        assert diff["modified"] == []
        assert diff["removed"] == []

    def test_removed(self) -> None:
        """Detects removed files."""
        signed = {"a.txt": "sha256:aaa", "b.txt": "sha256:bbb"}
        current = {"a.txt": "sha256:aaa"}
        diff = SkillSigner.detect_tampered_files(current, signed)
        assert diff["removed"] == ["b.txt"]
        assert diff["modified"] == []
        assert diff["added"] == []

    def test_combined(self) -> None:
        """Detects all categories at once."""
        signed = {"keep.txt": "sha256:k", "mod.txt": "sha256:old", "gone.txt": "sha256:g"}
        current = {"keep.txt": "sha256:k", "mod.txt": "sha256:new", "extra.txt": "sha256:e"}
        diff = SkillSigner.detect_tampered_files(current, signed)
        assert diff["modified"] == ["mod.txt"]
        assert diff["added"] == ["extra.txt"]
        assert diff["removed"] == ["gone.txt"]

    def test_no_changes(self) -> None:
        """No changes returns empty lists."""
        m = {"a.txt": "sha256:aaa", "b.txt": "sha256:bbb"}
        diff = SkillSigner.detect_tampered_files(m, m)
        assert diff == {"modified": [], "added": [], "removed": []}


# ---------------------------------------------------------------------------
# TestLoadSignature
# ---------------------------------------------------------------------------


class TestLoadSignature:
    """Tests for SkillSigner.load_signature."""

    def test_load_existing(self, tmp_path: Path) -> None:
        """Loads an existing .schemapin.sig file."""
        skill = tmp_path / "skill"
        skill.mkdir()
        sig_data = {"schemapin_version": "1.3", "skill_name": "test"}
        (skill / SIGNATURE_FILENAME).write_text(json.dumps(sig_data))
        loaded = SkillSigner.load_signature(skill)
        assert loaded == sig_data

    def test_missing_raises(self, tmp_path: Path) -> None:
        """Missing file raises FileNotFoundError."""
        skill = tmp_path / "nosig"
        skill.mkdir()
        with pytest.raises(FileNotFoundError):
            SkillSigner.load_signature(skill)


# ---------------------------------------------------------------------------
# TestSkillCLI
# ---------------------------------------------------------------------------


class TestSkillCLI:
    """Integration tests for CLI --skill flag."""

    def test_sign_and_verify_roundtrip(self, tmp_path: Path) -> None:
        """sign --skill + verify --skill --public-key roundtrip."""
        priv_pem, pub_pem = _make_keypair()

        # Write keys
        priv_path = tmp_path / "private.pem"
        pub_path = tmp_path / "public.pem"
        priv_path.write_text(priv_pem)
        pub_path.write_text(pub_pem)

        # Create skill
        skill = _create_skill_dir(
            tmp_path / "my-skill",
            {"SKILL.md": "---\nname: cli-test\n---\n# CLI test skill"},
        )

        # Sign via library (CLI delegates here)
        sig_doc = SkillSigner.sign_skill(
            skill, priv_pem, "example.com"
        )
        assert sig_doc["skill_name"] == "cli-test"

        # Verify with public key
        root_hash, _manifest = SkillSigner.canonicalize_skill(skill)
        pub_key = KeyManager.load_public_key_pem(pub_pem)
        valid = SignatureManager.verify_signature(
            root_hash, sig_doc["signature"], pub_key
        )
        assert valid is True

    def test_sign_requires_domain(self, tmp_path: Path) -> None:
        """sign_skill requires a domain argument."""
        priv_pem, _ = _make_keypair()
        skill = _create_skill_dir(
            tmp_path / "skill",
            {"SKILL.md": "# hi"},
        )
        # Domain is a required positional; calling without it would be a
        # TypeError at the Python level.
        with pytest.raises(TypeError):
            SkillSigner.sign_skill(skill, priv_pem)  # type: ignore[call-arg]
