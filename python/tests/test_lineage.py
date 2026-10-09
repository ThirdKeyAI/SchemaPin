"""Tests for the verifier-side LineageStore (design issue 3)."""

import pytest

from schemapin.lineage import LineageError, LineageStore, version_increases


def _doc(skill_hash, previous=None, version=None, schemapin="1.4"):
    d = {"schemapin_version": schemapin, "skill_hash": skill_hash}
    if previous is not None:
        d["previous_hash"] = previous
    if version is not None:
        d["schema_version"] = version
    return d


def test_first_use_then_advance_then_unchanged():
    store = LineageStore()
    assert store.check_and_advance("calc", "example.com", _doc("sha256:a", version="1.0.0")) == "first_use"
    assert store.check_and_advance("calc", "example.com", _doc("sha256:a", version="1.0.0")) == "unchanged"
    assert (
        store.check_and_advance("calc", "example.com", _doc("sha256:b", previous="sha256:a", version="1.1.0"))
        == "advanced"
    )
    assert store.get("calc", "example.com").skill_hash == "sha256:b"


def test_fork_and_rollback_rejected():
    store = LineageStore()
    store.check_and_advance("calc", "example.com", _doc("sha256:v4"))
    store.check_and_advance("calc", "example.com", _doc("sha256:v5", previous="sha256:v4"))
    # Fork from the old head.
    with pytest.raises(LineageError, match="fork or rollback"):
        store.check_and_advance("calc", "example.com", _doc("sha256:v5x", previous="sha256:v4"))
    # Missing previous_hash on a known tool.
    with pytest.raises(LineageError, match="no previous_hash"):
        store.check_and_advance("calc", "example.com", _doc("sha256:v6"))
    assert store.check_and_advance("calc", "example.com", _doc("sha256:v6"), require_chain=False) == "advanced"


def test_schema_version_must_increase():
    store = LineageStore()
    store.check_and_advance("calc", "example.com", _doc("sha256:a", version="1.9.0"))
    with pytest.raises(LineageError, match="does not increase"):
        store.check_and_advance("calc", "example.com", _doc("sha256:b", previous="sha256:a", version="1.9.0"))
    with pytest.raises(LineageError, match="does not increase"):
        store.check_and_advance("calc", "example.com", _doc("sha256:b", previous="sha256:a", version="1.2.0"))
    assert store.check_and_advance("calc", "example.com", _doc("sha256:b", previous="sha256:a", version="1.10.0")) == "advanced"
    assert version_increases("1.9.0", "1.10.0")
    assert not version_increases("2.0.0", "2.0.0")
    assert version_increases("abc", "abd")


def test_legacy_documents_refused_and_tools_isolated():
    store = LineageStore()
    with pytest.raises(LineageError, match="legacy"):
        store.check_and_advance("calc", "example.com", _doc("sha256:a", schemapin="1.3"))
    store.seed("calc", "example.com", "sha256:a", "1.0.0")
    assert store.check_and_advance("calc", "other.com", _doc("sha256:z")) == "first_use"
    restored = LineageStore.from_json(store.to_json())
    assert restored.get("calc", "example.com").schema_version == "1.0.0"
    with pytest.raises(ValueError):
        LineageStore.from_json("[]")
