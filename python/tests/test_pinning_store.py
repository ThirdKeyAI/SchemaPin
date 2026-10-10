"""Regression tests for the legacy KeyPinning store (SP-15)."""

import os
import sqlite3
import warnings

import pytest

from schemapin.pinning import KeyPinning, PinningMode

PEM_A = "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----"
PEM_B = "-----BEGIN PUBLIC KEY-----\nBBBB\n-----END PUBLIC KEY-----"


def _store(tmp_path):
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        return KeyPinning(db_path=str(tmp_path / "pins.db"), mode=PinningMode.AUTOMATIC)


def test_pins_are_bound_to_domain(tmp_path):
    store = _store(tmp_path)
    assert store.pin_key("calculator", PEM_A, "evil.com")
    # The attacker's pin must not satisfy a lookup for a different domain.
    assert store.get_pinned_key("calculator", "good.com") is None
    assert not store.is_key_pinned("calculator", "good.com")
    assert store.get_pinned_key("calculator", "evil.com") == PEM_A
    # The same tool id can be pinned independently per domain.
    assert store.pin_key("calculator", PEM_B, "good.com")
    assert store.get_pinned_key("calculator", "good.com") == PEM_B
    # The deprecated domain-less lookup refuses to guess between domains.
    assert store.get_pinned_key("calculator") is None
    assert store.remove_pinned_key("calculator", "evil.com")
    assert store.get_pinned_key("calculator") == PEM_B


def test_legacy_schema_is_migrated(tmp_path):
    db = tmp_path / "legacy.db"
    with sqlite3.connect(db) as conn:
        conn.execute(
            """CREATE TABLE pinned_keys (
                tool_id TEXT PRIMARY KEY, public_key_pem TEXT NOT NULL, domain TEXT NOT NULL,
                developer_name TEXT, pinned_at TEXT NOT NULL, last_verified TEXT)"""
        )
        conn.execute(
            "INSERT INTO pinned_keys VALUES (?, ?, ?, ?, ?, NULL)",
            ("calc", PEM_A, "example.com", "Dev", "2026-01-01T00:00:00+00:00"),
        )
        conn.commit()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        store = KeyPinning(db_path=str(db))
    assert store.get_pinned_key("calc", "example.com") == PEM_A
    with sqlite3.connect(db) as conn:
        sql = conn.execute(
            "SELECT sql FROM sqlite_master WHERE name='pinned_keys'"
        ).fetchone()[0]
    assert "PRIMARY KEY (tool_id, domain)" in sql
    # A second domain for the same tool now coexists.
    assert store.pin_key("calc", PEM_B, "other.com")


@pytest.mark.skipif(os.name != "posix", reason="POSIX permissions")
def test_store_file_is_owner_only(tmp_path):
    store = _store(tmp_path)
    assert oct(os.stat(store.db_path).st_mode & 0o777) == "0o600"


def test_constructor_emits_deprecation_warning(tmp_path):
    with pytest.warns(DeprecationWarning):
        KeyPinning(db_path=str(tmp_path / "x.db"))
