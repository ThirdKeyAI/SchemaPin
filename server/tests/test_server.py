"""Tests for the reference .well-known server (SP-7, design issue 11)."""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "python"))

from fastapi.testclient import TestClient  # noqa: E402

from schemapin.crypto import KeyManager  # noqa: E402
from well_known_server import ServerConfig, create_app  # noqa: E402


def _pem():
    priv, pub = KeyManager.generate_keypair()
    return KeyManager.export_public_key_pem(pub), KeyManager.calculate_key_fingerprint(pub)


@pytest.fixture
def server(tmp_path, monkeypatch):
    monkeypatch.delenv("SCHEMAPIN_ADMIN_TOKEN", raising=False)
    cfg = {
        "storage": {"keys_directory": str(tmp_path / "keys")},
        "logging": {"file": str(tmp_path / "server.log")},
        "developers": {
            "alice.example.com": {"name": "Alice", "contact": "a@example.com", "enabled": True},
            "bob.example.com": {"name": "Bob", "contact": "b@example.com", "enabled": True},
        },
        "features": {"admin_api": True},
        "security": {"admin_token": "test-admin-token", "rate_limit": {"requests_per_minute": 1000}},
        "cors": {"allow_origins": ["*"], "allow_credentials": True},
    }
    path = tmp_path / "config.json"
    path.write_text(json.dumps(cfg))
    config = ServerConfig(path, setup_logging=False)
    app = create_app(config)
    return TestClient(app, base_url="http://alice.example.com")


AUTH = {"Authorization": "Bearer test-admin-token"}


def _upload(client, domain, pem, headers=AUTH):
    return client.post(
        f"/api/developers/{domain}/keys",
        json={"public_key_pem": pem, "developer_name": "Alice", "contact": "a@example.com"},
        headers=headers,
    )


def test_defaults_are_safe(tmp_path):
    path = tmp_path / "config.json"
    path.write_text(json.dumps({"developers": {}}))
    cfg = ServerConfig(path, setup_logging=False)
    assert cfg.config["server"]["host"] == "127.0.0.1"
    assert cfg.config["server"]["debug"] is False
    assert cfg.config["server"]["reload"] is False
    assert cfg.admin_api_enabled is False
    assert cfg.admin_token is None


def test_mutations_require_bearer_token(server):
    pem, _ = _pem()
    assert _upload(server, "alice.example.com", pem, headers={}).status_code == 401
    assert _upload(server, "alice.example.com", pem, headers={"Authorization": "Bearer wrong"}).status_code == 401
    assert server.post("/api/developers/alice.example.com/revoke", json={"fingerprint": "x"}).status_code == 401
    assert _upload(server, "alice.example.com", pem).status_code == 200


def test_admin_api_can_be_disabled(tmp_path):
    cfg = {
        "storage": {"keys_directory": str(tmp_path / "keys")},
        "developers": {"alice.example.com": {"name": "A", "contact": "a@x.com"}},
        "features": {"admin_api": False},
        "security": {"admin_token": "t"},
    }
    path = tmp_path / "config.json"
    path.write_text(json.dumps(cfg))
    client = TestClient(create_app(ServerConfig(path, setup_logging=False)))
    pem, _ = _pem()
    assert _upload(client, "alice.example.com", pem, headers={"Authorization": "Bearer t"}).status_code == 404


def test_rotation_preserves_revocations_and_revokes_old_key(server):
    pem1, fp1 = _pem()
    pem2, fp2 = _pem()
    pem3, fp3 = _pem()
    assert _upload(server, "alice.example.com", pem1).status_code == 200
    assert server.post("/api/developers/alice.example.com/revoke", json={"fingerprint": "sha256:" + "ab" * 32}, headers=AUTH).status_code == 200
    assert _upload(server, "alice.example.com", pem2).status_code == 200
    info = server.get("/api/developers/alice.example.com").json()
    assert info["current_key"]["fingerprint"] == fp2
    assert "sha256:" + "ab" * 32 in info["revoked_keys"], "upload must not wipe revocations"
    assert fp1 in info["revoked_keys"], "rotation must revoke the previous key"
    # A revoked key cannot be re-uploaded.
    assert _upload(server, "alice.example.com", pem1).status_code == 400
    wk = server.get("/.well-known/schemapin.json").json()
    assert wk["public_key_pem"] == pem2
    assert fp1 in wk["revoked_keys"]
    assert _upload(server, "alice.example.com", pem3).status_code == 200


def test_well_known_is_selected_by_host_with_no_fallback(server):
    pem_a, _ = _pem()
    pem_b, _ = _pem()
    assert _upload(server, "alice.example.com", pem_a).status_code == 200
    assert _upload(server, "bob.example.com", pem_b).status_code == 200
    assert server.get("/.well-known/schemapin.json", headers={"host": "alice.example.com"}).json()["public_key_pem"] == pem_a
    assert server.get("/.well-known/schemapin.json", headers={"host": "bob.example.com:8443"}).json()["public_key_pem"] == pem_b
    assert server.get("/.well-known/schemapin.json", headers={"host": "carol.example.com"}).status_code == 404
    assert server.get("/.well-known/schemapin.json", headers={"host": "127.0.0.1"}).status_code == 404
    # Multi-tenant path still works and validates the domain.
    assert server.get("/.well-known/schemapin/bob.example.com.json").json()["public_key_pem"] == pem_b
    assert server.get("/.well-known/schemapin/..%2F..%2Fetc.json").status_code == 404


def test_non_p256_keys_are_rejected(server):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    rsa_pem = (
        rsa.generate_private_key(public_exponent=65537, key_size=2048)
        .public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        .decode()
    )
    assert _upload(server, "alice.example.com", rsa_pem).status_code == 400


def test_cors_wildcard_never_sends_credentials(server):
    r = server.options(
        "/.well-known/schemapin.json",
        headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "GET"},
    )
    assert r.headers.get("access-control-allow-origin") == "*"
    assert "access-control-allow-credentials" not in r.headers


def test_rate_limit(tmp_path):
    cfg = {
        "storage": {"keys_directory": str(tmp_path / "keys")},
        "developers": {},
        "security": {"rate_limit": {"requests_per_minute": 3}},
    }
    path = tmp_path / "config.json"
    path.write_text(json.dumps(cfg))
    client = TestClient(create_app(ServerConfig(path, setup_logging=False)))
    codes = [client.get("/health").status_code for _ in range(5)]
    assert codes == [200, 200, 200, 429, 429]
