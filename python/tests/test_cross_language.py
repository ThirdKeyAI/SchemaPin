"""Cross-language conformance: canonicalization corpus shared by all SDKs.

Every vector under ``tests/cross-language/canonicalization/`` is asserted by
the Python, JavaScript, Go and Rust suites. A vector with ``reject: true``
must fail to parse or canonicalize; otherwise the canonical bytes and their
SHA-256 must match exactly.
"""

import glob
import hashlib
import json
import os

import pytest

from schemapin.core import CanonicalizationError, SchemaPinCore

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
CORPUS = os.path.join(ROOT, "tests", "cross-language", "canonicalization")


def _vectors():
    paths = sorted(glob.glob(os.path.join(CORPUS, "*.json")))
    assert paths, f"no canonicalization vectors found under {CORPUS}"
    for path in paths:
        with open(path, encoding="utf-8") as f:
            yield pytest.param(json.load(f), id=os.path.basename(path))


@pytest.mark.parametrize("vector", list(_vectors()))
def test_canonicalization_vector(vector):
    if vector["reject"]:
        with pytest.raises(CanonicalizationError):
            SchemaPinCore.canonicalize_schema(
                SchemaPinCore.parse_schema_json(vector["input"])
            )
        return
    parsed = SchemaPinCore.parse_schema_json(vector["input"])
    canonical = SchemaPinCore.canonicalize_schema(parsed)
    assert canonical == vector["expected_canonical"]
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    assert digest == vector["expected_sha256"]
    # Idempotence: canonical output re-parses and re-canonicalizes identically.
    assert (
        SchemaPinCore.canonicalize_schema(SchemaPinCore.parse_schema_json(canonical))
        == canonical
    )


# ---------------------------------------------------------------------------
# Fixed ECDSA signature vector (SP-2) and key-policy fixtures (SP-10, SP-19)
# ---------------------------------------------------------------------------

SIGNATURES = os.path.join(ROOT, "tests", "cross-language", "signatures")
KEYS = os.path.join(ROOT, "tests", "cross-language", "keys")


def _load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def test_schema_signature_vector_verifies():
    from schemapin.crypto import KeyManager, SignatureManager

    v = _load_json(os.path.join(SIGNATURES, "schema-signature.json"))
    canonical = SchemaPinCore.canonicalize_schema(v["schema"])
    assert canonical == v["canonical"]
    digest = SchemaPinCore.hash_canonical(canonical)
    assert digest.hex() == v["sha256"]
    public_key = KeyManager.load_public_key_pem(v["public_key_pem"])
    assert KeyManager.calculate_key_fingerprint(public_key) == v["key_fingerprint"]
    assert SignatureManager.verify_schema_signature(digest, v["signature"], public_key)
    # Tampered schema must fail.
    tampered = SchemaPinCore.canonicalize_and_hash(v["tampered_schema"])
    assert not SignatureManager.verify_schema_signature(tampered, v["signature"], public_key)
    # DER trailing bytes must fail.
    assert not SignatureManager.verify_schema_signature(
        digest, v["signature_with_trailing_byte"], public_key
    )


@pytest.mark.parametrize("name", ["reject-p384-public.pem", "reject-rsa2048-public.pem"])
def test_non_p256_public_keys_rejected(name):
    from schemapin.crypto import KeyManager

    with open(os.path.join(KEYS, name), encoding="utf-8") as f:
        pem = f.read()
    with pytest.raises(ValueError):
        KeyManager.load_public_key_pem(pem)
    with pytest.raises(ValueError):
        KeyManager.calculate_key_fingerprint_from_pem(pem)
