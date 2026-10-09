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
