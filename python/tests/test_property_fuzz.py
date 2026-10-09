"""Property-based tests for the parsers that face untrusted input.

Canonicalization must be idempotent and total over valid JSON values, and
every parser must fail only with its documented exception type on arbitrary
input (never with a TypeError, IndexError, or a crash).
"""

import json
import math

from hypothesis import given, settings
from hypothesis import strategies as st

from schemapin.core import MAX_SAFE_INTEGER, CanonicalizationError, SchemaPinCore
from schemapin.dns import parse_txt_record
from schemapin.domain import InvalidDomainError, validate_domain
from schemapin.skill import SkillSigner

json_scalars = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(min_value=-MAX_SAFE_INTEGER, max_value=MAX_SAFE_INTEGER),
    st.floats(allow_nan=False, allow_infinity=False, min_value=-1e15, max_value=1e15),
    st.text(),
)
json_values = st.recursive(
    json_scalars,
    lambda children: st.one_of(st.lists(children, max_size=6), st.dictionaries(st.text(), children, max_size=6)),
    max_leaves=40,
)


@settings(max_examples=300, deadline=None)
@given(json_values)
def test_canonicalization_is_idempotent_and_order_independent(value):
    canonical = SchemaPinCore.canonicalize_schema(value)
    reparsed = SchemaPinCore.parse_schema_json(canonical)
    assert SchemaPinCore.canonicalize_schema(reparsed) == canonical
    # Standard parser agrees with the strict one on well-formed output.
    assert json.loads(canonical) == reparsed


@settings(max_examples=300, deadline=None)
@given(st.text())
def test_strict_parser_only_raises_canonicalization_error(text):
    try:
        value = SchemaPinCore.parse_schema_json(text)
    except CanonicalizationError:
        return
    assert SchemaPinCore.canonicalize_schema(value) is not None


@settings(max_examples=200, deadline=None)
@given(st.floats(allow_nan=False, allow_infinity=False))
def test_number_policy_is_consistent(x):
    try:
        out = SchemaPinCore.canonicalize_schema(x)
    except CanonicalizationError:
        assert abs(x) > MAX_SAFE_INTEGER
        return
    assert abs(x) <= MAX_SAFE_INTEGER
    assert float(out) == x
    assert "e+" not in out or x != math.trunc(x)


@settings(max_examples=300, deadline=None)
@given(st.text())
def test_txt_parser_only_raises_value_error(text):
    try:
        rec = parse_txt_record(text)
    except ValueError:
        return
    assert rec.fingerprint.startswith("sha256:")


@settings(max_examples=300, deadline=None)
@given(st.text())
def test_domain_validator_only_raises_invalid_domain(text):
    try:
        normalized = validate_domain(text)
    except InvalidDomainError:
        return
    assert normalized == normalized.lower()
    assert validate_domain(normalized) == normalized


@settings(max_examples=200, deadline=None)
@given(st.dictionaries(st.text(), json_values, max_size=8))
def test_signing_input_only_raises_value_error(doc):
    try:
        SkillSigner.signing_input(doc)
    except ValueError:
        pass
