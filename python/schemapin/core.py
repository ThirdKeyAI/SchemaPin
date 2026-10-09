"""Core SchemaPin functionality for schema canonicalization and hashing.

This module implements the ``schemapin-v1`` canonical JSON serialization
exactly as specified in TECHNICAL_SPECIFICATION.md section 4. The rules are
deliberately strict so that every SDK produces byte-identical output:

* Object keys are sorted by Unicode code point (equivalently, by the UTF-8
  byte sequence of the key). This is *not* UTF-16 code-unit order.
* Duplicate object keys, ``NaN``/``Infinity``, lone surrogates and invalid
  UTF-8 are rejected -- they have no canonical form.
* Strings are escaped minimally: ``"`` and ``\\`` are backslash-escaped,
  U+0008/U+000C/U+000A/U+000D/U+0009 use the two-character escapes
  ``\\b \\f \\n \\r \\t``, the remaining C0 controls (U+0000--U+001F) use
  lowercase ``\\u00xx``, and every other code point (including ``<``, ``>``,
  ``&``, U+007F, U+2028 and U+2029) is emitted literally as UTF-8.
* Numbers are interpreted as IEEE-754 binary64 values. Any number whose
  absolute value exceeds 2**53 - 1 is rejected, so no two distinct inputs
  can collide after double rounding. Integral values are emitted as plain
  decimal integers (``1.0`` -> ``1``, ``-0`` -> ``0``); non-integral values
  use the ECMAScript ``Number::toString`` algorithm (RFC 8785 section
  3.2.2.3), e.g. ``1e-7``, ``0.000001``, ``123.456``.
* ``__proto__`` and other special-looking keys are ordinary keys and are
  preserved.
"""

import hashlib
import json
import math
import re
from typing import Any, Dict, List, Tuple

#: Largest integer magnitude accepted by the canonicalizer (2**53 - 1).
MAX_SAFE_INTEGER = 9007199254740991

_ESCAPES = {
    '"': '\\"',
    "\\": "\\\\",
    "\b": "\\b",
    "\f": "\\f",
    "\n": "\\n",
    "\r": "\\r",
    "\t": "\\t",
}

_FLOAT_RE = re.compile(r"^(-)?(\d+)(?:\.(\d+))?(?:e([+-]\d+))?$")


class CanonicalizationError(ValueError):
    """Raised when a value has no ``schemapin-v1`` canonical form."""


def _canonical_string(value: str) -> str:
    out: List[str] = ['"']
    for ch in value:
        cp = ord(ch)
        if 0xD800 <= cp <= 0xDFFF:
            raise CanonicalizationError(
                f"lone surrogate U+{cp:04X} has no canonical form"
            )
        esc = _ESCAPES.get(ch)
        if esc is not None:
            out.append(esc)
        elif cp < 0x20:
            out.append(f"\\u{cp:04x}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _es6_number_to_string(value: float) -> str:
    """Format a finite, non-integral binary64 per ECMAScript Number::toString."""
    text = repr(value)
    m = _FLOAT_RE.match(text)
    if m is None:  # pragma: no cover - repr() of a finite float always matches
        raise CanonicalizationError(f"cannot format number {value!r}")
    sign, int_part, frac_part, exp_part = m.groups()
    frac_part = frac_part or ""
    exp = int(exp_part) if exp_part else 0
    digits = (int_part + frac_part).lstrip("0")
    exp -= len(frac_part)
    stripped = digits.rstrip("0")
    exp += len(digits) - len(stripped)
    digits = stripped
    k = len(digits)
    n = exp + k
    if 0 < n <= 21:
        body = digits[:n] + "." + digits[n:]
    elif -6 < n <= 0:
        body = "0." + "0" * (-n) + digits
    else:
        e = n - 1
        esign = "+" if e >= 0 else "-"
        mant = digits[0] if k == 1 else digits[0] + "." + digits[1:]
        body = f"{mant}e{esign}{abs(e)}"
    return ("-" if sign else "") + body


def _canonical_number(value: Any) -> str:
    if isinstance(value, bool):
        raise CanonicalizationError("bool is not a number")
    if isinstance(value, int):
        if abs(value) > MAX_SAFE_INTEGER:
            raise CanonicalizationError(
                f"integer {value} exceeds the 2**53-1 safe range"
            )
        return str(value)
    if isinstance(value, float):
        if math.isnan(value) or math.isinf(value):
            raise CanonicalizationError("NaN and Infinity are not valid JSON")
        if abs(value) > MAX_SAFE_INTEGER:
            raise CanonicalizationError(
                f"number {value!r} exceeds the 2**53-1 safe range"
            )
        if value == int(value):
            return str(int(value))
        return _es6_number_to_string(value)
    raise CanonicalizationError(f"unsupported numeric type {type(value).__name__}")


def _canonical_value(value: Any, out: List[str]) -> None:
    if value is None:
        out.append("null")
    elif value is True:
        out.append("true")
    elif value is False:
        out.append("false")
    elif isinstance(value, str):
        out.append(_canonical_string(value))
    elif isinstance(value, (int, float)):
        out.append(_canonical_number(value))
    elif isinstance(value, dict):
        out.append("{")
        first = True
        # Keys sort by Unicode code point: Python str ordering is exactly that.
        for key in sorted(value.keys()):
            if not isinstance(key, str):
                raise CanonicalizationError(
                    f"object key must be a string, got {type(key).__name__}"
                )
            if not first:
                out.append(",")
            first = False
            out.append(_canonical_string(key))
            out.append(":")
            _canonical_value(value[key], out)
        out.append("}")
    elif isinstance(value, (list, tuple)):
        out.append("[")
        for i, item in enumerate(value):
            if i:
                out.append(",")
            _canonical_value(item, out)
        out.append("]")
    else:
        raise CanonicalizationError(
            f"unsupported value type {type(value).__name__}"
        )


def _reject_duplicate_keys(pairs: List[Tuple[str, Any]]) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    for key, val in pairs:
        if key in result:
            raise CanonicalizationError(f"duplicate object key {key!r}")
        result[key] = val
    return result


def _reject_constant(name: str) -> Any:
    raise CanonicalizationError(f"{name} is not valid JSON")


def _parse_int(text: str) -> int:
    value = int(text)
    if abs(value) > MAX_SAFE_INTEGER:
        raise CanonicalizationError(
            f"integer {text} exceeds the 2**53-1 safe range"
        )
    return value


def _parse_float(text: str) -> float:
    value = float(text)
    if math.isinf(value) or abs(value) > MAX_SAFE_INTEGER:
        raise CanonicalizationError(
            f"number {text} exceeds the 2**53-1 safe range"
        )
    return value


def _check_surrogates(value: Any) -> None:
    if isinstance(value, str):
        for ch in value:
            if 0xD800 <= ord(ch) <= 0xDFFF:
                raise CanonicalizationError(
                    f"lone surrogate U+{ord(ch):04X} is not valid"
                )
    elif isinstance(value, dict):
        for k, v in value.items():
            _check_surrogates(k)
            _check_surrogates(v)
    elif isinstance(value, list):
        for v in value:
            _check_surrogates(v)


class SchemaPinCore:
    """Core SchemaPin operations for schema canonicalization and hashing."""

    @staticmethod
    def parse_schema_json(text: str) -> Any:
        """Parse JSON text strictly for canonicalization.

        Rejects (``CanonicalizationError``): duplicate object keys,
        ``NaN``/``Infinity``, numbers outside the 2**53-1 safe range and
        lone surrogates. Everything else follows RFC 8259.
        """
        try:
            value = json.loads(
                text,
                object_pairs_hook=_reject_duplicate_keys,
                parse_constant=_reject_constant,
                parse_int=_parse_int,
                parse_float=_parse_float,
            )
        except json.JSONDecodeError as e:
            raise CanonicalizationError(f"invalid JSON: {e}") from e
        _check_surrogates(value)
        return value

    @staticmethod
    def canonicalize_schema(schema: Any) -> str:
        """Convert a schema to its ``schemapin-v1`` canonical string.

        See the module docstring for the normative rules. Raises
        ``CanonicalizationError`` when the value has no canonical form
        (duplicate keys cannot occur in a ``dict``; non-finite or oversized
        numbers, lone surrogates and non-JSON types are rejected).
        """
        out: List[str] = []
        _canonical_value(schema, out)
        return "".join(out)

    @staticmethod
    def hash_canonical(canonical: str) -> bytes:
        """Hash a canonical schema string using SHA-256."""
        return hashlib.sha256(canonical.encode("utf-8")).digest()

    @classmethod
    def canonicalize_and_hash(cls, schema: Any) -> bytes:
        """Canonicalize and hash a schema in one step."""
        canonical = cls.canonicalize_schema(schema)
        return cls.hash_canonical(canonical)
