"""Core SchemaPin functionality for schema canonicalization and hashing."""

import hashlib
import json
from typing import Any, Dict


class SchemaPinCore:
    """Core SchemaPin operations for schema canonicalization and hashing."""

    @staticmethod
    def canonicalize_schema(schema: Dict[str, Any]) -> str:
        """
        Convert a schema to canonical string format per SchemaPin specification.

        Process:
        1. UTF-8 encoding
        2. Remove insignificant whitespace
        3. Sort keys lexicographically (recursive)
        4. Strict JSON serialization

        Args:
            schema: Tool schema as dictionary

        Returns:
            Canonical string representation
        """
        return json.dumps(schema, ensure_ascii=False, separators=(',', ':'), sort_keys=True)

    @staticmethod
    def hash_canonical(canonical: str) -> bytes:
        """
        Hash canonical schema string using SHA-256.

        Args:
            canonical: Canonical schema string

        Returns:
            SHA-256 hash bytes
        """
        return hashlib.sha256(canonical.encode('utf-8')).digest()

    @classmethod
    def canonicalize_and_hash(cls, schema: Dict[str, Any]) -> bytes:
        """
        Convenience method to canonicalize and hash schema in one step.

        Args:
            schema: Tool schema as dictionary

        Returns:
            SHA-256 hash of canonical schema
        """
        canonical = cls.canonicalize_schema(schema)
        return cls.hash_canonical(canonical)
