"""Tests for core SchemaPin functionality."""

from schemapin.core import SchemaPinCore


class TestSchemaPinCore:
    """Test schema canonicalization and hashing."""

    def test_canonicalize_schema_basic(self):
        """Test basic schema canonicalization."""
        schema = {
            "description": "Calculates the sum",
            "name": "calculate_sum",
            "parameters": {"b": "integer", "a": "integer"}
        }
        
        expected = '{"description":"Calculates the sum","name":"calculate_sum","parameters":{"a":"integer","b":"integer"}}'
        result = SchemaPinCore.canonicalize_schema(schema)
        
        assert result == expected

    def test_canonicalize_schema_nested(self):
        """Test canonicalization with nested objects."""
        schema = {
            "name": "complex_tool",
            "parameters": {
                "config": {
                    "timeout": 30,
                    "retries": 3
                },
                "data": ["item1", "item2"]
            }
        }
        
        result = SchemaPinCore.canonicalize_schema(schema)
        
        # Should have sorted keys at all levels
        assert '"config":{"retries":3,"timeout":30}' in result
        assert result.startswith('{"name":"complex_tool"')

    def test_canonicalize_schema_unicode(self):
        """Test canonicalization with Unicode characters."""
        schema = {
            "name": "unicode_tool",
            "description": "Tool with émojis 🔧 and ñoñó"
        }
        
        result = SchemaPinCore.canonicalize_schema(schema)
        
        # Should preserve Unicode characters
        assert "émojis 🔧" in result
        assert "ñoñó" in result

    def test_hash_canonical(self):
        """Test SHA-256 hashing of canonical strings."""
        canonical = '{"name":"test","value":42}'
        hash_result = SchemaPinCore.hash_canonical(canonical)
        
        # Should return 32 bytes (256 bits)
        assert len(hash_result) == 32
        assert isinstance(hash_result, bytes)

    def test_canonicalize_and_hash(self):
        """Test combined canonicalization and hashing."""
        schema = {"name": "test", "value": 42}
        hash_result = SchemaPinCore.canonicalize_and_hash(schema)
        
        # Should return 32 bytes
        assert len(hash_result) == 32
        assert isinstance(hash_result, bytes)

    def test_canonicalization_deterministic(self):
        """Test that canonicalization is deterministic."""
        schema1 = {"b": 2, "a": 1}
        schema2 = {"a": 1, "b": 2}
        
        canonical1 = SchemaPinCore.canonicalize_schema(schema1)
        canonical2 = SchemaPinCore.canonicalize_schema(schema2)
        
        # Should produce identical results regardless of input order
        assert canonical1 == canonical2

    def test_hash_deterministic(self):
        """Test that hashing is deterministic."""
        schema = {"name": "test", "value": 42}
        
        hash1 = SchemaPinCore.canonicalize_and_hash(schema)
        hash2 = SchemaPinCore.canonicalize_and_hash(schema)
        
        # Should produce identical hashes
        assert hash1 == hash2