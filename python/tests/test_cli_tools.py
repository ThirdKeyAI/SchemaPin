"""Tests for SchemaPin CLI tools."""

import json
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from schemapin.crypto import KeyManager


class TestKeygenCLI:
    """Tests for keygen CLI tool."""

    def test_keygen_ecdsa_basic(self):
        """Test basic ECDSA key generation."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)

            # Run keygen
            result = subprocess.run([
                sys.executable, "-m", "tools.keygen",
                "--type", "ecdsa",
                "--output-dir", str(tmpdir_path),
                "--json"
            ], capture_output=True, text=True)

            assert result.returncode == 0
            output = json.loads(result.stdout)

            assert output["key_type"] == "ecdsa"
            assert output["key_size"] == 256
            assert output["format"] == "pem"
            assert "fingerprint" in output
            assert output["fingerprint"].startswith("sha256:")

            # Check files exist
            private_key_file = Path(output["private_key_file"])
            public_key_file = Path(output["public_key_file"])

            assert private_key_file.exists()
            assert public_key_file.exists()

            # Validate key content
            private_key_pem = private_key_file.read_text()
            public_key_pem = public_key_file.read_text()

            assert "BEGIN PRIVATE KEY" in private_key_pem
            assert "BEGIN PUBLIC KEY" in public_key_pem

            # Validate fingerprint
            calculated_fingerprint = KeyManager.calculate_key_fingerprint_from_pem(public_key_pem)
            assert calculated_fingerprint == output["fingerprint"]

    def test_keygen_rsa_basic(self):
        """Test basic RSA key generation."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)

            # Run keygen
            result = subprocess.run([
                sys.executable, "-m", "tools.keygen",
                "--type", "rsa",
                "--key-size", "2048",
                "--output-dir", str(tmpdir_path),
                "--json"
            ], capture_output=True, text=True, )

            assert result.returncode == 0
            output = json.loads(result.stdout)

            assert output["key_type"] == "rsa"
            assert output["key_size"] == 2048
            assert output["format"] == "pem"
            assert "fingerprint" in output
            assert output["fingerprint"].startswith("sha256:")

    def test_keygen_well_known_template(self):
        """Test .well-known template generation."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)

            # Run keygen with well-known template
            result = subprocess.run([
                sys.executable, "-m", "tools.keygen",
                "--type", "ecdsa",
                "--output-dir", str(tmpdir_path),
                "--well-known",
                "--developer", "Test Developer",
                "--contact", "test@example.com",
                "--json"
            ], capture_output=True, text=True, )

            assert result.returncode == 0
            output = json.loads(result.stdout)

            # Check well-known file
            well_known_file = Path(output["well_known_file"])
            assert well_known_file.exists()

            well_known_data = json.loads(well_known_file.read_text())
            assert well_known_data["developer_name"] == "Test Developer"
            assert well_known_data["contact"] == "test@example.com"
            assert well_known_data["schema_version"] == "1.1"
            assert "public_key_pem" in well_known_data

    def test_keygen_invalid_args(self):
        """Test keygen with invalid arguments."""
        # Missing developer for well-known
        result = subprocess.run([
            sys.executable, "-m", "tools.keygen",
            "--well-known"
        ], capture_output=True, text=True, )

        assert result.returncode != 0
        assert "developer is required" in result.stderr.lower()


class TestSchemaSigner:
    """Tests for schema-signer CLI tool."""

    def setup_method(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.temp_path = Path(self.temp_dir)

        # Generate test key pair
        private_key, public_key = KeyManager.generate_keypair()
        self.private_key_pem = KeyManager.export_private_key_pem(private_key)
        self.public_key_pem = KeyManager.export_public_key_pem(public_key)

        # Write private key file
        self.private_key_file = self.temp_path / "private.pem"
        self.private_key_file.write_text(self.private_key_pem)

        # Create test schema
        self.test_schema = {
            "type": "object",
            "properties": {
                "name": {"type": "string"}
            }
        }
        self.schema_file = self.temp_path / "schema.json"
        self.schema_file.write_text(json.dumps(self.test_schema, indent=2))

    def test_sign_single_schema(self):
        """Test signing a single schema."""
        output_file = self.temp_path / "signed_schema.json"

        result = subprocess.run([
            sys.executable, "-m", "tools.schema_signer",
            "--key", str(self.private_key_file),
            "--schema", str(self.schema_file),
            "--output", str(output_file),
            "--developer", "Test Developer"
        ], capture_output=True, text=True, )

        assert result.returncode == 0
        assert output_file.exists()

        # Validate signed schema
        signed_schema = json.loads(output_file.read_text())
        assert "schema" in signed_schema
        assert "signature" in signed_schema
        assert "signed_at" in signed_schema
        assert "metadata" in signed_schema
        assert signed_schema["metadata"]["developer"] == "Test Developer"
        assert signed_schema["schema"] == self.test_schema

    def test_sign_stdin(self):
        """Test signing schema from stdin."""
        result = subprocess.run([
            sys.executable, "-m", "tools.schema_signer",
            "--key", str(self.private_key_file),
            "--stdin"
        ], input=json.dumps(self.test_schema), capture_output=True, text=True, )

        assert result.returncode == 0

        # Parse output
        signed_schema = json.loads(result.stdout)
        assert "schema" in signed_schema
        assert "signature" in signed_schema
        assert signed_schema["schema"] == self.test_schema

    def test_sign_batch(self):
        """Test batch signing of schemas."""
        # Create multiple schema files
        schemas_dir = self.temp_path / "schemas"
        schemas_dir.mkdir()
        output_dir = self.temp_path / "signed"

        for i in range(3):
            schema_file = schemas_dir / f"schema_{i}.json"
            schema_file.write_text(json.dumps({
                "type": "object",
                "properties": {"id": {"type": "integer", "const": i}}
            }))

        result = subprocess.run([
            sys.executable, "-m", "tools.schema_signer",
            "--key", str(self.private_key_file),
            "--batch", str(schemas_dir),
            "--output-dir", str(output_dir),
            "--json"
        ], capture_output=True, text=True, )

        assert result.returncode == 0

        # Check results
        output = json.loads(result.stdout)
        assert output["total"] == 3
        assert output["successful"] == 3
        assert output["failed"] == 0

        # Check output files
        for i in range(3):
            signed_file = output_dir / f"schema_{i}_signed.json"
            assert signed_file.exists()


class TestVerifySchema:
    """Tests for verify-schema CLI tool."""

    def setup_method(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.temp_path = Path(self.temp_dir)

        # Generate test key pair
        private_key, public_key = KeyManager.generate_keypair()
        self.private_key_pem = KeyManager.export_private_key_pem(private_key)
        self.public_key_pem = KeyManager.export_public_key_pem(public_key)

        # Write public key file
        self.public_key_file = self.temp_path / "public.pem"
        self.public_key_file.write_text(self.public_key_pem)

        # Create and sign test schema
        from schemapin.utils import SchemaSigningWorkflow
        self.test_schema = {
            "type": "object",
            "properties": {"name": {"type": "string"}}
        }

        workflow = SchemaSigningWorkflow(self.private_key_pem)
        signature = workflow.sign_schema(self.test_schema)

        self.signed_schema = {
            "schema": self.test_schema,
            "signature": signature,
            "signed_at": "2024-01-01T00:00:00Z"
        }

        self.signed_schema_file = self.temp_path / "signed_schema.json"
        self.signed_schema_file.write_text(json.dumps(self.signed_schema, indent=2))

    def test_verify_with_public_key(self):
        """Test verification with public key."""
        result = subprocess.run([
            sys.executable, "-m", "tools.verify_schema",
            "--schema", str(self.signed_schema_file),
            "--public-key", str(self.public_key_file),
            "--json"
        ], capture_output=True, text=True, )

        assert result.returncode == 0

        output = json.loads(result.stdout)
        assert output["total"] == 1
        assert output["valid"] == 1
        assert output["invalid"] == 0

        result_data = output["results"][0]
        assert result_data["valid"] is True
        assert result_data["verification_method"] == "public_key"
        assert "key_fingerprint" in result_data

    @patch('schemapin.discovery.PublicKeyDiscovery.get_public_key_pem')
    def test_verify_with_discovery(self, mock_get_key):
        """Test verification with discovery."""
        mock_get_key.return_value = self.public_key_pem

        # Test the underlying function directly instead of subprocess
        from tools.verify_schema import verify_with_discovery

        result = verify_with_discovery(
            schema=self.test_schema,
            signature=self.signed_schema["signature"],
            domain="example.com",
            tool_id="test-tool"
        )

        assert result["valid"] is True
        assert result["verification_method"] == "discovery"
        assert result.get("error") is None

    def test_verify_stdin(self):
        """Test verification from stdin."""
        result = subprocess.run([
            sys.executable, "-m", "tools.verify_schema",
            "--stdin",
            "--public-key", str(self.public_key_file),
            "--json"
        ], input=json.dumps(self.signed_schema), capture_output=True, text=True, )

        assert result.returncode == 0

        output = json.loads(result.stdout)
        assert output["total"] == 1
        assert output["valid"] == 1

    def test_verify_invalid_signature(self):
        """Test verification with invalid signature."""
        # Create schema with invalid signature
        invalid_signed_schema = self.signed_schema.copy()
        invalid_signed_schema["signature"] = "invalid_signature"

        invalid_file = self.temp_path / "invalid_signed_schema.json"
        invalid_file.write_text(json.dumps(invalid_signed_schema))

        result = subprocess.run([
            sys.executable, "-m", "tools.verify_schema",
            "--schema", str(invalid_file),
            "--public-key", str(self.public_key_file),
            "--json"
        ], capture_output=True, text=True, )

        assert result.returncode == 0

        output = json.loads(result.stdout)
        assert output["total"] == 1
        assert output["valid"] == 0
        assert output["invalid"] == 1

        result_data = output["results"][0]
        assert result_data["valid"] is False

    def test_verify_exit_code_on_failure(self):
        """Test exit code behavior on verification failure."""
        # Create schema with invalid signature
        invalid_signed_schema = self.signed_schema.copy()
        invalid_signed_schema["signature"] = "invalid_signature"

        invalid_file = self.temp_path / "invalid_signed_schema.json"
        invalid_file.write_text(json.dumps(invalid_signed_schema))

        result = subprocess.run([
            sys.executable, "-m", "tools.verify_schema",
            "--schema", str(invalid_file),
            "--public-key", str(self.public_key_file),
            "--exit-code"
        ], capture_output=True, text=True, )

        assert result.returncode == 1


class TestCLIIntegration:
    """Integration tests for CLI tools working together."""

    def test_full_workflow(self):
        """Test complete workflow: keygen -> sign -> verify."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)

            # Step 1: Generate keys
            keygen_result = subprocess.run([
                sys.executable, "-m", "tools.keygen",
                "--type", "ecdsa",
                "--output-dir", str(tmpdir_path),
                "--developer", "Test Developer",
                "--well-known",
                "--json"
            ], capture_output=True, text=True, )

            assert keygen_result.returncode == 0
            keygen_output = json.loads(keygen_result.stdout)

            private_key_file = keygen_output["private_key_file"]
            public_key_file = keygen_output["public_key_file"]

            # Step 2: Create and sign schema
            test_schema = {
                "type": "object",
                "properties": {"name": {"type": "string"}}
            }
            schema_file = tmpdir_path / "test_schema.json"
            schema_file.write_text(json.dumps(test_schema))

            signed_schema_file = tmpdir_path / "signed_schema.json"

            sign_result = subprocess.run([
                sys.executable, "-m", "tools.schema_signer",
                "--key", private_key_file,
                "--schema", str(schema_file),
                "--output", str(signed_schema_file),
                "--developer", "Test Developer"
            ], capture_output=True, text=True, )

            assert sign_result.returncode == 0
            assert signed_schema_file.exists()

            # Step 3: Verify signed schema
            verify_result = subprocess.run([
                sys.executable, "-m", "tools.verify_schema",
                "--schema", str(signed_schema_file),
                "--public-key", public_key_file,
                "--json"
            ], capture_output=True, text=True, )

            assert verify_result.returncode == 0
            verify_output = json.loads(verify_result.stdout)

            assert verify_output["total"] == 1
            assert verify_output["valid"] == 1
            assert verify_output["results"][0]["valid"] is True


if __name__ == "__main__":
    pytest.main([__file__])
