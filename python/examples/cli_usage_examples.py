#!/usr/bin/env python3
"""
SchemaPin CLI Tools Usage Examples

This file demonstrates common workflows using the SchemaPin CLI tools:
- schemapin-keygen: Generate cryptographic key pairs
- schemapin-sign: Sign JSON schemas
- schemapin-verify: Verify signed schemas

Run this script to see example commands and their outputs.
"""

import json
import subprocess
import sys
import tempfile
from pathlib import Path


def run_command(cmd, input_data=None, show_output=True):
    """Run a command and optionally display output."""
    print(f"\n$ {' '.join(cmd)}")

    try:
        result = subprocess.run(
            cmd,
            input=input_data,
            capture_output=True,
            text=True,
            cwd="python"
        )

        if show_output and result.stdout:
            print(result.stdout)

        if result.stderr:
            print(f"Error: {result.stderr}", file=sys.stderr)

        return result
    except Exception as e:
        print(f"Failed to run command: {e}")
        return None


def example_key_generation():
    """Demonstrate key generation examples."""
    print("\n" + "="*60)
    print("KEY GENERATION EXAMPLES")
    print("="*60)

    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir_path = Path(tmpdir)

        print("\n1. Generate ECDSA key pair with .well-known template:")
        run_command([
            sys.executable, "-m", "tools.keygen",
            "--type", "ecdsa",
            "--output-dir", str(tmpdir_path),
            "--developer", "Example Corp",
            "--contact", "security@example.com",
            "--well-known",
            "--verbose"
        ])

        print("\n2. Generate RSA 4096-bit key pair:")
        run_command([
            sys.executable, "-m", "tools.keygen",
            "--type", "rsa",
            "--key-size", "4096",
            "--output-dir", str(tmpdir_path),
            "--prefix", "rsa_keys",
            "--json"
        ])

        print("\n3. Generate keys in DER format:")
        run_command([
            sys.executable, "-m", "tools.keygen",
            "--type", "ecdsa",
            "--format", "der",
            "--output-dir", str(tmpdir_path),
            "--prefix", "der_keys"
        ])


def example_schema_signing():
    """Demonstrate schema signing examples."""
    print("\n" + "="*60)
    print("SCHEMA SIGNING EXAMPLES")
    print("="*60)

    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir_path = Path(tmpdir)

        # Generate keys first
        print("\nGenerating keys for signing examples...")
        keygen_result = run_command([
            sys.executable, "-m", "tools.keygen",
            "--type", "ecdsa",
            "--output-dir", str(tmpdir_path),
            "--json"
        ], show_output=False)

        if not keygen_result or keygen_result.returncode != 0:
            print("Failed to generate keys for examples")
            return

        keygen_output = json.loads(keygen_result.stdout)
        private_key_file = keygen_output["private_key_file"]

        # Create example schemas
        example_schema = {
            "type": "object",
            "properties": {
                "name": {"type": "string"},
                "age": {"type": "integer", "minimum": 0}
            },
            "required": ["name"]
        }

        schema_file = tmpdir_path / "example_schema.json"
        schema_file.write_text(json.dumps(example_schema, indent=2))

        # Create multiple schemas for batch example
        schemas_dir = tmpdir_path / "schemas"
        schemas_dir.mkdir()

        for i in range(3):
            schema = {
                "type": "object",
                "properties": {
                    "id": {"type": "integer", "const": i},
                    "data": {"type": "string"}
                }
            }
            (schemas_dir / f"schema_{i}.json").write_text(json.dumps(schema))

        print("\n1. Sign a single schema with metadata:")
        run_command([
            sys.executable, "-m", "tools.schema-signer",
            "--key", private_key_file,
            "--schema", str(schema_file),
            "--output", str(tmpdir_path / "signed_schema.json"),
            "--developer", "Example Corp",
            "--version", "1.0.0",
            "--description", "Example user schema"
        ])

        print("\n2. Sign schema from stdin:")
        run_command([
            sys.executable, "-m", "tools.schema-signer",
            "--key", private_key_file,
            "--stdin"
        ], input_data=json.dumps(example_schema))

        print("\n3. Batch sign multiple schemas:")
        run_command([
            sys.executable, "-m", "tools.schema-signer",
            "--key", private_key_file,
            "--batch", str(schemas_dir),
            "--output-dir", str(tmpdir_path / "signed_schemas"),
            "--developer", "Example Corp",
            "--json"
        ])


def example_schema_verification():
    """Demonstrate schema verification examples."""
    print("\n" + "="*60)
    print("SCHEMA VERIFICATION EXAMPLES")
    print("="*60)

    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir_path = Path(tmpdir)

        # Generate keys and sign a schema
        print("\nSetting up signed schema for verification examples...")

        # Generate keys
        keygen_result = run_command([
            sys.executable, "-m", "tools.keygen",
            "--type", "ecdsa",
            "--output-dir", str(tmpdir_path),
            "--json"
        ], show_output=False)

        if not keygen_result or keygen_result.returncode != 0:
            print("Failed to generate keys")
            return

        keygen_output = json.loads(keygen_result.stdout)
        private_key_file = keygen_output["private_key_file"]
        public_key_file = keygen_output["public_key_file"]

        # Create and sign schema
        example_schema = {
            "type": "object",
            "properties": {"message": {"type": "string"}}
        }

        schema_file = tmpdir_path / "example_schema.json"
        schema_file.write_text(json.dumps(example_schema))

        signed_schema_file = tmpdir_path / "signed_schema.json"

        sign_result = run_command([
            sys.executable, "-m", "tools.schema-signer",
            "--key", private_key_file,
            "--schema", str(schema_file),
            "--output", str(signed_schema_file),
            "--developer", "Example Corp"
        ], show_output=False)

        if not sign_result or sign_result.returncode != 0:
            print("Failed to sign schema")
            return

        print("\n1. Verify schema with public key:")
        run_command([
            sys.executable, "-m", "tools.verify-schema",
            "--schema", str(signed_schema_file),
            "--public-key", public_key_file,
            "--verbose"
        ])

        print("\n2. Verify schema with JSON output:")
        run_command([
            sys.executable, "-m", "tools.verify-schema",
            "--schema", str(signed_schema_file),
            "--public-key", public_key_file,
            "--json"
        ])

        print("\n3. Verify schema from stdin:")
        signed_schema_content = Path(signed_schema_file).read_text()
        run_command([
            sys.executable, "-m", "tools.verify-schema",
            "--stdin",
            "--public-key", public_key_file
        ], input_data=signed_schema_content)

        # Create multiple signed schemas for batch verification
        signed_schemas_dir = tmpdir_path / "signed_schemas"
        signed_schemas_dir.mkdir()

        for i in range(3):
            schema = {"type": "object", "properties": {"id": {"const": i}}}
            schema_file = tmpdir_path / f"temp_schema_{i}.json"
            schema_file.write_text(json.dumps(schema))

            signed_file = signed_schemas_dir / f"signed_schema_{i}.json"
            run_command([
                sys.executable, "-m", "tools.schema-signer",
                "--key", private_key_file,
                "--schema", str(schema_file),
                "--output", str(signed_file)
            ], show_output=False)

        print("\n4. Batch verify multiple schemas:")
        run_command([
            sys.executable, "-m", "tools.verify-schema",
            "--batch", str(signed_schemas_dir),
            "--public-key", public_key_file,
            "--verbose"
        ])


def example_discovery_verification():
    """Demonstrate discovery-based verification (mock example)."""
    print("\n" + "="*60)
    print("DISCOVERY-BASED VERIFICATION EXAMPLES")
    print("="*60)

    print("\nNote: These examples show the command syntax.")
    print("In real usage, the domain would need to serve .well-known/schemapin.json")

    print("\n1. Verify with domain discovery:")
    print("$ schemapin-verify --schema signed_schema.json --domain example.com --tool-id my-tool")

    print("\n2. Verify with interactive pinning:")
    print("$ schemapin-verify --schema signed_schema.json --domain example.com --tool-id my-tool --interactive")

    print("\n3. Verify with auto-pinning:")
    print("$ schemapin-verify --schema signed_schema.json --domain example.com --tool-id my-tool --auto-pin")

    print("\n4. Verify with custom pinning database:")
    print("$ schemapin-verify --schema signed_schema.json --domain example.com --tool-id my-tool --pinning-db ./my_pins.db")


def example_advanced_workflows():
    """Demonstrate advanced CLI workflows."""
    print("\n" + "="*60)
    print("ADVANCED WORKFLOW EXAMPLES")
    print("="*60)

    print("\n1. Complete developer workflow:")
    print("# Generate keys")
    print("$ schemapin-keygen --type ecdsa --developer 'My Company' --well-known")
    print()
    print("# Sign multiple schemas")
    print("$ schemapin-sign --key schemapin_private.pem --batch ./schemas/ --output-dir ./signed/ --developer 'My Company'")
    print()
    print("# Verify all signed schemas")
    print("$ schemapin-verify --batch ./signed/ --public-key schemapin_public.pem --exit-code")

    print("\n2. Client verification workflow:")
    print("# Verify with discovery and pinning")
    print("$ schemapin-verify --schema tool_schema.json --domain tool-provider.com --tool-id awesome-tool --interactive")
    print()
    print("# Batch verify with auto-pinning")
    print("$ schemapin-verify --batch ./downloaded_schemas/ --domain tool-provider.com --auto-pin")

    print("\n3. CI/CD integration:")
    print("# Verify schemas in CI pipeline")
    print("$ schemapin-verify --batch ./schemas/ --public-key ./keys/public.pem --json --exit-code > verification_results.json")
    print()
    print("# Sign schemas for release")
    print("$ schemapin-sign --batch ./schemas/ --key $SIGNING_KEY --output-dir ./release/signed/ --version $VERSION")

    print("\n4. Key rotation workflow:")
    print("# Generate new keys")
    print("$ schemapin-keygen --type ecdsa --developer 'My Company' --well-known --output-dir ./new_keys/")
    print()
    print("# Update .well-known with revoked keys list")
    print("# (Manual step: update .well-known/schemapin.json with revoked_keys array)")
    print()
    print("# Re-sign schemas with new key")
    print("$ schemapin-sign --batch ./schemas/ --key ./new_keys/schemapin_private.pem --output-dir ./resigned/")


def main():
    """Run all CLI examples."""
    print("SchemaPin CLI Tools Usage Examples")
    print("=" * 60)
    print("This script demonstrates common usage patterns for SchemaPin CLI tools.")
    print("All examples use temporary directories and generated test data.")

    try:
        example_key_generation()
        example_schema_signing()
        example_schema_verification()
        example_discovery_verification()
        example_advanced_workflows()

        print("\n" + "="*60)
        print("EXAMPLES COMPLETED")
        print("="*60)
        print("\nFor more information, run:")
        print("  schemapin-keygen --help")
        print("  schemapin-sign --help")
        print("  schemapin-verify --help")

    except KeyboardInterrupt:
        print("\nExamples interrupted by user.")
    except Exception as e:
        print(f"\nError running examples: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
