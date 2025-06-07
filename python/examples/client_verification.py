#!/usr/bin/env python3
"""Example client verification workflow for validating signed schemas."""

import json
import sys
from pathlib import Path
from unittest.mock import patch

# Add the parent directory to the path so we can import schemapin
sys.path.insert(0, str(Path(__file__).parent.parent))

from schemapin.utils import SchemaVerificationWorkflow


def mock_well_known_server(domain: str):
    """Mock .well-known server response for demonstration."""
    # In a real scenario, this would be fetched from the actual domain
    if domain == "example.com":
        # Load the demo well-known response if it exists
        try:
            with open("demo_well_known.json") as f:
                return json.load(f)
        except FileNotFoundError:
            return {
                "schema_version": "1.0",
                "developer_name": "Example Tool Developer",
                "public_key_pem": "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...\n-----END PUBLIC KEY-----",
                "contact": "developer@example.com"
            }
    return None


def main():
    """Demonstrate client verification workflow."""
    print("SchemaPin Client Verification Example")
    print("=" * 45)

    # Check if we have demo files from tool developer example
    schema_file = Path("demo_schema_signed.json")
    well_known_file = Path("demo_well_known.json")

    if not schema_file.exists():
        print("❌ demo_schema_signed.json not found!")
        print("Please run tool_developer.py first to generate demo files.")
        return

    # Load signed schema
    print("\n1. Loading signed schema...")
    with open(schema_file) as f:
        schema_data = json.load(f)

    schema = schema_data["schema"]
    signature = schema_data["signature"]

    print("✓ Signed schema loaded")
    print(f"Schema: {schema['name']} - {schema['description']}")
    print(f"Signature: {signature[:32]}...")

    # Load well-known response for mocking
    well_known_data = None
    if well_known_file.exists():
        with open(well_known_file) as f:
            well_known_data = json.load(f)

    # Step 2: Initialize verification workflow
    print("\n2. Initializing verification workflow...")
    verification_workflow = SchemaVerificationWorkflow()
    print("✓ Verification workflow initialized")

    # Step 3: Mock the discovery service for demonstration
    print("\n3. Simulating public key discovery...")

    def mock_get_public_key_pem(domain, timeout=10):
        if domain == "example.com" and well_known_data:
            return well_known_data["public_key_pem"]
        return None

    def mock_get_developer_info(domain, timeout=10):
        if domain == "example.com" and well_known_data:
            return {
                "developer_name": well_known_data.get("developer_name", "Unknown"),
                "schema_version": well_known_data.get("schema_version", "1.0"),
                "contact": well_known_data.get("contact", ""),
            }
        return None

    # Patch the discovery methods
    with patch.object(verification_workflow.discovery, 'get_public_key_pem', mock_get_public_key_pem), \
         patch.object(verification_workflow.discovery, 'get_developer_info', mock_get_developer_info):

        # Step 4: First-time verification (key pinning)
        print("\n4. First-time verification (TOFU - Trust On First Use)...")

        result = verification_workflow.verify_schema(
            schema=schema,
            signature_b64=signature,
            tool_id="example.com/calculate_sum",
            domain="example.com",
            auto_pin=True
        )

        print(f"✓ Verification result: {result}")

        if result['valid']:
            print("✅ Schema signature is VALID")
            if result['first_use']:
                print("🔑 Key pinned for future use")
                if result['developer_info']:
                    dev_info = result['developer_info']
                    print(f"📋 Developer: {dev_info['developer_name']}")
                    print(f"📧 Contact: {dev_info['contact']}")
        else:
            print("❌ Schema signature is INVALID")
            if result['error']:
                print(f"Error: {result['error']}")

        # Step 5: Subsequent verification (using pinned key)
        print("\n5. Subsequent verification (using pinned key)...")

        result2 = verification_workflow.verify_schema(
            schema=schema,
            signature_b64=signature,
            tool_id="example.com/calculate_sum",
            domain="example.com"
        )

        print(f"✓ Verification result: {result2}")

        if result2['valid']:
            print("✅ Schema signature is VALID (using pinned key)")
            print("🔒 Key was already pinned - no network request needed")
        else:
            print("❌ Schema signature is INVALID")

    # Step 6: Show pinned keys
    print("\n6. Listing pinned keys...")
    pinned_keys = verification_workflow.pinning.list_pinned_keys()

    if pinned_keys:
        print("✓ Pinned keys:")
        for key_info in pinned_keys:
            print(f"  - Tool: {key_info['tool_id']}")
            print(f"    Domain: {key_info['domain']}")
            print(f"    Developer: {key_info['developer_name']}")
            print(f"    Pinned: {key_info['pinned_at']}")
    else:
        print("No keys pinned yet")

    # Step 7: Demonstrate invalid signature detection
    print("\n7. Testing invalid signature detection...")

    # Modify the signature to make it invalid
    invalid_signature = signature[:-4] + "XXXX"

    result3 = verification_workflow.verify_schema(
        schema=schema,
        signature_b64=invalid_signature,
        tool_id="example.com/calculate_sum",
        domain="example.com"
    )

    if not result3['valid']:
        print("✅ Invalid signature correctly detected")
        print("🛡️ SchemaPin successfully prevented use of tampered schema")
    else:
        print("❌ Invalid signature was not detected (this should not happen)")

    print("\n" + "=" * 45)
    print("Client verification workflow complete!")
    print("\nKey takeaways:")
    print("✓ Valid signatures are accepted")
    print("✓ Invalid signatures are rejected")
    print("✓ Keys are pinned on first use (TOFU)")
    print("✓ Subsequent verifications use pinned keys")
    print("✓ Network requests only needed for new tools")


if __name__ == "__main__":
    main()
