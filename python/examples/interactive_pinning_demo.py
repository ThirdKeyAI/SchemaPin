#!/usr/bin/env python3
"""
Interactive Key Pinning Demo

This example demonstrates how to use SchemaPin's interactive key pinning
functionality to prompt users for key decisions.
"""

import json
import os
import tempfile

from schemapin.core import SchemaPinCore
from schemapin.crypto import KeyManager, SignatureManager
from schemapin.interactive import CallbackInteractiveHandler, PromptType, UserDecision
from schemapin.pinning import KeyPinning, PinningMode, PinningPolicy


def demo_console_interactive_pinning():
    """Demonstrate console-based interactive pinning."""
    print("=== Console Interactive Pinning Demo ===\n")

    # Create temporary database
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, "demo_pinning.db")

    try:
        # Initialize pinning with interactive mode
        pinning = KeyPinning(
            db_path=db_path,
            mode=PinningMode.INTERACTIVE
        )

        # Generate demo keys
        private_key, public_key = KeyManager.generate_keypair()
        public_key_pem = KeyManager.export_public_key_pem(public_key)

        # Demo tool information
        tool_id = "demo-calculator"
        domain = "example-tools.com"
        developer_name = "Example Tools Inc"

        print(f"Tool: {tool_id}")
        print(f"Domain: {domain}")
        print(f"Developer: {developer_name}")
        print(f"Key Fingerprint: {KeyManager.calculate_key_fingerprint(public_key)}")
        print()

        # Attempt to pin the key (will prompt user)
        print("Attempting to pin key for first time...")
        result = pinning.interactive_pin_key(
            tool_id, public_key_pem, domain, developer_name
        )

        if result:
            print("✅ Key was accepted and pinned!")
        else:
            print("❌ Key was rejected.")

        print(f"Key pinned: {pinning.is_key_pinned(tool_id)}")

        # Demonstrate key change scenario
        if pinning.is_key_pinned(tool_id):
            print("\n--- Key Change Scenario ---")

            # Generate new key
            new_private_key, new_public_key = KeyManager.generate_keypair()
            new_public_key_pem = KeyManager.export_public_key_pem(new_public_key)

            print(f"New Key Fingerprint: {KeyManager.calculate_key_fingerprint(new_public_key)}")
            print("Attempting to change pinned key...")

            result = pinning.interactive_pin_key(
                tool_id, new_public_key_pem, domain, developer_name
            )

            if result:
                print("✅ Key change was accepted!")
            else:
                print("❌ Key change was rejected.")

    finally:
        # Cleanup
        if os.path.exists(db_path):
            os.unlink(db_path)
        os.rmdir(temp_dir)


def demo_callback_interactive_pinning():
    """Demonstrate callback-based interactive pinning."""
    print("\n=== Callback Interactive Pinning Demo ===\n")

    # Create temporary database
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, "demo_pinning.db")

    try:
        # Custom callback function
        def custom_prompt_handler(context):
            """Custom prompt handler that automatically accepts first-time keys."""
            print(f"Custom handler called for: {context.tool_id}")
            print(f"Prompt type: {context.prompt_type.value}")

            if context.prompt_type == PromptType.FIRST_TIME_KEY:
                print("Auto-accepting first-time key...")
                return UserDecision.ACCEPT
            elif context.prompt_type == PromptType.KEY_CHANGE:
                print("Auto-rejecting key change...")
                return UserDecision.REJECT
            else:
                print("Auto-rejecting revoked key...")
                return UserDecision.REJECT

        # Create callback handler
        callback_handler = CallbackInteractiveHandler(custom_prompt_handler)

        # Initialize pinning with callback handler
        pinning = KeyPinning(
            db_path=db_path,
            mode=PinningMode.INTERACTIVE,
            interactive_handler=callback_handler
        )

        # Generate demo keys
        private_key, public_key = KeyManager.generate_keypair()
        public_key_pem = KeyManager.export_public_key_pem(public_key)

        # Demo tool information
        tool_id = "demo-api-client"
        domain = "api.example.com"
        developer_name = "API Corp"

        print(f"Tool: {tool_id}")
        print(f"Domain: {domain}")
        print(f"Developer: {developer_name}")
        print()

        # Pin the key (will use callback)
        result = pinning.interactive_pin_key(
            tool_id, public_key_pem, domain, developer_name
        )

        print(f"Result: {'Accepted' if result else 'Rejected'}")
        print(f"Key pinned: {pinning.is_key_pinned(tool_id)}")

        # Test key change (should be rejected by callback)
        if pinning.is_key_pinned(tool_id):
            print("\n--- Testing Key Change ---")

            new_private_key, new_public_key = KeyManager.generate_keypair()
            new_public_key_pem = KeyManager.export_public_key_pem(new_public_key)

            result = pinning.interactive_pin_key(
                tool_id, new_public_key_pem, domain, developer_name
            )

            print(f"Key change result: {'Accepted' if result else 'Rejected'}")

    finally:
        # Cleanup
        if os.path.exists(db_path):
            os.unlink(db_path)
        os.rmdir(temp_dir)


def demo_domain_policies():
    """Demonstrate domain-based pinning policies."""
    print("\n=== Domain Policies Demo ===\n")

    # Create temporary database
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, "demo_pinning.db")

    try:
        pinning = KeyPinning(
            db_path=db_path,
            mode=PinningMode.INTERACTIVE
        )

        # Generate demo key
        private_key, public_key = KeyManager.generate_keypair()
        public_key_pem = KeyManager.export_public_key_pem(public_key)

        # Test different domain policies
        domains = [
            ("trusted.example.com", PinningPolicy.ALWAYS_TRUST),
            ("untrusted.example.com", PinningPolicy.NEVER_TRUST),
            ("normal.example.com", PinningPolicy.DEFAULT)
        ]

        for domain, policy in domains:
            print(f"Testing domain: {domain} with policy: {policy.value}")

            # Set domain policy
            pinning.set_domain_policy(domain, policy)

            # Try to pin key
            tool_id = f"tool-{domain.split('.')[0]}"
            result = pinning.interactive_pin_key(
                tool_id, public_key_pem, domain, "Test Developer"
            )

            print(f"  Result: {'Accepted' if result else 'Rejected'}")
            print(f"  Key pinned: {pinning.is_key_pinned(tool_id)}")
            print()

    finally:
        # Cleanup
        if os.path.exists(db_path):
            os.unlink(db_path)
        os.rmdir(temp_dir)


def demo_schema_verification_with_interactive_pinning():
    """Demonstrate complete schema verification with interactive pinning."""
    print("\n=== Schema Verification with Interactive Pinning Demo ===\n")

    # Create temporary database
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, "demo_pinning.db")

    try:
        # Initialize components
        pinning = KeyPinning(
            db_path=db_path,
            mode=PinningMode.AUTOMATIC  # Use automatic for demo
        )

        # Generate developer key pair
        private_key, public_key = KeyManager.generate_keypair()
        public_key_pem = KeyManager.export_public_key_pem(public_key)

        # Create demo schema
        schema = {
            "name": "calculate_sum",
            "description": "Calculate the sum of two numbers",
            "parameters": {
                "a": {"type": "number", "description": "First number"},
                "b": {"type": "number", "description": "Second number"}
            }
        }

        # Sign the schema
        canonical_schema = SchemaPinCore.canonicalize_schema(schema)
        schema_hash = SchemaPinCore.hash_canonical(canonical_schema)
        signature = SignatureManager.sign_schema_hash(schema_hash, private_key)

        print("Schema to verify:")
        print(json.dumps(schema, indent=2))
        print(f"\nSignature: {signature[:50]}...")
        print(f"Key fingerprint: {KeyManager.calculate_key_fingerprint(public_key)}")

        # Tool information
        tool_id = "math-calculator"
        domain = "mathtools.example.com"
        developer_name = "Math Tools LLC"

        # Verify with interactive pinning
        print(f"\nVerifying schema for tool: {tool_id}")

        # First, handle key pinning
        pin_result = pinning.verify_with_interactive_pinning(
            tool_id, domain, public_key_pem, developer_name
        )

        if pin_result:
            print("✅ Key pinning successful")

            # Now verify the signature
            verification_result = SignatureManager.verify_schema_signature(
                schema_hash, signature, public_key
            )

            if verification_result:
                print("✅ Schema signature verification successful")
                print("🎉 Schema is authentic and can be trusted!")
            else:
                print("❌ Schema signature verification failed")
        else:
            print("❌ Key pinning failed - schema cannot be trusted")

        # Show pinned keys
        print("\nPinned keys in database:")
        for key_info in pinning.list_pinned_keys():
            print(f"  - {key_info['tool_id']} ({key_info['domain']})")

    finally:
        # Cleanup
        if os.path.exists(db_path):
            os.unlink(db_path)
        os.rmdir(temp_dir)


def main():
    """Run all interactive pinning demos."""
    print("SchemaPin Interactive Key Pinning Demo")
    print("=" * 50)

    # Note: Console demo requires user interaction
    # Uncomment the line below to test console interaction
    # demo_console_interactive_pinning()

    demo_callback_interactive_pinning()
    demo_domain_policies()
    demo_schema_verification_with_interactive_pinning()

    print("\n🎉 All demos completed successfully!")


if __name__ == "__main__":
    main()
