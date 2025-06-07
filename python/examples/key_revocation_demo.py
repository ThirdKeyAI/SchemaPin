#!/usr/bin/env python3
"""
Demonstration of SchemaPin key revocation functionality.

This script shows how key revocation works in SchemaPin v1.1:
1. Generate key pairs and demonstrate fingerprint calculation
2. Create well-known responses with revoked keys
3. Show how revocation checking prevents use of compromised keys
4. Demonstrate backward compatibility with v1.0
"""

import json

from schemapin.crypto import KeyManager
from schemapin.discovery import PublicKeyDiscovery
from schemapin.utils import create_well_known_response


def demonstrate_fingerprint_calculation():
    """Show how key fingerprints are calculated."""
    print("🔐 Key Fingerprint Calculation Demo")
    print("=" * 50)

    # Generate a test key pair
    private_key, public_key = KeyManager.generate_keypair()
    public_key_pem = KeyManager.export_public_key_pem(public_key)

    # Calculate fingerprint
    fingerprint = KeyManager.calculate_key_fingerprint(public_key)

    print(f"Public Key (first 80 chars): {public_key_pem[:80]}...")
    print(f"SHA-256 Fingerprint: {fingerprint}")

    # Show consistency
    fingerprint2 = KeyManager.calculate_key_fingerprint_from_pem(public_key_pem)
    print(f"Fingerprint from PEM: {fingerprint2}")
    print(f"Fingerprints match: {fingerprint == fingerprint2}")
    print()

    return public_key_pem, fingerprint


def demonstrate_well_known_v11():
    """Show well-known response with revoked keys."""
    print("📋 Well-Known Response v1.1 Demo")
    print("=" * 50)

    # Generate current and revoked keys
    _, current_key = KeyManager.generate_keypair()
    _, revoked_key1 = KeyManager.generate_keypair()
    _, revoked_key2 = KeyManager.generate_keypair()

    current_key_pem = KeyManager.export_public_key_pem(current_key)
    revoked_fingerprint1 = KeyManager.calculate_key_fingerprint(revoked_key1)
    revoked_fingerprint2 = KeyManager.calculate_key_fingerprint(revoked_key2)

    # Create well-known response with revoked keys
    well_known = create_well_known_response(
        public_key_pem=current_key_pem,
        developer_name="Example Corp Security Team",
        contact="security@example.com",
        revoked_keys=[revoked_fingerprint1, revoked_fingerprint2],
        schema_version="1.1"
    )

    print("Well-Known Response (v1.1):")
    print(json.dumps(well_known, indent=2))
    print()

    return well_known, revoked_fingerprint1


def demonstrate_revocation_checking():
    """Show how revocation checking works."""
    print("🚫 Key Revocation Checking Demo")
    print("=" * 50)

    # Generate keys
    _, good_key = KeyManager.generate_keypair()
    _, revoked_key = KeyManager.generate_keypair()

    good_key_pem = KeyManager.export_public_key_pem(good_key)
    revoked_key_pem = KeyManager.export_public_key_pem(revoked_key)
    revoked_fingerprint = KeyManager.calculate_key_fingerprint(revoked_key)

    # Create revocation list
    revoked_keys = [revoked_fingerprint]

    # Test revocation checking
    print("Testing key revocation checking:")
    print(f"Good key revoked: {PublicKeyDiscovery.check_key_revocation(good_key_pem, revoked_keys)}")
    print(f"Revoked key revoked: {PublicKeyDiscovery.check_key_revocation(revoked_key_pem, revoked_keys)}")
    print()

    return good_key_pem, revoked_key_pem, revoked_keys


def demonstrate_backward_compatibility():
    """Show backward compatibility with v1.0."""
    print("🔄 Backward Compatibility Demo")
    print("=" * 50)

    # Generate key
    _, public_key = KeyManager.generate_keypair()
    public_key_pem = KeyManager.export_public_key_pem(public_key)

    # Create v1.0 response (no revoked_keys)
    well_known_v10 = create_well_known_response(
        public_key_pem=public_key_pem,
        developer_name="Legacy Tool Developer",
        contact="support@legacy.com",
        schema_version="1.0"
    )

    print("Well-Known Response (v1.0 - backward compatible):")
    print(json.dumps(well_known_v10, indent=2))

    # Show that revocation checking handles missing revoked_keys gracefully
    print(f"\nRevocation check with no revoked_keys field: {not PublicKeyDiscovery.check_key_revocation(public_key_pem, [])}")
    print()


def demonstrate_security_scenario():
    """Show a realistic security scenario."""
    print("🛡️  Security Scenario Demo")
    print("=" * 50)

    print("Scenario: A developer's private key has been compromised")
    print("1. Developer generates new key pair")
    print("2. Developer adds old key fingerprint to revoked_keys")
    print("3. Clients automatically reject schemas signed with old key")
    print()

    # Generate old (compromised) and new keys
    old_private_key, old_public_key = KeyManager.generate_keypair()
    new_private_key, new_public_key = KeyManager.generate_keypair()

    old_public_key_pem = KeyManager.export_public_key_pem(old_public_key)
    new_public_key_pem = KeyManager.export_public_key_pem(new_public_key)
    old_fingerprint = KeyManager.calculate_key_fingerprint(old_public_key)

    print(f"Old key fingerprint: {old_fingerprint}")
    print(f"New key fingerprint: {KeyManager.calculate_key_fingerprint(new_public_key)}")

    # Create updated well-known response
    updated_well_known = create_well_known_response(
        public_key_pem=new_public_key_pem,
        developer_name="Example Corp Security Team",
        contact="security@example.com",
        revoked_keys=[old_fingerprint],
        schema_version="1.1"
    )

    print("\nUpdated well-known response:")
    print(json.dumps(updated_well_known, indent=2))

    # Show that old key is now rejected
    print(f"\nOld key now revoked: {PublicKeyDiscovery.check_key_revocation(old_public_key_pem, [old_fingerprint])}")
    print(f"New key still valid: {not PublicKeyDiscovery.check_key_revocation(new_public_key_pem, [old_fingerprint])}")
    print()


def main():
    """Run all demonstrations."""
    print("🧷 SchemaPin Key Revocation Demo")
    print("=" * 60)
    print("This demo shows the new key revocation features in SchemaPin v1.1")
    print()

    # Run demonstrations
    demonstrate_fingerprint_calculation()
    demonstrate_well_known_v11()
    demonstrate_revocation_checking()
    demonstrate_backward_compatibility()
    demonstrate_security_scenario()

    print("✅ Key revocation demo completed!")
    print("\nKey benefits of SchemaPin v1.1 key revocation:")
    print("• Immediate protection against compromised keys")
    print("• SHA-256 fingerprints for secure key identification")
    print("• Backward compatibility with v1.0 endpoints")
    print("• Automatic revocation checking in verification workflow")
    print("• Clear security model for key rotation scenarios")


if __name__ == "__main__":
    main()
