#!/usr/bin/env python3
"""SchemaPin key generation tool."""

import argparse
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from schemapin.crypto import KeyManager
from schemapin.utils import create_well_known_response


def generate_rsa_keypair(key_size: int = 2048):
    """Generate RSA key pair."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size
    )
    public_key = private_key.public_key()
    return private_key, public_key


def export_rsa_private_key_pem(private_key):
    """Export RSA private key to PEM format."""
    pem_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    return pem_bytes.decode('utf-8')


def export_rsa_public_key_pem(public_key):
    """Export RSA public key to PEM format."""
    pem_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem_bytes.decode('utf-8')


def export_key_der(key, is_private: bool = False):
    """Export key to DER format."""
    if is_private:
        der_bytes = key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
    else:
        der_bytes = key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    return der_bytes


def calculate_rsa_fingerprint(public_key):
    """Calculate SHA-256 fingerprint of RSA public key."""
    der_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    fingerprint = hashes.Hash(hashes.SHA256())
    fingerprint.update(der_bytes)
    return f"sha256:{fingerprint.finalize().hex()}"


def main():
    """Main entry point for keygen tool."""
    parser = argparse.ArgumentParser(
        description="Generate cryptographic key pairs for SchemaPin",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --type ecdsa --output-dir ./keys --developer "Alice Corp"
  %(prog)s --type rsa --key-size 4096 --format der --output-dir ./keys
  %(prog)s --type ecdsa --well-known --developer "Bob Inc" --contact "security@bob.com"
        """
    )

    parser.add_argument(
        '--type',
        choices=['ecdsa', 'rsa'],
        default='ecdsa',
        help='Key type to generate (default: ecdsa)'
    )

    parser.add_argument(
        '--key-size',
        type=int,
        choices=[2048, 3072, 4096],
        default=2048,
        help='RSA key size in bits (default: 2048, ignored for ECDSA)'
    )

    parser.add_argument(
        '--format',
        choices=['pem', 'der'],
        default='pem',
        help='Output format (default: pem)'
    )

    parser.add_argument(
        '--output-dir',
        type=Path,
        default=Path('.'),
        help='Output directory for key files (default: current directory)'
    )

    parser.add_argument(
        '--prefix',
        default='schemapin',
        help='Filename prefix for generated keys (default: schemapin)'
    )

    parser.add_argument(
        '--developer',
        help='Developer or organization name for .well-known template'
    )

    parser.add_argument(
        '--contact',
        help='Contact information for .well-known template'
    )

    parser.add_argument(
        '--schema-version',
        default='1.1',
        help='Schema version for .well-known template (default: 1.1)'
    )

    parser.add_argument(
        '--well-known',
        action='store_true',
        help='Generate .well-known/schemapin.json template'
    )

    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Verbose output'
    )

    parser.add_argument(
        '--quiet', '-q',
        action='store_true',
        help='Quiet output (only errors)'
    )

    parser.add_argument(
        '--json',
        action='store_true',
        help='Output results as JSON'
    )

    args = parser.parse_args()

    # Validate arguments
    if args.well_known and not args.developer:
        parser.error("--developer is required when generating .well-known template")

    if args.quiet and args.verbose:
        parser.error("--quiet and --verbose are mutually exclusive")

    try:
        # Create output directory
        args.output_dir.mkdir(parents=True, exist_ok=True)

        # Generate key pair
        if args.type == 'ecdsa':
            private_key, public_key = KeyManager.generate_keypair()
            private_key_data = KeyManager.export_private_key_pem(private_key)
            public_key_data = KeyManager.export_public_key_pem(public_key)
            fingerprint = KeyManager.calculate_key_fingerprint(public_key)
        else:  # RSA
            private_key, public_key = generate_rsa_keypair(args.key_size)
            if args.format == 'pem':
                private_key_data = export_rsa_private_key_pem(private_key)
                public_key_data = export_rsa_public_key_pem(public_key)
            else:  # DER
                private_key_data = export_key_der(private_key, is_private=True)
                public_key_data = export_key_der(public_key, is_private=False)
            fingerprint = calculate_rsa_fingerprint(public_key)

        # Determine file extensions
        ext = '.pem' if args.format == 'pem' else '.der'
        private_key_file = args.output_dir / f"{args.prefix}_private{ext}"
        public_key_file = args.output_dir / f"{args.prefix}_public{ext}"

        # Write key files
        if args.format == 'pem':
            private_key_file.write_text(private_key_data)
            public_key_file.write_text(public_key_data)
        else:  # DER
            private_key_file.write_bytes(private_key_data)
            public_key_file.write_bytes(public_key_data)

        # Generate .well-known template if requested
        well_known_file = None
        if args.well_known:
            well_known_data = create_well_known_response(
                public_key_pem=public_key_data if args.format == 'pem' else export_rsa_public_key_pem(public_key) if args.type == 'rsa' else KeyManager.export_public_key_pem(public_key),
                developer_name=args.developer,
                contact=args.contact,
                schema_version=args.schema_version
            )
            well_known_file = args.output_dir / "schemapin.json"
            well_known_file.write_text(json.dumps(well_known_data, indent=2))

        # Output results
        result = {
            'key_type': args.type,
            'key_size': args.key_size if args.type == 'rsa' else 256,
            'format': args.format,
            'fingerprint': fingerprint,
            'private_key_file': str(private_key_file),
            'public_key_file': str(public_key_file),
            'well_known_file': str(well_known_file) if well_known_file else None
        }

        if args.json:
            print(json.dumps(result, indent=2))
        elif not args.quiet:
            print(f"Generated {args.type.upper()} key pair:")
            print(f"  Key type: {args.type}")
            if args.type == 'rsa':
                print(f"  Key size: {args.key_size} bits")
            print(f"  Format: {args.format}")
            print(f"  Fingerprint: {fingerprint}")
            print(f"  Private key: {private_key_file}")
            print(f"  Public key: {public_key_file}")
            if well_known_file:
                print(f"  .well-known template: {well_known_file}")

        if args.verbose and not args.json:
            print(f"\nPublic key fingerprint: {fingerprint}")
            if args.format == 'pem':
                print(f"\nPublic key PEM:\n{public_key_data}")

    except Exception as e:
        if args.json:
            print(json.dumps({'error': str(e)}), file=sys.stderr)
        else:
            print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
