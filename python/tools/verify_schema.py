#!/usr/bin/env python3
"""SchemaPin schema verification tool."""

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from schemapin.core import SchemaPinCore
from schemapin.crypto import KeyManager, SignatureManager
from schemapin.discovery import PublicKeyDiscovery
from schemapin.skill import SkillSigner
from schemapin.utils import SchemaVerificationWorkflow


def load_signed_schema(schema_path: Path) -> Dict[str, Any]:
    """Load and validate signed schema from file."""
    try:
        schema_data = schema_path.read_text()
        signed_schema = json.loads(schema_data)

        # Validate signed schema structure
        required_fields = ['schema', 'signature']
        if not all(field in signed_schema for field in required_fields):
            raise ValueError("Invalid signed schema format - missing required fields")

        return signed_schema
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON in signed schema file: {e}")
    except Exception as e:
        raise ValueError(f"Failed to load signed schema from {schema_path}: {e}")


def load_public_key(key_path: Path) -> Any:
    """Load public key from file."""
    try:
        key_data = key_path.read_text()
        return KeyManager.load_public_key_pem(key_data)
    except Exception as e:
        raise ValueError(f"Failed to load public key from {key_path}: {e}")


def verify_with_public_key(
    schema: Dict[str, Any],
    signature: str,
    public_key_path: Path
) -> Dict[str, Any]:
    """Verify schema with provided public key."""
    public_key = load_public_key(public_key_path)
    schema_hash = SchemaPinCore.canonicalize_and_hash(schema)

    is_valid = SignatureManager.verify_schema_signature(
        schema_hash, signature, public_key
    )

    fingerprint = KeyManager.calculate_key_fingerprint(public_key)

    return {
        'valid': is_valid,
        'verification_method': 'public_key',
        'key_fingerprint': fingerprint,
        'key_source': str(public_key_path)
    }


def verify_with_discovery(
    schema: Dict[str, Any],
    signature: str,
    domain: str,
    tool_id: Optional[str] = None,
    pinning_db: Optional[str] = None,
    interactive: bool = False,
    auto_pin: bool = False
) -> Dict[str, Any]:
    """Verify schema using discovery and optional pinning."""
    workflow = SchemaVerificationWorkflow(pinning_db)

    if interactive and tool_id:
        # Use interactive pinning
        from schemapin.interactive import InteractivePinningManager
        interactive_manager = InteractivePinningManager()

        # Check if key is already pinned
        pinned_key = workflow.pinning.get_pinned_key(tool_id)

        if not pinned_key:
            # First time - prompt user
            discovery = PublicKeyDiscovery()
            public_key_pem = discovery.get_public_key_pem(domain)
            if not public_key_pem:
                return {
                    'valid': False,
                    'error': 'Could not discover public key',
                    'verification_method': 'discovery_interactive'
                }

            developer_info = discovery.get_developer_info(domain)
            decision = interactive_manager.prompt_first_time_key(
                tool_id, domain, public_key_pem, developer_info
            )

            from schemapin.interactive import UserDecision
            if decision == UserDecision.ACCEPT:
                auto_pin = True
            elif decision == UserDecision.REJECT:
                return {
                    'valid': False,
                    'error': 'User rejected key',
                    'verification_method': 'discovery_interactive'
                }

    # Use standard verification workflow
    result = workflow.verify_schema(
        schema, signature, tool_id or 'unknown', domain, auto_pin
    )

    result['verification_method'] = 'discovery'
    if interactive:
        result['verification_method'] = 'discovery_interactive'

    return result


def verify_batch_schemas(
    schema_files: List[Path],
    verification_method: str,
    **kwargs
) -> List[Dict[str, Any]]:
    """Verify multiple schema files."""
    results = []

    for schema_file in schema_files:
        try:
            signed_schema = load_signed_schema(schema_file)
            schema = signed_schema['schema']
            signature = signed_schema['signature']

            if verification_method == 'public_key':
                result = verify_with_public_key(schema, signature, kwargs['public_key_path'])
            else:  # discovery
                result = verify_with_discovery(
                    schema, signature, kwargs['domain'],
                    kwargs.get('tool_id'), kwargs.get('pinning_db'),
                    kwargs.get('interactive', False), kwargs.get('auto_pin', False)
                )

            result['file'] = str(schema_file)
            result['metadata'] = signed_schema.get('metadata', {})
            result['signed_at'] = signed_schema.get('signed_at')

            results.append(result)

        except Exception as e:
            results.append({
                'file': str(schema_file),
                'valid': False,
                'error': str(e),
                'verification_method': verification_method
            })

    return results


def display_verification_result(result: Dict[str, Any], verbose: bool = False) -> None:
    """Display verification result in human-readable format."""
    file_info = f" ({result['file']})" if 'file' in result else ""

    if result['valid']:
        print(f"✅ VALID{file_info}")
        if verbose:
            print(f"   Method: {result.get('verification_method', 'unknown')}")
            if 'key_fingerprint' in result:
                print(f"   Key fingerprint: {result['key_fingerprint']}")
            if 'key_source' in result:
                print(f"   Key source: {result['key_source']}")
            if result.get('pinned'):
                print("   Key status: Pinned")
            if result.get('first_use'):
                print("   Key status: First use")
            if 'developer_info' in result and result['developer_info']:
                dev_info = result['developer_info']
                print(f"   Developer: {dev_info.get('developer_name', 'Unknown')}")
            if 'signed_at' in result:
                print(f"   Signed at: {result['signed_at']}")
    else:
        print(f"❌ INVALID{file_info}")
        if 'error' in result:
            print(f"   Error: {result['error']}")
        if verbose and 'verification_method' in result:
            print(f"   Method: {result['verification_method']}")


def main():
    """Main entry point for verify-schema tool."""
    parser = argparse.ArgumentParser(
        description="Verify signed JSON schemas with SchemaPin",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --schema signed_schema.json --public-key public.pem
  %(prog)s --schema signed_schema.json --domain example.com --tool-id my-tool
  %(prog)s --batch schemas/ --domain example.com --auto-pin
  echo '{"schema": {...}, "signature": "..."}' | %(prog)s --stdin --domain example.com
        """
    )

    # Input options
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument(
        '--schema',
        type=Path,
        help='Signed schema file to verify'
    )
    input_group.add_argument(
        '--batch',
        type=Path,
        help='Directory containing signed schema files'
    )
    input_group.add_argument(
        '--stdin',
        action='store_true',
        help='Read signed schema from stdin'
    )
    input_group.add_argument(
        '--skill',
        type=Path,
        help='Skill directory to verify'
    )

    # Verification method options
    method_group = parser.add_mutually_exclusive_group(required=True)
    method_group.add_argument(
        '--public-key',
        type=Path,
        help='Public key file for verification (PEM format)'
    )
    method_group.add_argument(
        '--domain',
        help='Domain for public key discovery'
    )

    # Discovery and pinning options
    parser.add_argument(
        '--tool-id',
        help='Tool identifier for key pinning'
    )

    parser.add_argument(
        '--pinning-db',
        type=Path,
        help='Path to key pinning database'
    )

    parser.add_argument(
        '--interactive',
        action='store_true',
        help='Enable interactive key pinning prompts'
    )

    parser.add_argument(
        '--auto-pin',
        action='store_true',
        help='Automatically pin keys on first use'
    )

    # Batch processing options
    parser.add_argument(
        '--pattern',
        default='*.json',
        help='File pattern for batch processing (default: *.json)'
    )

    # Output options
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Verbose output with security information'
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

    parser.add_argument(
        '--exit-code',
        action='store_true',
        help='Exit with non-zero code if any verification fails'
    )

    args = parser.parse_args()

    # Validate arguments
    if args.quiet and args.verbose:
        parser.error("--quiet and --verbose are mutually exclusive")

    if args.domain and args.interactive and not args.tool_id:
        parser.error("--tool-id is required for interactive mode")

    try:
        results = []

        if args.stdin:
            # Process stdin
            schema_data = sys.stdin.read()
            signed_schema = json.loads(schema_data)

            if not all(field in signed_schema for field in ['schema', 'signature']):
                raise ValueError("Invalid signed schema format from stdin")

            schema = signed_schema['schema']
            signature = signed_schema['signature']

            if args.public_key:
                result = verify_with_public_key(schema, signature, args.public_key)
            else:
                result = verify_with_discovery(
                    schema, signature, args.domain, args.tool_id,
                    str(args.pinning_db) if args.pinning_db else None,
                    args.interactive, args.auto_pin
                )

            result['metadata'] = signed_schema.get('metadata', {})
            result['signed_at'] = signed_schema.get('signed_at')
            results.append(result)

        elif args.skill:
            # Verify skill directory
            if args.public_key:
                # Direct key verification
                root_hash, _manifest = SkillSigner.canonicalize_skill(args.skill)
                public_key = load_public_key(args.public_key)
                sig_data = SkillSigner.load_signature(args.skill)
                is_valid = SignatureManager.verify_signature(
                    root_hash, sig_data.get("signature", ""), public_key
                )
                fingerprint = KeyManager.calculate_key_fingerprint(public_key)
                result = {
                    'valid': is_valid,
                    'verification_method': 'public_key',
                    'key_fingerprint': fingerprint,
                    'key_source': str(args.public_key),
                    'skill_name': sig_data.get('skill_name', ''),
                }
            elif args.domain:
                # Resolver-based verification
                from schemapin.resolver import WellKnownResolver
                from schemapin.verification import KeyPinStore

                pin_store = KeyPinStore()
                resolver = WellKnownResolver()
                vr = SkillSigner.verify_skill_with_resolver(
                    args.skill,
                    args.domain,
                    resolver=resolver,
                    pin_store=pin_store,
                    tool_id=args.tool_id,
                )
                result = vr.to_dict()
                result['verification_method'] = 'discovery'
            else:
                raise ValueError("--public-key or --domain is required for --skill")

            results.append(result)

        elif args.schema:
            # Process single schema
            signed_schema = load_signed_schema(args.schema)
            schema = signed_schema['schema']
            signature = signed_schema['signature']

            if args.public_key:
                result = verify_with_public_key(schema, signature, args.public_key)
            else:
                result = verify_with_discovery(
                    schema, signature, args.domain, args.tool_id,
                    str(args.pinning_db) if args.pinning_db else None,
                    args.interactive, args.auto_pin
                )

            result['file'] = str(args.schema)
            result['metadata'] = signed_schema.get('metadata', {})
            result['signed_at'] = signed_schema.get('signed_at')
            results.append(result)

        elif args.batch:
            # Process batch
            schema_files = list(args.batch.glob(args.pattern))

            if not schema_files:
                raise ValueError(f"No schema files found matching pattern '{args.pattern}' in {args.batch}")

            kwargs = {
                'domain': args.domain,
                'tool_id': args.tool_id,
                'pinning_db': str(args.pinning_db) if args.pinning_db else None,
                'interactive': args.interactive,
                'auto_pin': args.auto_pin,
                'public_key_path': args.public_key
            }

            verification_method = 'public_key' if args.public_key else 'discovery'
            results = verify_batch_schemas(schema_files, verification_method, **kwargs)

        # Output results
        if args.json:
            output = {
                'results': results,
                'total': len(results),
                'valid': len([r for r in results if r.get('valid', False)]),
                'invalid': len([r for r in results if not r.get('valid', False)])
            }
            print(json.dumps(output, indent=2))
        else:
            # Human-readable output
            if not args.quiet:
                for result in results:
                    display_verification_result(result, args.verbose)

                if len(results) > 1:
                    valid_count = len([r for r in results if r.get('valid', False)])
                    print(f"\nSummary: {valid_count}/{len(results)} schemas verified successfully")

        # Exit code handling
        if args.exit_code:
            invalid_count = len([r for r in results if not r.get('valid', False)])
            if invalid_count > 0:
                sys.exit(1)

    except Exception as e:
        if args.json:
            print(json.dumps({'error': str(e)}), file=sys.stderr)
        else:
            print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
