#!/usr/bin/env python3
"""SchemaPin schema signing tool."""

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from schemapin.crypto import KeyManager
from schemapin.utils import SchemaSigningWorkflow


def load_private_key(key_path: Path, key_type: str = 'auto') -> Any:
    """Load private key from file."""
    try:
        key_data = key_path.read_text()
        return KeyManager.load_private_key_pem(key_data)
    except Exception as e:
        raise ValueError(f"Failed to load private key from {key_path}: {e}")


def load_schema(schema_path: Path) -> Dict[str, Any]:
    """Load and validate JSON schema from file."""
    try:
        schema_data = schema_path.read_text()
        schema = json.loads(schema_data)

        # Basic validation - ensure it's a dictionary
        if not isinstance(schema, dict):
            raise ValueError("Schema must be a JSON object")

        return schema
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON in schema file: {e}")
    except Exception as e:
        raise ValueError(f"Failed to load schema from {schema_path}: {e}")


def validate_schema_format(schema: Dict[str, Any]) -> bool:
    """Basic validation of schema format."""
    # Check for common schema fields
    if 'type' not in schema and '$schema' not in schema:
        return False
    return True


def create_signed_schema(
    schema: Dict[str, Any],
    signature: str,
    metadata: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """Create signed schema with signature and metadata."""
    signed_schema = {
        'schema': schema,
        'signature': signature,
        'signed_at': datetime.now(timezone.utc).isoformat()
    }

    if metadata:
        signed_schema['metadata'] = metadata

    return signed_schema


def process_single_schema(
    schema_path: Path,
    private_key: Any,
    output_path: Optional[Path] = None,
    metadata: Optional[Dict[str, Any]] = None,
    validate_format: bool = True
) -> Dict[str, Any]:
    """Process a single schema file."""
    # Load schema
    schema = load_schema(schema_path)

    # Validate format if requested
    if validate_format and not validate_schema_format(schema):
        raise ValueError(f"Schema format validation failed for {schema_path}")

    # Sign schema
    workflow = SchemaSigningWorkflow(KeyManager.export_private_key_pem(private_key))
    signature = workflow.sign_schema(schema)

    # Create signed schema
    signed_schema = create_signed_schema(schema, signature, metadata)

    # Write output
    if output_path:
        output_path.write_text(json.dumps(signed_schema, indent=2))

    return signed_schema


def main():
    """Main entry point for schema-signer tool."""
    parser = argparse.ArgumentParser(
        description="Sign JSON schema files with SchemaPin",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --key private.pem --schema schema.json --output signed_schema.json
  %(prog)s --key private.pem --schema schema.json --developer "Alice Corp" --version "1.0"
  %(prog)s --key private.pem --batch schemas/ --output-dir signed/
  echo '{"type": "object"}' | %(prog)s --key private.pem --stdin
        """
    )

    # Input options
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument(
        '--schema',
        type=Path,
        help='Input schema file'
    )
    input_group.add_argument(
        '--batch',
        type=Path,
        help='Directory containing schema files to sign'
    )
    input_group.add_argument(
        '--stdin',
        action='store_true',
        help='Read schema from stdin'
    )

    # Key options
    parser.add_argument(
        '--key',
        type=Path,
        required=True,
        help='Private key file (PEM format)'
    )

    # Output options
    parser.add_argument(
        '--output',
        type=Path,
        help='Output file (default: stdout for single schema)'
    )

    parser.add_argument(
        '--output-dir',
        type=Path,
        help='Output directory for batch processing'
    )

    # Metadata options
    parser.add_argument(
        '--developer',
        help='Developer or organization name'
    )

    parser.add_argument(
        '--version',
        help='Schema version'
    )

    parser.add_argument(
        '--description',
        help='Schema description'
    )

    parser.add_argument(
        '--metadata',
        type=Path,
        help='JSON file containing additional metadata'
    )

    # Processing options
    parser.add_argument(
        '--no-validate',
        action='store_true',
        help='Skip schema format validation'
    )

    parser.add_argument(
        '--pattern',
        default='*.json',
        help='File pattern for batch processing (default: *.json)'
    )

    parser.add_argument(
        '--suffix',
        default='_signed',
        help='Suffix for output files in batch mode (default: _signed)'
    )

    # Output format options
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
    if args.quiet and args.verbose:
        parser.error("--quiet and --verbose are mutually exclusive")

    if args.batch and not args.output_dir:
        parser.error("--output-dir is required for batch processing")

    if args.output and args.output_dir:
        parser.error("--output and --output-dir are mutually exclusive")

    try:
        # Load private key
        private_key = load_private_key(args.key)

        # Load additional metadata
        additional_metadata = {}
        if args.metadata:
            additional_metadata = json.loads(args.metadata.read_text())

        # Build metadata
        metadata = {}
        if args.developer:
            metadata['developer'] = args.developer
        if args.version:
            metadata['version'] = args.version
        if args.description:
            metadata['description'] = args.description
        if additional_metadata:
            metadata.update(additional_metadata)

        metadata = metadata if metadata else None

        results = []

        if args.stdin:
            # Process stdin
            schema_data = sys.stdin.read()
            schema = json.loads(schema_data)

            if not args.no_validate and not validate_schema_format(schema):
                raise ValueError("Schema format validation failed for stdin input")

            workflow = SchemaSigningWorkflow(KeyManager.export_private_key_pem(private_key))
            signature = workflow.sign_schema(schema)
            signed_schema = create_signed_schema(schema, signature, metadata)

            if args.output:
                args.output.write_text(json.dumps(signed_schema, indent=2))
            else:
                print(json.dumps(signed_schema, indent=2))

            results.append({
                'input': 'stdin',
                'output': str(args.output) if args.output else 'stdout',
                'status': 'success'
            })

        elif args.schema:
            # Process single schema
            output_path = args.output
            signed_schema = process_single_schema(
                args.schema, private_key, output_path, metadata, not args.no_validate
            )

            if not output_path:
                print(json.dumps(signed_schema, indent=2))

            results.append({
                'input': str(args.schema),
                'output': str(output_path) if output_path else 'stdout',
                'status': 'success'
            })

        elif args.batch:
            # Process batch
            args.output_dir.mkdir(parents=True, exist_ok=True)
            schema_files = list(args.batch.glob(args.pattern))

            if not schema_files:
                raise ValueError(f"No schema files found matching pattern '{args.pattern}' in {args.batch}")

            for schema_file in schema_files:
                try:
                    output_file = args.output_dir / f"{schema_file.stem}{args.suffix}{schema_file.suffix}"
                    process_single_schema(
                        schema_file, private_key, output_file, metadata, not args.no_validate
                    )

                    results.append({
                        'input': str(schema_file),
                        'output': str(output_file),
                        'status': 'success'
                    })

                    if args.verbose and not args.json:
                        print(f"Signed: {schema_file} -> {output_file}")

                except Exception as e:
                    results.append({
                        'input': str(schema_file),
                        'output': None,
                        'status': 'error',
                        'error': str(e)
                    })

                    if not args.quiet and not args.json:
                        print(f"Error processing {schema_file}: {e}", file=sys.stderr)

        # Output results
        if args.json:
            print(json.dumps({
                'results': results,
                'total': len(results),
                'successful': len([r for r in results if r['status'] == 'success']),
                'failed': len([r for r in results if r['status'] == 'error'])
            }, indent=2))
        elif not args.quiet:
            successful = len([r for r in results if r['status'] == 'success'])
            failed = len([r for r in results if r['status'] == 'error'])

            if len(results) > 1:
                print(f"Processed {len(results)} schemas: {successful} successful, {failed} failed")
            elif successful == 1 and not args.stdin and args.output:
                print(f"Successfully signed schema: {results[0]['output']}")

    except Exception as e:
        if args.json:
            print(json.dumps({'error': str(e)}), file=sys.stderr)
        else:
            print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
