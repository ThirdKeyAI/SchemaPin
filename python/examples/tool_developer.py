#!/usr/bin/env python3
"""Example tool developer workflow for signing schemas."""

import json
import sys
from pathlib import Path

# Add the parent directory to the path so we can import schemapin
sys.path.insert(0, str(Path(__file__).parent.parent))

from schemapin.crypto import KeyManager
from schemapin.utils import SchemaSigningWorkflow, create_well_known_response


def main():
    """Demonstrate tool developer workflow."""
    print("SchemaPin Tool Developer Example")
    print("=" * 40)
    
    # Step 1: Generate key pair
    print("\n1. Generating ECDSA P-256 key pair...")
    private_key, public_key = KeyManager.generate_keypair()
    
    private_key_pem = KeyManager.export_private_key_pem(private_key)
    public_key_pem = KeyManager.export_public_key_pem(public_key)
    
    print("✓ Key pair generated")
    
    # Step 2: Create sample tool schema
    print("\n2. Creating sample tool schema...")
    sample_schema = {
        "name": "calculate_sum",
        "description": "Calculates the sum of two numbers",
        "parameters": {
            "type": "object",
            "properties": {
                "a": {
                    "type": "number",
                    "description": "First number"
                },
                "b": {
                    "type": "number", 
                    "description": "Second number"
                }
            },
            "required": ["a", "b"]
        }
    }
    
    print("✓ Sample schema created")
    print(f"Schema: {json.dumps(sample_schema, indent=2)}")
    
    # Step 3: Sign the schema
    print("\n3. Signing schema...")
    signing_workflow = SchemaSigningWorkflow(private_key_pem)
    signature = signing_workflow.sign_schema(sample_schema)
    
    print("✓ Schema signed")
    print(f"Signature: {signature}")
    
    # Step 4: Create .well-known response
    print("\n4. Creating .well-known/schemapin.json response...")
    well_known_response = create_well_known_response(
        public_key_pem=public_key_pem,
        developer_name="Example Tool Developer",
        contact="developer@example.com"
    )
    
    print("✓ .well-known response created")
    print(f".well-known content: {json.dumps(well_known_response, indent=2)}")
    
    # Step 5: Save files for demonstration
    print("\n5. Saving demonstration files...")
    
    # Save private key (in real use, keep this secure!)
    with open("demo_private_key.pem", "w") as f:
        f.write(private_key_pem)
    
    # Save schema with signature
    schema_with_signature = {
        "schema": sample_schema,
        "signature": signature
    }
    with open("demo_schema_signed.json", "w") as f:
        json.dump(schema_with_signature, f, indent=2)
    
    # Save .well-known response
    with open("demo_well_known.json", "w") as f:
        json.dump(well_known_response, f, indent=2)
    
    print("✓ Files saved:")
    print("  - demo_private_key.pem (keep secure!)")
    print("  - demo_schema_signed.json")
    print("  - demo_well_known.json")
    
    print("\n" + "=" * 40)
    print("Tool developer workflow complete!")
    print("\nNext steps:")
    print("1. Host demo_well_known.json at https://yourdomain.com/.well-known/schemapin.json")
    print("2. Distribute demo_schema_signed.json with your tool")
    print("3. Keep demo_private_key.pem secure and use it to sign future schema updates")


if __name__ == "__main__":
    main()