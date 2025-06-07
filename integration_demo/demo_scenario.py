#!/usr/bin/env python3
"""
SchemaPin Integration Demo - Python Implementation

Demonstrates cross-language integration scenarios between Python and JavaScript
implementations of SchemaPin.
"""

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, Any

# Add parent directory to path to import schemapin
sys.path.insert(0, str(Path(__file__).parent.parent / "python"))

from schemapin.crypto import KeyManager
from schemapin.utils import SchemaSigningWorkflow, SchemaVerificationWorkflow, create_well_known_response
from schemapin.interactive import ConsoleInteractiveHandler


class DemoRunner:
    """Manages demo scenarios and test data."""
    
    def __init__(self, base_dir: Path):
        self.base_dir = base_dir
        self.test_data_dir = base_dir / "test_data"
        self.keys_dir = self.test_data_dir / "keys"
        self.signed_schemas_dir = self.test_data_dir / "signed_schemas"
        self.verification_results_dir = self.test_data_dir / "verification_results"
        self.sample_schemas_dir = base_dir / "sample_schemas"
        
        # Ensure directories exist
        for dir_path in [self.test_data_dir, self.keys_dir, self.signed_schemas_dir, self.verification_results_dir]:
            dir_path.mkdir(parents=True, exist_ok=True)
    
    def setup_demo_environment(self):
        """Set up demo environment with test keys and data."""
        print("🔧 Setting up demo environment...")
        
        # Generate test keys for different developers
        developers = [
            {"name": "Alice Corp", "domain": "alice.example.com"},
            {"name": "Bob Industries", "domain": "bob.example.com"},
            {"name": "Charlie Tech", "domain": "charlie.example.com"}
        ]
        
        for dev in developers:
            print(f"  Generating keys for {dev['name']}...")
            
            # Generate key pair
            private_key, public_key = KeyManager.generate_keypair()
            
            # Save keys
            private_key_file = self.keys_dir / f"{dev['domain']}_private.pem"
            public_key_file = self.keys_dir / f"{dev['domain']}_public.pem"
            
            private_key_pem = KeyManager.export_private_key_pem(private_key)
            public_key_pem = KeyManager.export_public_key_pem(public_key)
            
            private_key_file.write_text(private_key_pem)
            public_key_file.write_text(public_key_pem)
            
            # Create .well-known response
            well_known_data = create_well_known_response(
                public_key_pem=public_key_pem,
                developer_name=dev['name'],
                contact=f"security@{dev['domain']}"
            )
            
            well_known_file = self.keys_dir / f"{dev['domain']}_well_known.json"
            well_known_file.write_text(json.dumps(well_known_data, indent=2))
        
        print("✅ Demo environment setup complete!")
        return True
    
    def load_sample_schema(self, schema_name: str) -> Dict[str, Any]:
        """Load a sample schema by name."""
        schema_file = self.sample_schemas_dir / f"{schema_name}.json"
        if not schema_file.exists():
            raise FileNotFoundError(f"Sample schema not found: {schema_file}")
        
        return json.loads(schema_file.read_text())
    
    def scenario_1_python_signs_js_verifies(self):
        """Scenario 1: Python signs schema, JavaScript verifies with auto-pinning."""
        print("\n🧪 Scenario 1: Python Signs → JavaScript Verifies (Auto-pinning)")
        print("=" * 70)
        
        # Load schema and keys
        schema = self.load_sample_schema("mcp_tool")
        private_key_file = self.keys_dir / "alice.example.com_private.pem"
        private_key_pem = private_key_file.read_text()
        
        # Sign schema with Python
        print("📝 Signing schema with Python...")
        signing_workflow = SchemaSigningWorkflow(private_key_pem)
        signature = signing_workflow.sign_schema(schema)
        
        # Create signed schema file
        signed_schema = {
            "schema": schema,
            "signature": signature,
            "signed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "metadata": {
                "developer": "Alice Corp",
                "domain": "alice.example.com",
                "tool_id": "alice.example.com/calculate_sum"
            }
        }
        
        signed_file = self.signed_schemas_dir / "scenario1_python_signed.json"
        signed_file.write_text(json.dumps(signed_schema, indent=2))
        
        print(f"✅ Schema signed and saved to {signed_file}")
        print(f"   Signature: {signature[:50]}...")
        
        # Verify with JavaScript (if Node.js is available)
        if self._check_nodejs():
            print("🔍 Verifying with JavaScript...")
            try:
                result = subprocess.run([
                    "node", "-e", f"""
                    import {{ readFileSync }} from 'fs';
                    import {{ SchemaVerificationWorkflow }} from '../javascript/src/utils.js';
                    
                    const signedData = JSON.parse(readFileSync('{signed_file}', 'utf8'));
                    const workflow = new SchemaVerificationWorkflow();
                    
                    // Mock discovery for demo
                    workflow.discovery.getPublicKeyPem = async () => {{
                        return readFileSync('{self.keys_dir}/alice.example.com_public.pem', 'utf8');
                    }};
                    
                    const result = await workflow.verifySchema(
                        signedData.schema,
                        signedData.signature,
                        signedData.metadata.tool_id,
                        signedData.metadata.domain,
                        true  // auto-pin
                    );
                    
                    console.log(JSON.stringify(result, null, 2));
                    """
                ], capture_output=True, text=True, cwd=self.base_dir)
                
                if result.returncode == 0:
                    verification_result = json.loads(result.stdout)
                    print("✅ JavaScript verification successful!")
                    print(f"   Valid: {verification_result.get('valid')}")
                    print(f"   Pinned: {verification_result.get('pinned')}")
                    print(f"   First use: {verification_result.get('first_use')}")
                else:
                    print(f"❌ JavaScript verification failed: {result.stderr}")
            except Exception as e:
                print(f"❌ JavaScript verification error: {e}")
        else:
            print("⚠️  Node.js not available, skipping JavaScript verification")
        
        return True
    
    def scenario_2_js_signs_python_verifies(self):
        """Scenario 2: JavaScript signs schema, Python verifies with interactive pinning."""
        print("\n🧪 Scenario 2: JavaScript Signs → Python Verifies (Interactive)")
        print("=" * 70)
        
        if not self._check_nodejs():
            print("⚠️  Node.js not available, skipping JavaScript signing")
            return False
        
        # Sign with JavaScript
        print("📝 Signing schema with JavaScript...")
        schema_file = self.sample_schemas_dir / "api_endpoint.json"
        private_key_file = self.keys_dir / "bob.example.com_private.pem"
        signed_file = self.signed_schemas_dir / "scenario2_js_signed.json"
        
        try:
            result = subprocess.run([
                "node", "-e", f"""
                import {{ readFileSync, writeFileSync }} from 'fs';
                import {{ SchemaSigningWorkflow }} from '../javascript/src/utils.js';
                
                const schema = JSON.parse(readFileSync('{schema_file}', 'utf8'));
                const privateKeyPem = readFileSync('{private_key_file}', 'utf8');
                
                const workflow = new SchemaSigningWorkflow(privateKeyPem);
                const signature = workflow.signSchema(schema);
                
                const signedSchema = {{
                    schema: schema,
                    signature: signature,
                    signed_at: new Date().toISOString(),
                    metadata: {{
                        developer: "Bob Industries",
                        domain: "bob.example.com",
                        tool_id: "bob.example.com/user_api"
                    }}
                }};
                
                writeFileSync('{signed_file}', JSON.stringify(signedSchema, null, 2));
                console.log('Schema signed successfully');
                console.log('Signature:', signature.substring(0, 50) + '...');
                """
            ], capture_output=True, text=True, cwd=self.base_dir)
            
            if result.returncode == 0:
                print("✅ JavaScript signing successful!")
                print(result.stdout)
            else:
                print(f"❌ JavaScript signing failed: {result.stderr}")
                return False
        except Exception as e:
            print(f"❌ JavaScript signing error: {e}")
            return False
        
        # Verify with Python (interactive mode)
        print("🔍 Verifying with Python (interactive mode)...")
        signed_data = json.loads(signed_file.read_text())
        
        # Mock interactive handler for demo
        class DemoInteractiveHandler(ConsoleInteractiveHandler):
            def prompt_pin_key(self, context):
                print("\n🔐 Interactive Key Pinning Prompt:")
                print(f"   Tool: {context.tool_id}")
                print(f"   Domain: {context.domain}")
                print(f"   Developer: {context.key_info.developer_name}")
                print(f"   Key fingerprint: {context.key_info.fingerprint}")
                print("   Auto-accepting for demo...")
                return True
        
        verification_workflow = SchemaVerificationWorkflow()
        
        # Mock discovery for demo
        public_key_pem = (self.keys_dir / "bob.example.com_public.pem").read_text()
        verification_workflow.discovery.get_public_key_pem = lambda domain: public_key_pem
        verification_workflow.discovery.get_developer_info = lambda domain: {"developer_name": "Bob Industries"}
        verification_workflow.discovery.validate_key_not_revoked = lambda key_pem, domain: True
        
        result = verification_workflow.verify_schema(
            signed_data["schema"],
            signed_data["signature"],
            signed_data["metadata"]["tool_id"],
            signed_data["metadata"]["domain"],
            auto_pin=False  # Force interactive mode
        )
        
        print("✅ Python verification completed!")
        print(f"   Valid: {result.get('valid')}")
        print(f"   Pinned: {result.get('pinned')}")
        print(f"   First use: {result.get('first_use')}")
        
        return True
    
    def scenario_3_key_revocation(self):
        """Scenario 3: Demonstrate key rotation with revocation."""
        print("\n🧪 Scenario 3: Key Rotation with Revocation")
        print("=" * 70)
        
        # Generate old and new keys for Charlie
        print("🔑 Generating old and new keys for Charlie Tech...")
        
        old_private, old_public = KeyManager.generate_keypair()
        new_private, new_public = KeyManager.generate_keypair()
        
        old_private_pem = KeyManager.export_private_key_pem(old_private)
        old_public_pem = KeyManager.export_public_key_pem(old_public)
        new_private_pem = KeyManager.export_private_key_pem(new_private)
        new_public_pem = KeyManager.export_public_key_pem(new_public)
        
        # Calculate fingerprints
        old_fingerprint = KeyManager.calculate_key_fingerprint(old_public)
        new_fingerprint = KeyManager.calculate_key_fingerprint(new_public)
        
        print(f"   Old key fingerprint: {old_fingerprint}")
        print(f"   New key fingerprint: {new_fingerprint}")
        
        # Sign schema with old key
        schema = self.load_sample_schema("complex_nested")
        old_workflow = SchemaSigningWorkflow(old_private_pem)
        old_signature = old_workflow.sign_schema(schema)
        
        print("📝 Schema signed with old key")
        
        # Create .well-known with revoked old key
        create_well_known_response(
            public_key_pem=new_public_pem,
            developer_name="Charlie Tech",
            contact="security@charlie.example.com",
            revoked_keys=[old_fingerprint]
        )
        
        print("🚫 Created .well-known with old key revoked")
        
        # Try to verify with revoked key (should fail)
        verification_workflow = SchemaVerificationWorkflow()
        
        # Mock discovery to return new key but show old key as revoked
        verification_workflow.discovery.get_public_key_pem = lambda domain: new_public_pem
        verification_workflow.discovery.validate_key_not_revoked = lambda key_pem, domain: key_pem != old_public_pem
        
        # This should fail because signature was made with revoked key
        result = verification_workflow.verify_schema(
            schema,
            old_signature,
            "charlie.example.com/complex_tool",
            "charlie.example.com",
            auto_pin=True
        )
        
        print("🔍 Verification with revoked key:")
        print(f"   Valid: {result.get('valid')}")
        print(f"   Error: {result.get('error')}")
        
        # Sign with new key and verify (should succeed)
        new_workflow = SchemaSigningWorkflow(new_private_pem)
        new_signature = new_workflow.sign_schema(schema)
        
        result = verification_workflow.verify_schema(
            schema,
            new_signature,
            "charlie.example.com/complex_tool_v2",
            "charlie.example.com",
            auto_pin=True
        )
        
        print("🔍 Verification with new key:")
        print(f"   Valid: {result.get('valid')}")
        print(f"   Pinned: {result.get('pinned')}")
        
        return True
    
    def scenario_4_batch_processing(self):
        """Scenario 4: Cross-language batch processing."""
        print("\n🧪 Scenario 4: Cross-language Batch Processing")
        print("=" * 70)
        
        # Load all sample schemas
        schemas = []
        for schema_file in self.sample_schemas_dir.glob("*.json"):
            schema = json.loads(schema_file.read_text())
            schemas.append({
                "name": schema_file.stem,
                "schema": schema
            })
        
        print(f"📦 Processing {len(schemas)} schemas...")
        
        # Sign all schemas with Python
        private_key_pem = (self.keys_dir / "alice.example.com_private.pem").read_text()
        signing_workflow = SchemaSigningWorkflow(private_key_pem)
        
        signed_schemas = []
        for item in schemas:
            signature = signing_workflow.sign_schema(item["schema"])
            signed_schemas.append({
                "name": item["name"],
                "schema": item["schema"],
                "signature": signature,
                "metadata": {
                    "developer": "Alice Corp",
                    "domain": "alice.example.com",
                    "tool_id": f"alice.example.com/{item['name']}"
                }
            })
        
        print("✅ All schemas signed with Python")
        
        # Verify all with Python
        verification_workflow = SchemaVerificationWorkflow()
        public_key_pem = (self.keys_dir / "alice.example.com_public.pem").read_text()
        verification_workflow.discovery.get_public_key_pem = lambda domain: public_key_pem
        verification_workflow.discovery.validate_key_not_revoked = lambda key_pem, domain: True
        
        valid_count = 0
        for signed_item in signed_schemas:
            result = verification_workflow.verify_schema(
                signed_item["schema"],
                signed_item["signature"],
                signed_item["metadata"]["tool_id"],
                signed_item["metadata"]["domain"],
                auto_pin=True
            )
            if result.get("valid"):
                valid_count += 1
        
        print(f"✅ Python verification: {valid_count}/{len(signed_schemas)} valid")
        
        # Save batch results
        batch_file = self.verification_results_dir / "batch_results.json"
        batch_file.write_text(json.dumps({
            "total_schemas": len(signed_schemas),
            "valid_signatures": valid_count,
            "schemas": signed_schemas
        }, indent=2))
        
        return True
    
    def scenario_5_server_discovery(self):
        """Scenario 5: Server-based discovery and verification."""
        print("\n🧪 Scenario 5: Server-based Discovery")
        print("=" * 70)
        
        print("🌐 This scenario requires the .well-known server to be running")
        print("   Start the server with: cd ../server && python well_known_server.py")
        print("   Then run this scenario again")
        
        # Check if server is running
        try:
            import requests
            response = requests.get("http://localhost:8000/health", timeout=2)
            if response.status_code == 200:
                print("✅ Server is running!")
                
                # Test discovery endpoints
                developers = ["alice.example.com", "bob.example.com", "charlie.example.com"]
                for domain in developers:
                    try:
                        well_known_url = f"http://localhost:8000/.well-known/schemapin/{domain}.json"
                        response = requests.get(well_known_url, timeout=2)
                        if response.status_code == 200:
                            data = response.json()
                            print(f"   ✅ {domain}: {data.get('developer_name')}")
                        else:
                            print(f"   ❌ {domain}: HTTP {response.status_code}")
                    except Exception as e:
                        print(f"   ❌ {domain}: {e}")
                
                return True
            else:
                print("❌ Server health check failed")
        except ImportError:
            print("⚠️  requests library not available")
        except Exception as e:
            print(f"❌ Server not reachable: {e}")
        
        return False
    
    def _check_nodejs(self) -> bool:
        """Check if Node.js is available."""
        try:
            result = subprocess.run(["node", "--version"], capture_output=True, text=True)
            return result.returncode == 0
        except FileNotFoundError:
            return False


def main():
    """Main entry point for demo scenarios."""
    parser = argparse.ArgumentParser(
        description="SchemaPin Integration Demo",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --setup                    # Set up demo environment
  %(prog)s --scenario 1               # Run scenario 1
  %(prog)s --interactive              # Interactive mode
  %(prog)s --all                      # Run all scenarios
        """
    )
    
    parser.add_argument(
        '--setup',
        action='store_true',
        help='Set up demo environment with test keys and data'
    )
    
    parser.add_argument(
        '--scenario',
        type=int,
        choices=[1, 2, 3, 4, 5],
        help='Run specific scenario (1-5)'
    )
    
    parser.add_argument(
        '--all',
        action='store_true',
        help='Run all scenarios'
    )
    
    parser.add_argument(
        '--interactive',
        action='store_true',
        help='Interactive mode for scenario selection'
    )
    
    parser.add_argument(
        '--debug',
        action='store_true',
        help='Enable debug output'
    )
    
    args = parser.parse_args()
    
    # Initialize demo runner
    base_dir = Path(__file__).parent
    demo = DemoRunner(base_dir)
    
    if args.setup:
        demo.setup_demo_environment()
        return
    
    # Ensure demo environment exists
    if not (demo.keys_dir / "alice.example.com_private.pem").exists():
        print("⚠️  Demo environment not set up. Run with --setup first.")
        return
    
    print("🧷 SchemaPin Integration Demo")
    print("=" * 50)
    
    if args.scenario:
        scenarios = {
            1: demo.scenario_1_python_signs_js_verifies,
            2: demo.scenario_2_js_signs_python_verifies,
            3: demo.scenario_3_key_revocation,
            4: demo.scenario_4_batch_processing,
            5: demo.scenario_5_server_discovery
        }
        
        if args.scenario in scenarios:
            scenarios[args.scenario]()
        else:
            print(f"❌ Invalid scenario: {args.scenario}")
    
    elif args.all:
        scenarios = [
            demo.scenario_1_python_signs_js_verifies,
            demo.scenario_2_js_signs_python_verifies,
            demo.scenario_3_key_revocation,
            demo.scenario_4_batch_processing,
            demo.scenario_5_server_discovery
        ]
        
        for i, scenario in enumerate(scenarios, 1):
            try:
                scenario()
            except Exception as e:
                print(f"❌ Scenario {i} failed: {e}")
                if args.debug:
                    import traceback
                    traceback.print_exc()
    
    elif args.interactive:
        while True:
            print("\n📋 Available Scenarios:")
            print("  1. Python Signs → JavaScript Verifies (Auto-pinning)")
            print("  2. JavaScript Signs → Python Verifies (Interactive)")
            print("  3. Key Rotation with Revocation")
            print("  4. Cross-language Batch Processing")
            print("  5. Server-based Discovery")
            print("  0. Exit")
            
            try:
                choice = input("\nSelect scenario (0-5): ").strip()
                if choice == "0":
                    break
                elif choice in ["1", "2", "3", "4", "5"]:
                    scenario_num = int(choice)
                    scenarios = {
                        1: demo.scenario_1_python_signs_js_verifies,
                        2: demo.scenario_2_js_signs_python_verifies,
                        3: demo.scenario_3_key_revocation,
                        4: demo.scenario_4_batch_processing,
                        5: demo.scenario_5_server_discovery
                    }
                    scenarios[scenario_num]()
                else:
                    print("❌ Invalid choice. Please select 0-5.")
            except KeyboardInterrupt:
                print("\n👋 Goodbye!")
                break
            except Exception as e:
                print(f"❌ Error: {e}")
                if args.debug:
                    import traceback
                    traceback.print_exc()
    
    else:
        parser.print_help()


if __name__ == "__main__":
    main()