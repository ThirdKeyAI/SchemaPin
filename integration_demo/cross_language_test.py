#!/usr/bin/env python3
"""
Cross-language integration testing for SchemaPin.

Automated testing suite that validates compatibility between Python and JavaScript
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
from schemapin.utils import SchemaSigningWorkflow, SchemaVerificationWorkflow
from schemapin.core import SchemaPinCore


class CrossLanguageTestSuite:
    """Test suite for cross-language compatibility."""
    
    def __init__(self, base_dir: Path):
        self.base_dir = base_dir
        self.test_data_dir = base_dir / "test_data"
        self.keys_dir = self.test_data_dir / "keys"
        self.sample_schemas_dir = base_dir / "sample_schemas"
        self.results_dir = self.test_data_dir / "test_results"
        
        # Ensure directories exist
        self.results_dir.mkdir(parents=True, exist_ok=True)
        
        self.test_results = []
    
    def check_nodejs(self) -> bool:
        """Check if Node.js is available."""
        try:
            result = subprocess.run(["node", "--version"], capture_output=True, text=True)
            return result.returncode == 0
        except FileNotFoundError:
            return False
    
    def load_sample_schema(self, schema_name: str) -> Dict[str, Any]:
        """Load a sample schema by name."""
        schema_file = self.sample_schemas_dir / f"{schema_name}.json"
        return json.loads(schema_file.read_text())
    
    def run_test(self, test_name: str, test_func) -> bool:
        """Run a test and record results."""
        print(f"🧪 Running {test_name}...")
        start_time = time.time()
        
        try:
            result = test_func()
            duration = time.time() - start_time
            
            self.test_results.append({
                "test": test_name,
                "status": "PASS" if result else "FAIL",
                "duration": duration,
                "error": None
            })
            
            if result:
                print(f"✅ {test_name} PASSED ({duration:.2f}s)")
            else:
                print(f"❌ {test_name} FAILED ({duration:.2f}s)")
            
            return result
        except Exception as e:
            duration = time.time() - start_time
            
            self.test_results.append({
                "test": test_name,
                "status": "ERROR",
                "duration": duration,
                "error": str(e)
            })
            
            print(f"💥 {test_name} ERROR ({duration:.2f}s): {e}")
            return False
    
    def test_schema_canonicalization_compatibility(self) -> bool:
        """Test that both implementations produce identical canonical schemas."""
        schemas = ["mcp_tool", "api_endpoint", "complex_nested"]
        
        for schema_name in schemas:
            schema = self.load_sample_schema(schema_name)
            
            # Python canonicalization
            python_canonical = SchemaPinCore.canonicalize_schema(schema)
            
            # JavaScript canonicalization
            if not self.check_nodejs():
                print("⚠️  Node.js not available, skipping JS canonicalization test")
                return False
            
            js_script = f"""
            import {{ SchemaPinCore }} from '../javascript/src/core.js';
            import {{ readFileSync }} from 'fs';
            
            const schema = JSON.parse(readFileSync('{self.sample_schemas_dir / schema_name}.json', 'utf8'));
            const canonical = SchemaPinCore.canonicalizeSchema(schema);
            console.log(canonical);
            """
            
            try:
                result = subprocess.run(
                    ["node", "-e", js_script],
                    capture_output=True,
                    text=True,
                    cwd=self.base_dir
                )
                
                if result.returncode != 0:
                    print(f"❌ JavaScript canonicalization failed for {schema_name}: {result.stderr}")
                    return False
                
                js_canonical = result.stdout.strip()
                
                if python_canonical != js_canonical:
                    print(f"❌ Canonicalization mismatch for {schema_name}")
                    print(f"   Python: {python_canonical[:100]}...")
                    print(f"   JavaScript: {js_canonical[:100]}...")
                    return False
                
            except Exception as e:
                print(f"❌ Error testing {schema_name}: {e}")
                return False
        
        return True
    
    def test_cross_language_signing_verification(self) -> bool:
        """Test signing in one language and verifying in another."""
        schema = self.load_sample_schema("mcp_tool")
        
        # Load test keys
        private_key_file = self.keys_dir / "alice.example.com_private.pem"
        public_key_file = self.keys_dir / "alice.example.com_public.pem"
        
        if not private_key_file.exists() or not public_key_file.exists():
            print("❌ Test keys not found. Run demo setup first.")
            return False
        
        private_key_pem = private_key_file.read_text()
        public_key_pem = public_key_file.read_text()
        
        # Test 1: Python signs, JavaScript verifies
        python_workflow = SchemaSigningWorkflow(private_key_pem)
        python_signature = python_workflow.sign_schema(schema)
        
        if not self.check_nodejs():
            print("⚠️  Node.js not available, skipping cross-language verification")
            return False
        
        js_verify_script = f"""
        import {{ SchemaVerificationWorkflow }} from '../javascript/src/utils.js';
        import {{ readFileSync }} from 'fs';
        
        const schema = {json.dumps(schema)};
        const signature = '{python_signature}';
        const publicKeyPem = readFileSync('{public_key_file}', 'utf8');
        
        const workflow = new SchemaVerificationWorkflow();
        workflow.discovery.getPublicKeyPem = async () => publicKeyPem;
        workflow.discovery.validateKeyNotRevoked = async () => true;
        
        const result = await workflow.verifySchema(
            schema,
            signature,
            'alice.example.com/test_tool',
            'alice.example.com',
            true
        );
        
        console.log(JSON.stringify(result));
        """
        
        try:
            result = subprocess.run(
                ["node", "-e", js_verify_script],
                capture_output=True,
                text=True,
                cwd=self.base_dir
            )
            
            if result.returncode != 0:
                print(f"❌ JavaScript verification failed: {result.stderr}")
                return False
            
            js_result = json.loads(result.stdout.strip())
            if not js_result.get("valid"):
                print(f"❌ JavaScript verification returned invalid: {js_result}")
                return False
            
        except Exception as e:
            print(f"❌ Error in Python→JavaScript test: {e}")
            return False
        
        # Test 2: JavaScript signs, Python verifies
        js_sign_script = f"""
        import {{ SchemaSigningWorkflow }} from '../javascript/src/utils.js';
        import {{ readFileSync }} from 'fs';
        
        const schema = {json.dumps(schema)};
        const privateKeyPem = readFileSync('{private_key_file}', 'utf8');
        
        const workflow = new SchemaSigningWorkflow(privateKeyPem);
        const signature = workflow.signSchema(schema);
        
        console.log(signature);
        """
        
        try:
            result = subprocess.run(
                ["node", "-e", js_sign_script],
                capture_output=True,
                text=True,
                cwd=self.base_dir
            )
            
            if result.returncode != 0:
                print(f"❌ JavaScript signing failed: {result.stderr}")
                return False
            
            js_signature = result.stdout.strip()
            
            # Verify with Python
            python_verify_workflow = SchemaVerificationWorkflow()
            python_verify_workflow.discovery.get_public_key_pem = lambda domain: public_key_pem
            python_verify_workflow.discovery.validate_key_not_revoked = lambda key_pem, domain: True
            
            python_result = python_verify_workflow.verify_schema(
                schema,
                js_signature,
                "alice.example.com/test_tool",
                "alice.example.com",
                auto_pin=True
            )
            
            if not python_result.get("valid"):
                print(f"❌ Python verification of JS signature failed: {python_result}")
                return False
            
        except Exception as e:
            print(f"❌ Error in JavaScript→Python test: {e}")
            return False
        
        return True
    
    def test_key_fingerprint_compatibility(self) -> bool:
        """Test that key fingerprints are identical across implementations."""
        public_key_file = self.keys_dir / "alice.example.com_public.pem"
        
        if not public_key_file.exists():
            print("❌ Test keys not found. Run demo setup first.")
            return False
        
        public_key_pem = public_key_file.read_text()
        
        # Python fingerprint
        public_key = KeyManager.load_public_key_pem(public_key_pem)
        python_fingerprint = KeyManager.calculate_key_fingerprint(public_key)
        
        # JavaScript fingerprint
        if not self.check_nodejs():
            print("⚠️  Node.js not available, skipping JS fingerprint test")
            return False
        
        js_script = f"""
        import {{ KeyManager }} from '../javascript/src/crypto.js';
        import {{ readFileSync }} from 'fs';
        
        const publicKeyPem = readFileSync('{public_key_file}', 'utf8');
        const publicKey = KeyManager.loadPublicKeyPem(publicKeyPem);
        const fingerprint = KeyManager.calculateKeyFingerprint(publicKey);
        
        console.log(fingerprint);
        """
        
        try:
            result = subprocess.run(
                ["node", "-e", js_script],
                capture_output=True,
                text=True,
                cwd=self.base_dir
            )
            
            if result.returncode != 0:
                print(f"❌ JavaScript fingerprint calculation failed: {result.stderr}")
                return False
            
            js_fingerprint = result.stdout.strip()
            
            if python_fingerprint != js_fingerprint:
                print("❌ Fingerprint mismatch:")
                print(f"   Python: {python_fingerprint}")
                print(f"   JavaScript: {js_fingerprint}")
                return False
            
        except Exception as e:
            print(f"❌ Error testing fingerprints: {e}")
            return False
        
        return True
    
    def test_well_known_format_compatibility(self) -> bool:
        """Test .well-known response format compatibility."""
        public_key_file = self.keys_dir / "alice.example.com_public.pem"
        
        if not public_key_file.exists():
            print("❌ Test keys not found. Run demo setup first.")
            return False
        
        public_key_pem = public_key_file.read_text()
        
        # Python .well-known creation
        from schemapin.utils import create_well_known_response
        python_well_known = create_well_known_response(
            public_key_pem=public_key_pem,
            developer_name="Test Developer",
            contact="test@example.com",
            revoked_keys=["sha256:abc123"],
            schema_version="1.1"
        )
        
        # JavaScript .well-known creation
        if not self.check_nodejs():
            print("⚠️  Node.js not available, skipping JS .well-known test")
            return False
        
        js_script = f"""
        import {{ createWellKnownResponse }} from '../javascript/src/utils.js';
        import {{ readFileSync }} from 'fs';
        
        const publicKeyPem = readFileSync('{public_key_file}', 'utf8');
        const wellKnown = createWellKnownResponse(
            publicKeyPem,
            "Test Developer",
            "test@example.com",
            ["sha256:abc123"],
            "1.1"
        );
        
        console.log(JSON.stringify(wellKnown, null, 2));
        """
        
        try:
            result = subprocess.run(
                ["node", "-e", js_script],
                capture_output=True,
                text=True,
                cwd=self.base_dir
            )
            
            if result.returncode != 0:
                print(f"❌ JavaScript .well-known creation failed: {result.stderr}")
                return False
            
            js_well_known = json.loads(result.stdout.strip())
            
            # Compare structures (order might differ)
            if (python_well_known.get("schema_version") != js_well_known.get("schema_version") or
                python_well_known.get("developer_name") != js_well_known.get("developer_name") or
                python_well_known.get("contact") != js_well_known.get("contact") or
                python_well_known.get("revoked_keys") != js_well_known.get("revoked_keys")):
                
                print("❌ .well-known format mismatch:")
                print(f"   Python: {json.dumps(python_well_known, indent=2)}")
                print(f"   JavaScript: {json.dumps(js_well_known, indent=2)}")
                return False
            
        except Exception as e:
            print(f"❌ Error testing .well-known format: {e}")
            return False
        
        return True
    
    def run_performance_tests(self) -> bool:
        """Run performance benchmarks."""
        print("\n🚀 Running Performance Tests...")
        
        schema = self.load_sample_schema("complex_nested")
        private_key_file = self.keys_dir / "alice.example.com_private.pem"
        
        if not private_key_file.exists():
            print("❌ Test keys not found. Run demo setup first.")
            return False
        
        private_key_pem = private_key_file.read_text()
        
        # Python performance
        python_workflow = SchemaSigningWorkflow(private_key_pem)
        
        iterations = 100
        start_time = time.time()
        for _ in range(iterations):
            python_workflow.sign_schema(schema)
        python_duration = time.time() - start_time
        
        print(f"📊 Python signing: {iterations} iterations in {python_duration:.2f}s ({python_duration/iterations*1000:.2f}ms per signature)")
        
        # JavaScript performance (if available)
        if self.check_nodejs():
            js_script = f"""
            import {{ SchemaSigningWorkflow }} from '../javascript/src/utils.js';
            import {{ readFileSync }} from 'fs';
            
            const schema = {json.dumps(schema)};
            const privateKeyPem = readFileSync('{private_key_file}', 'utf8');
            const workflow = new SchemaSigningWorkflow(privateKeyPem);
            
            const iterations = {iterations};
            const startTime = Date.now();
            
            for (let i = 0; i < iterations; i++) {{
                workflow.signSchema(schema);
            }}
            
            const duration = (Date.now() - startTime) / 1000;
            console.log(`JavaScript signing: ${{iterations}} iterations in ${{duration.toFixed(2)}}s (${{(duration/iterations*1000).toFixed(2)}}ms per signature)`);
            """
            
            try:
                result = subprocess.run(
                    ["node", "-e", js_script],
                    capture_output=True,
                    text=True,
                    cwd=self.base_dir
                )
                
                if result.returncode == 0:
                    print(f"📊 {result.stdout.strip()}")
                else:
                    print(f"❌ JavaScript performance test failed: {result.stderr}")
            
            except Exception as e:
                print(f"❌ Error in JavaScript performance test: {e}")
        
        return True
    
    def run_security_tests(self) -> bool:
        """Run security validation tests."""
        print("\n🔒 Running Security Tests...")
        
        # Test signature tampering detection
        schema = self.load_sample_schema("mcp_tool")
        private_key_file = self.keys_dir / "alice.example.com_private.pem"
        public_key_file = self.keys_dir / "alice.example.com_public.pem"
        
        if not private_key_file.exists() or not public_key_file.exists():
            print("❌ Test keys not found. Run demo setup first.")
            return False
        
        private_key_pem = private_key_file.read_text()
        public_key_pem = public_key_file.read_text()
        
        # Create valid signature
        workflow = SchemaSigningWorkflow(private_key_pem)
        valid_signature = workflow.sign_schema(schema)
        
        # Tamper with signature
        tampered_signature = valid_signature[:-10] + "tampered123"
        
        # Test Python detection
        verify_workflow = SchemaVerificationWorkflow()
        verify_workflow.discovery.get_public_key_pem = lambda domain: public_key_pem
        verify_workflow.discovery.validate_key_not_revoked = lambda key_pem, domain: True
        
        result = verify_workflow.verify_schema(
            schema,
            tampered_signature,
            "alice.example.com/test_tool",
            "alice.example.com",
            auto_pin=True
        )
        
        if result.get("valid"):
            print("❌ Python failed to detect tampered signature")
            return False
        
        print("✅ Python correctly detected tampered signature")
        
        # Test JavaScript detection (if available)
        if self.check_nodejs():
            js_script = f"""
            import {{ SchemaVerificationWorkflow }} from '../javascript/src/utils.js';
            import {{ readFileSync }} from 'fs';
            
            const schema = {json.dumps(schema)};
            const tamperedSignature = '{tampered_signature}';
            const publicKeyPem = readFileSync('{public_key_file}', 'utf8');
            
            const workflow = new SchemaVerificationWorkflow();
            workflow.discovery.getPublicKeyPem = async () => publicKeyPem;
            workflow.discovery.validateKeyNotRevoked = async () => true;
            
            const result = await workflow.verifySchema(
                schema,
                tamperedSignature,
                'alice.example.com/test_tool',
                'alice.example.com',
                true
            );
            
            console.log(result.valid ? 'FAIL' : 'PASS');
            """
            
            try:
                result = subprocess.run(
                    ["node", "-e", js_script],
                    capture_output=True,
                    text=True,
                    cwd=self.base_dir
                )
                
                if result.returncode == 0:
                    js_result = result.stdout.strip()
                    if js_result == "PASS":
                        print("✅ JavaScript correctly detected tampered signature")
                    else:
                        print("❌ JavaScript failed to detect tampered signature")
                        return False
                else:
                    print(f"❌ JavaScript security test failed: {result.stderr}")
                    return False
            
            except Exception as e:
                print(f"❌ Error in JavaScript security test: {e}")
                return False
        
        return True
    
    def generate_report(self):
        """Generate test report."""
        report = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "summary": {
                "total_tests": len(self.test_results),
                "passed": len([r for r in self.test_results if r["status"] == "PASS"]),
                "failed": len([r for r in self.test_results if r["status"] == "FAIL"]),
                "errors": len([r for r in self.test_results if r["status"] == "ERROR"])
            },
            "results": self.test_results
        }
        
        report_file = self.results_dir / "cross_language_test_report.json"
        report_file.write_text(json.dumps(report, indent=2))
        
        print(f"\n📋 Test Report Generated: {report_file}")
        print(f"   Total: {report['summary']['total_tests']}")
        print(f"   Passed: {report['summary']['passed']}")
        print(f"   Failed: {report['summary']['failed']}")
        print(f"   Errors: {report['summary']['errors']}")
        
        return report["summary"]["failed"] == 0 and report["summary"]["errors"] == 0


def main():
    """Main entry point for cross-language testing."""
    parser = argparse.ArgumentParser(
        description="Cross-language integration testing for SchemaPin",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        '--performance',
        action='store_true',
        help='Run performance benchmarks'
    )
    
    parser.add_argument(
        '--security',
        action='store_true',
        help='Run security validation tests'
    )
    
    parser.add_argument(
        '--all',
        action='store_true',
        help='Run all tests including performance and security'
    )
    
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Verbose output'
    )
    
    args = parser.parse_args()
    
    base_dir = Path(__file__).parent
    test_suite = CrossLanguageTestSuite(base_dir)
    
    print("🧷 SchemaPin Cross-Language Integration Tests")
    print("=" * 50)
    
    # Core compatibility tests
    test_suite.run_test("Schema Canonicalization Compatibility", 
                       test_suite.test_schema_canonicalization_compatibility)
    
    test_suite.run_test("Cross-Language Signing/Verification", 
                       test_suite.test_cross_language_signing_verification)
    
    test_suite.run_test("Key Fingerprint Compatibility", 
                       test_suite.test_key_fingerprint_compatibility)
    
    test_suite.run_test(".well-known Format Compatibility", 
                       test_suite.test_well_known_format_compatibility)
    
    # Optional tests
    if args.performance or args.all:
        test_suite.run_test("Performance Benchmarks", 
                           test_suite.run_performance_tests)
    
    if args.security or args.all:
        test_suite.run_test("Security Validation", 
                           test_suite.run_security_tests)
    
    # Generate report
    success = test_suite.generate_report()
    
    if success:
        print("\n✅ All tests passed!")
        sys.exit(0)
    else:
        print("\n❌ Some tests failed!")
        sys.exit(1)


if __name__ == "__main__":
    main()