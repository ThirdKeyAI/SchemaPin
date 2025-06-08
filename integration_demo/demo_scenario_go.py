#!/usr/bin/env python3
"""
Go CLI Integration Demo for SchemaPin

This script demonstrates integration between Go CLI tools and Python/JavaScript libraries,
showcasing cross-language compatibility and CLI automation workflows.
"""

import sys
import json
import subprocess
import tempfile
import shutil
from pathlib import Path
from typing import List, Optional

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    from python.schemapin.crypto import KeyManager
    from python.schemapin.utils import SchemaVerificationWorkflow
except ImportError:
    print("❌ Python SchemaPin package not found. Please install it first:")
    print("cd ../python && pip install -e .")
    sys.exit(1)


class GoCliIntegrationDemo:
    """Demonstrates Go CLI integration with Python/JavaScript libraries."""
    
    def __init__(self):
        """Initialize the demo."""
        self.root_dir = Path(__file__).parent.parent
        self.go_dir = self.root_dir / "go"
        self.demo_dir = Path(__file__).parent
        self.test_data_dir = self.demo_dir / "test_data"
        self.go_binaries_dir = self.test_data_dir / "go_binaries"
        
        # Ensure test data directory exists
        self.test_data_dir.mkdir(exist_ok=True)
        self.go_binaries_dir.mkdir(exist_ok=True)
        
        # Go CLI tool paths
        self.keygen_tool = None
        self.sign_tool = None
        self.verify_tool = None
        
    def setup_go_tools(self) -> bool:
        """Set up Go CLI tools for testing."""
        print("🔧 Setting up Go CLI tools...")
        
        # Check if Go tools are built
        go_bin_dir = self.go_dir / "bin"
        if not go_bin_dir.exists():
            print("Building Go CLI tools...")
            try:
                subprocess.run(["make", "build"], cwd=self.go_dir, check=True)
            except subprocess.CalledProcessError:
                print("❌ Failed to build Go CLI tools")
                return False
        
        # Copy tools to test directory
        tools = ["schemapin-keygen", "schemapin-sign", "schemapin-verify"]
        for tool in tools:
            src = go_bin_dir / tool
            dst = self.go_binaries_dir / tool
            
            if src.exists():
                shutil.copy2(src, dst)
                dst.chmod(0o755)
                print(f"✅ Copied {tool}")
            else:
                print(f"❌ Tool {tool} not found")
                return False
        
        # Set tool paths
        self.keygen_tool = self.go_binaries_dir / "schemapin-keygen"
        self.sign_tool = self.go_binaries_dir / "schemapin-sign"
        self.verify_tool = self.go_binaries_dir / "schemapin-verify"
        
        return True
    
    def run_command(self, cmd: List[str], cwd: Optional[Path] = None) -> subprocess.CompletedProcess:
        """Run a command and return the result."""
        cwd = cwd or self.test_data_dir
        print(f"Running: {' '.join(cmd)}")
        return subprocess.run(cmd, cwd=cwd, check=True, capture_output=True, text=True)
    
    def scenario_go_signs_python_verifies(self) -> bool:
        """Scenario: Go CLI signs, Python library verifies."""
        print("\n🎯 Scenario: Go CLI Signs → Python Library Verifies")
        
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            
            try:
                # Generate keys with Go CLI
                print("🔑 Generating keys with Go CLI...")
                self.run_command([
                    str(self.keygen_tool),
                    "--developer", "Go CLI Demo",
                    "--contact", "demo@gocli.com",
                    "--private-key", "go_private.pem",
                    "--public-key", "go_public.pem"
                ], cwd=temp_path)
                
                # Create test schema
                schema = {
                    "name": "go_cli_tool",
                    "description": "A tool signed by Go CLI",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "input": {"type": "string", "description": "Input parameter"}
                        },
                        "required": ["input"]
                    }
                }
                
                schema_file = temp_path / "test_schema.json"
                with open(schema_file, 'w') as f:
                    json.dump(schema, f, indent=2)
                
                # Sign schema with Go CLI
                print("✍️  Signing schema with Go CLI...")
                self.run_command([
                    str(self.sign_tool),
                    "--key", "go_private.pem",
                    "--schema", "test_schema.json",
                    "--output", "signed_schema.json"
                ], cwd=temp_path)
                
                # Load signed schema
                with open(temp_path / "signed_schema.json") as f:
                    signed_data = json.load(f)
                
                # Load public key
                with open(temp_path / "go_public.pem") as f:
                    public_key_pem = f.read()
                
                # Verify with Python library
                print("🔍 Verifying signature with Python library...")
                workflow = SchemaVerificationWorkflow()
                public_key = KeyManager.load_public_key_pem(public_key_pem)
                
                is_valid = workflow.verify_schema_signature(
                    signed_data["schema"],
                    signed_data["signature"],
                    public_key
                )
                
                if is_valid:
                    print("✅ Python successfully verified Go CLI signature!")
                    return True
                else:
                    print("❌ Python failed to verify Go CLI signature")
                    return False
                    
            except Exception as e:
                print(f"❌ Scenario failed: {e}")
                return False
    
    def scenario_python_signs_go_verifies(self) -> bool:
        """Scenario: Python library signs, Go CLI verifies."""
        print("\n🎯 Scenario: Python Library Signs → Go CLI Verifies")
        
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            
            try:
                # Generate keys with Python
                print("🔑 Generating keys with Python library...")
                private_key, public_key = KeyManager.generate_keypair()
                private_key_pem = KeyManager.export_private_key_pem(private_key)
                public_key_pem = KeyManager.export_public_key_pem(public_key)
                
                # Save keys
                with open(temp_path / "python_private.pem", 'w') as f:
                    f.write(private_key_pem)
                with open(temp_path / "python_public.pem", 'w') as f:
                    f.write(public_key_pem)
                
                # Create and sign schema with Python
                schema = {
                    "name": "python_lib_tool",
                    "description": "A tool signed by Python library",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "data": {"type": "string", "description": "Data parameter"}
                        },
                        "required": ["data"]
                    }
                }
                
                print("✍️  Signing schema with Python library...")
                from python.schemapin.utils import SchemaSigningWorkflow
                signing_workflow = SchemaSigningWorkflow(private_key_pem)
                signature = signing_workflow.sign_schema(schema)
                
                # Save signed schema
                signed_data = {
                    "schema": schema,
                    "signature": signature
                }
                
                with open(temp_path / "python_signed.json", 'w') as f:
                    json.dump(signed_data, f, indent=2)
                
                # Verify with Go CLI
                print("🔍 Verifying signature with Go CLI...")
                result = self.run_command([
                    str(self.verify_tool),
                    "--schema", "python_signed.json",
                    "--public-key", "python_public.pem"
                ], cwd=temp_path)
                
                if result.returncode == 0:
                    print("✅ Go CLI successfully verified Python library signature!")
                    return True
                else:
                    print("❌ Go CLI failed to verify Python library signature")
                    print(f"stderr: {result.stderr}")
                    return False
                    
            except Exception as e:
                print(f"❌ Scenario failed: {e}")
                return False
    
    def scenario_cli_automation_workflow(self) -> bool:
        """Scenario: Automated CLI workflow with multiple tools."""
        print("\n🎯 Scenario: CLI Automation Workflow")
        
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            
            try:
                # Simulate a developer workflow
                print("🏭 Simulating developer workflow...")
                
                # Step 1: Generate developer keys
                self.run_command([
                    str(self.keygen_tool),
                    "--developer", "Automation Corp",
                    "--contact", "security@automation.com",
                    "--well-known"
                ], cwd=temp_path)
                
                # Step 2: Sign multiple schemas
                schemas = [
                    {
                        "name": "file_manager",
                        "description": "File management tool",
                        "parameters": {"type": "object", "properties": {"path": {"type": "string"}}}
                    },
                    {
                        "name": "calculator",
                        "description": "Mathematical calculator",
                        "parameters": {"type": "object", "properties": {"expression": {"type": "string"}}}
                    },
                    {
                        "name": "weather_api",
                        "description": "Weather information API",
                        "parameters": {"type": "object", "properties": {"location": {"type": "string"}}}
                    }
                ]
                
                signed_schemas = []
                for i, schema in enumerate(schemas):
                    schema_file = temp_path / f"schema_{i}.json"
                    signed_file = temp_path / f"signed_{i}.json"
                    
                    with open(schema_file, 'w') as f:
                        json.dump(schema, f, indent=2)
                    
                    print(f"✍️  Signing schema {i+1}/3: {schema['name']}")
                    self.run_command([
                        str(self.sign_tool),
                        "--key", "private_key.pem",
                        "--schema", str(schema_file),
                        "--output", str(signed_file)
                    ], cwd=temp_path)
                    
                    signed_schemas.append(signed_file)
                
                # Step 3: Verify all schemas
                print("🔍 Verifying all signed schemas...")
                for i, signed_file in enumerate(signed_schemas):
                    result = self.run_command([
                        str(self.verify_tool),
                        "--schema", str(signed_file),
                        "--public-key", "public_key.pem"
                    ], cwd=temp_path)
                    
                    if result.returncode == 0:
                        print(f"✅ Schema {i+1} verified successfully")
                    else:
                        print(f"❌ Schema {i+1} verification failed")
                        return False
                
                # Step 4: Verify .well-known response exists
                well_known_file = temp_path / "well_known.json"
                if well_known_file.exists():
                    with open(well_known_file) as f:
                        well_known_data = json.load(f)
                    print(f"✅ .well-known response generated for {well_known_data.get('developer', 'Unknown')}")
                else:
                    print("⚠️  .well-known response not found")
                
                print("✅ CLI automation workflow completed successfully!")
                return True
                
            except Exception as e:
                print(f"❌ Scenario failed: {e}")
                return False
    
    def scenario_performance_comparison(self) -> bool:
        """Scenario: Performance comparison between implementations."""
        print("\n🎯 Scenario: Performance Comparison")
        
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            
            try:
                import time
                
                # Generate test data
                print("📊 Preparing performance test...")
                
                # Generate keys once
                private_key, public_key = KeyManager.generate_keypair()
                private_key_pem = KeyManager.export_private_key_pem(private_key)
                public_key_pem = KeyManager.export_public_key_pem(public_key)
                
                with open(temp_path / "perf_private.pem", 'w') as f:
                    f.write(private_key_pem)
                with open(temp_path / "perf_public.pem", 'w') as f:
                    f.write(public_key_pem)
                
                # Test schema
                schema = {
                    "name": "performance_test",
                    "description": "Schema for performance testing",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "data": {"type": "array", "items": {"type": "string"}},
                            "count": {"type": "number"},
                            "metadata": {"type": "object"}
                        }
                    }
                }
                
                with open(temp_path / "perf_schema.json", 'w') as f:
                    json.dump(schema, f, indent=2)
                
                # Test Python signing performance
                print("🐍 Testing Python signing performance...")
                from python.schemapin.utils import SchemaSigningWorkflow
                python_workflow = SchemaSigningWorkflow(private_key_pem)
                
                python_times = []
                for i in range(5):
                    start_time = time.time()
                    python_workflow.sign_schema(schema)
                    end_time = time.time()
                    python_times.append(end_time - start_time)
                
                python_avg = sum(python_times) / len(python_times)
                print(f"Python average: {python_avg:.4f}s")
                
                # Test Go CLI signing performance
                print("🐹 Testing Go CLI signing performance...")
                go_times = []
                for i in range(5):
                    start_time = time.time()
                    self.run_command([
                        str(self.sign_tool),
                        "--key", "perf_private.pem",
                        "--schema", "perf_schema.json",
                        "--output", f"go_signed_{i}.json"
                    ], cwd=temp_path)
                    end_time = time.time()
                    go_times.append(end_time - start_time)
                
                go_avg = sum(go_times) / len(go_times)
                print(f"Go CLI average: {go_avg:.4f}s")
                
                # Compare results
                if go_avg < python_avg:
                    speedup = python_avg / go_avg
                    print(f"🚀 Go CLI is {speedup:.2f}x faster than Python")
                else:
                    slowdown = go_avg / python_avg
                    print(f"🐌 Go CLI is {slowdown:.2f}x slower than Python")
                
                print("✅ Performance comparison completed!")
                return True
                
            except Exception as e:
                print(f"❌ Scenario failed: {e}")
                return False
    
    def run_all_scenarios(self) -> bool:
        """Run all integration scenarios."""
        print("🚀 Running Go CLI Integration Demo")
        print("=" * 50)
        
        if not self.setup_go_tools():
            return False
        
        scenarios = [
            ("Go CLI Signs → Python Verifies", self.scenario_go_signs_python_verifies),
            ("Python Signs → Go CLI Verifies", self.scenario_python_signs_go_verifies),
            ("CLI Automation Workflow", self.scenario_cli_automation_workflow),
            ("Performance Comparison", self.scenario_performance_comparison),
        ]
        
        results = []
        for name, scenario_func in scenarios:
            print(f"\n{'='*20} {name} {'='*20}")
            try:
                result = scenario_func()
                results.append((name, result))
                if result:
                    print(f"✅ {name} PASSED")
                else:
                    print(f"❌ {name} FAILED")
            except Exception as e:
                print(f"❌ {name} FAILED: {e}")
                results.append((name, False))
        
        # Summary
        print("\n" + "="*50)
        print("📊 DEMO RESULTS SUMMARY")
        print("="*50)
        
        passed = sum(1 for _, result in results if result)
        total = len(results)
        
        for name, result in results:
            status = "✅ PASS" if result else "❌ FAIL"
            print(f"{status} {name}")
        
        print(f"\nOverall: {passed}/{total} scenarios passed")
        
        if passed == total:
            print("🎉 All Go CLI integration scenarios passed!")
            return True
        else:
            print("❌ Some scenarios failed")
            return False


def main():
    """Main entry point."""
    demo = GoCliIntegrationDemo()
    
    if len(sys.argv) > 1:
        scenario = sys.argv[1]
        if scenario == "setup":
            success = demo.setup_go_tools()
        elif scenario == "go-python":
            success = demo.scenario_go_signs_python_verifies()
        elif scenario == "python-go":
            success = demo.scenario_python_signs_go_verifies()
        elif scenario == "automation":
            success = demo.scenario_cli_automation_workflow()
        elif scenario == "performance":
            success = demo.scenario_performance_comparison()
        else:
            print(f"Unknown scenario: {scenario}")
            print("Available scenarios: setup, go-python, python-go, automation, performance")
            sys.exit(1)
    else:
        success = demo.run_all_scenarios()
    
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()