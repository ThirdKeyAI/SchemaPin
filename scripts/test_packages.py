#!/usr/bin/env python3
"""
Package testing script for SchemaPin.

This script performs comprehensive testing of built packages including
installation testing, functionality validation, and dependency verification.
"""

import os
import sys
import subprocess
import tempfile
import shutil
import json
from pathlib import Path
from typing import List, Optional


class PackageTester:
    """Handles testing of built SchemaPin packages."""
    
    def __init__(self, root_dir: Optional[Path] = None):
        """Initialize the package tester."""
        self.root_dir = root_dir or Path(__file__).parent.parent
        self.dist_dir = self.root_dir / "dist"
        self.go_dir = self.root_dir / "go"
        
    def run_command(self, cmd: List[str], cwd: Optional[Path] = None, 
                   check: bool = True) -> subprocess.CompletedProcess:
        """Run a command and return the result."""
        cwd = cwd or self.root_dir
        print(f"Running: {' '.join(cmd)} (in {cwd})")
        return subprocess.run(cmd, cwd=cwd, check=check, capture_output=True, text=True)
    
    def test_python_package_installation(self) -> bool:
        """Test Python package installation and basic functionality."""
        print("🐍 Testing Python package installation...")
        
        # Find Python packages
        wheels = list(self.dist_dir.glob("*.whl"))
        if not wheels:
            print("❌ No Python wheel found for testing")
            return False
        
        wheel_path = wheels[0]
        print(f"Testing wheel: {wheel_path.name}")
        
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            
            try:
                # Create virtual environment
                venv_path = temp_path / "test_venv"
                self.run_command(["python", "-m", "venv", str(venv_path)])
                
                # Determine pip path
                if os.name == 'nt':  # Windows
                    pip_path = venv_path / "Scripts" / "pip"
                    python_path = venv_path / "Scripts" / "python"
                else:  # Unix-like
                    pip_path = venv_path / "bin" / "pip"
                    python_path = venv_path / "bin" / "python"
                
                # Install package
                self.run_command([str(pip_path), "install", str(wheel_path)])
                
                # Test basic import
                test_script = temp_path / "test_import.py"
                test_script.write_text("""
import schemapin
from schemapin.crypto import KeyManager
from schemapin.core import SchemaPinCore
from schemapin.utils import SchemaSigningWorkflow, SchemaVerificationWorkflow

# Test basic functionality
private_key, public_key = KeyManager.generate_keypair()
core = SchemaPinCore()
schema = {"test": "schema"}
canonical = core.canonicalize_schema(schema)
print("✅ Basic import and functionality test passed")
""")
                
                self.run_command([str(python_path), str(test_script)])
                print("✅ Python package installation test passed")
                
                # Test CLI tools
                cli_tools = ["schemapin-keygen", "schemapin-sign", "schemapin-verify"]
                for tool in cli_tools:
                    try:
                        # Test help command
                        if os.name == 'nt':
                            tool_path = venv_path / "Scripts" / f"{tool}.exe"
                        else:
                            tool_path = venv_path / "bin" / tool
                        
                        if tool_path.exists():
                            self.run_command([str(tool_path), "--help"])
                            print(f"✅ CLI tool {tool} works")
                        else:
                            print(f"⚠️  CLI tool {tool} not found at {tool_path}")
                    except subprocess.CalledProcessError:
                        print(f"⚠️  CLI tool {tool} help failed")
                
                return True
                
            except subprocess.CalledProcessError as e:
                print(f"❌ Python package test failed: {e}")
                print(f"stdout: {e.stdout}")
                print(f"stderr: {e.stderr}")
                return False
    
    def test_javascript_package_installation(self) -> bool:
        """Test JavaScript package installation and basic functionality."""
        print("📦 Testing JavaScript package installation...")
        
        # Find JavaScript packages
        tarballs = list(self.dist_dir.glob("*.tgz"))
        if not tarballs:
            print("❌ No JavaScript package found for testing")
            return False
        
        tarball_path = tarballs[0]
        print(f"Testing package: {tarball_path.name}")
        
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            
            try:
                # Create test project
                test_project = temp_path / "test_project"
                test_project.mkdir()
                
                # Initialize npm project
                package_json = test_project / "package.json"
                package_json.write_text(json.dumps({
                    "name": "schemapin-test",
                    "version": "1.0.0",
                    "type": "module"
                }, indent=2))
                
                # Install package
                self.run_command(["npm", "install", str(tarball_path)], cwd=test_project)
                
                # Test basic import and functionality
                test_script = test_project / "test.js"
                test_script.write_text("""
import { KeyManager, SchemaPinCore, SchemaSigningWorkflow, SchemaVerificationWorkflow } from 'schemapin';

// Test basic functionality
const { privateKey, publicKey } = KeyManager.generateKeypair();
const core = new SchemaPinCore();
const schema = { test: "schema" };
const canonical = core.canonicalizeSchema(schema);

console.log("✅ Basic import and functionality test passed");
""")
                
                self.run_command(["node", "test.js"], cwd=test_project)
                print("✅ JavaScript package installation test passed")
                
                return True
                
            except subprocess.CalledProcessError as e:
                print(f"❌ JavaScript package test failed: {e}")
                print(f"stdout: {e.stdout}")
                print(f"stderr: {e.stderr}")
                return False
    
    def test_go_package_installation(self) -> bool:
        """Test Go package installation and basic functionality."""
        print("🐹 Testing Go package installation...")
        
        # Check if Go binaries exist
        go_dist_dir = self.dist_dir / "go"
        if not go_dist_dir.exists():
            print("❌ No Go binaries found for testing")
            return False
        
        binaries = list(go_dist_dir.glob("*"))
        if not binaries:
            print("❌ No Go binaries found in dist/go/")
            return False
        
        print(f"Testing binaries: {[b.name for b in binaries]}")
        
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            
            try:
                # Copy binaries to temp directory and make executable
                for binary in binaries:
                    temp_binary = temp_path / binary.name
                    shutil.copy2(binary, temp_binary)
                    temp_binary.chmod(0o755)
                
                # Test keygen
                keygen_binary = temp_path / "schemapin-keygen"
                if keygen_binary.exists():
                    self.run_command([str(keygen_binary), "--help"], cwd=temp_path)
                    print("✅ schemapin-keygen works")
                
                # Test sign
                sign_binary = temp_path / "schemapin-sign"
                if sign_binary.exists():
                    self.run_command([str(sign_binary), "--help"], cwd=temp_path)
                    print("✅ schemapin-sign works")
                
                # Test verify
                verify_binary = temp_path / "schemapin-verify"
                if verify_binary.exists():
                    self.run_command([str(verify_binary), "--help"], cwd=temp_path)
                    print("✅ schemapin-verify works")
                
                # Test full workflow
                if keygen_binary.exists() and sign_binary.exists() and verify_binary.exists():
                    # Generate keys
                    self.run_command([str(keygen_binary), "--developer", "Test Developer",
                                    "--contact", "test@example.com"], cwd=temp_path)
                    
                    # Create test schema
                    test_schema = temp_path / "test_schema.json"
                    test_schema.write_text('{"name": "test", "type": "object"}')
                    
                    # Sign schema
                    self.run_command([str(sign_binary), "--key", "private_key.pem",
                                    "--schema", "test_schema.json", "--output", "signed_schema.json"],
                                   cwd=temp_path)
                    
                    # Verify schema
                    self.run_command([str(verify_binary), "--schema", "signed_schema.json",
                                    "--public-key", "public_key.pem"], cwd=temp_path)
                    
                    print("✅ Go CLI workflow test passed")
                
                return True
                
            except subprocess.CalledProcessError as e:
                print(f"❌ Go package test failed: {e}")
                print(f"stdout: {e.stdout}")
                print(f"stderr: {e.stderr}")
                return False
    
    def test_cross_language_compatibility(self) -> bool:
        """Test cross-language compatibility between Python and JavaScript packages."""
        print("🔄 Testing cross-language compatibility...")
        
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            
            try:
                # Set up Python environment
                python_venv = temp_path / "python_env"
                self.run_command(["python", "-m", "venv", str(python_venv)])
                
                if os.name == 'nt':
                    python_pip = python_venv / "Scripts" / "pip"
                    python_exe = python_venv / "Scripts" / "python"
                else:
                    python_pip = python_venv / "bin" / "pip"
                    python_exe = python_venv / "bin" / "python"
                
                # Install Python package
                wheels = list(self.dist_dir.glob("*.whl"))
                self.run_command([str(python_pip), "install", str(wheels[0])])
                
                # Set up JavaScript environment
                js_project = temp_path / "js_env"
                js_project.mkdir()
                
                package_json = js_project / "package.json"
                package_json.write_text(json.dumps({
                    "name": "compatibility-test",
                    "version": "1.0.0",
                    "type": "module"
                }, indent=2))
                
                # Install JavaScript package
                tarballs = list(self.dist_dir.glob("*.tgz"))
                self.run_command(["npm", "install", str(tarballs[0])], cwd=js_project)
                
                # Create Python script to generate signature
                python_script = temp_path / "python_signer.py"
                python_script.write_text("""
import json
from schemapin.crypto import KeyManager
from schemapin.utils import SchemaSigningWorkflow

# Generate key pair
private_key, public_key = KeyManager.generate_keypair()
private_key_pem = KeyManager.export_private_key_pem(private_key)
public_key_pem = KeyManager.export_public_key_pem(public_key)

# Sign schema
schema = {
    "name": "test_tool",
    "description": "A test tool for compatibility",
    "parameters": {
        "type": "object",
        "properties": {
            "input": {"type": "string"}
        }
    }
}

workflow = SchemaSigningWorkflow(private_key_pem)
signature = workflow.sign_schema(schema)

# Save results
result = {
    "schema": schema,
    "signature": signature,
    "public_key": public_key_pem
}

with open("compatibility_test.json", "w") as f:
    json.dump(result, f, indent=2)

print("Python signature generated")
""")
                
                # Create JavaScript script to verify signature
                js_script = js_project / "verify.js"
                js_script.write_text("""
import fs from 'fs';
import { KeyManager, SchemaVerificationWorkflow } from 'schemapin';

// Read data generated by Python
const data = JSON.parse(fs.readFileSync('../compatibility_test.json', 'utf8'));

// Verify signature using JavaScript
const workflow = new SchemaVerificationWorkflow();
const publicKey = KeyManager.loadPublicKeyPem(data.public_key);

try {
    const isValid = workflow.verifySchemaSignature(
        data.schema,
        data.signature,
        publicKey
    );
    
    if (isValid) {
        console.log("✅ Cross-language compatibility test passed");
        process.exit(0);
    } else {
        console.log("❌ Signature verification failed");
        process.exit(1);
    }
} catch (error) {
    console.log("❌ Verification error:", error.message);
    process.exit(1);
}
""")
                
                # Run Python script
                self.run_command([str(python_exe), "python_signer.py"], cwd=temp_path)
                
                # Run JavaScript verification
                self.run_command(["node", "verify.js"], cwd=js_project)
                
                print("✅ Cross-language compatibility test passed")
                return True
                
            except subprocess.CalledProcessError as e:
                print(f"❌ Cross-language compatibility test failed: {e}")
                print(f"stdout: {e.stdout}")
                print(f"stderr: {e.stderr}")
                return False
    
    def test_go_cross_compatibility(self) -> bool:
        """Test Go cross-language compatibility with Python and JavaScript."""
        print("🔄 Testing Go cross-language compatibility...")
        
        # Check if Go binaries exist
        go_dist_dir = self.dist_dir / "go"
        if not go_dist_dir.exists():
            print("⚠️  Go binaries not found, skipping Go cross-compatibility test")
            return True
        
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            
            try:
                # Copy Go binaries
                for binary in go_dist_dir.glob("*"):
                    temp_binary = temp_path / binary.name
                    shutil.copy2(binary, temp_binary)
                    temp_binary.chmod(0o755)
                
                # Set up Python environment
                python_venv = temp_path / "python_env"
                self.run_command(["python", "-m", "venv", str(python_venv)])
                
                if os.name == 'nt':
                    python_pip = python_venv / "Scripts" / "pip"
                    python_exe = python_venv / "Scripts" / "python"
                else:
                    python_pip = python_venv / "bin" / "pip"
                    python_exe = python_venv / "bin" / "python"
                
                # Install Python package
                wheels = list(self.dist_dir.glob("*.whl"))
                if wheels:
                    self.run_command([str(python_pip), "install", str(wheels[0])])
                
                # Generate signature with Python
                python_script = temp_path / "python_signer.py"
                python_script.write_text("""
import json
from schemapin.crypto import KeyManager
from schemapin.utils import SchemaSigningWorkflow

# Generate key pair
private_key, public_key = KeyManager.generate_keypair()
private_key_pem = KeyManager.export_private_key_pem(private_key)
public_key_pem = KeyManager.export_public_key_pem(public_key)

# Save keys
with open("python_private.pem", "w") as f:
    f.write(private_key_pem)
with open("python_public.pem", "w") as f:
    f.write(public_key_pem)

# Sign schema
schema = {"name": "cross_test", "type": "object", "properties": {"test": {"type": "string"}}}
workflow = SchemaSigningWorkflow(private_key_pem)
signature = workflow.sign_schema(schema)

# Save signed schema
signed_schema = {"schema": schema, "signature": signature}
with open("python_signed.json", "w") as f:
    json.dump(signed_schema, f, indent=2)

print("Python signature generated")
""")
                
                # Run Python script
                self.run_command([str(python_exe), "python_signer.py"], cwd=temp_path)
                
                # Verify with Go
                verify_binary = temp_path / "schemapin-verify"
                if verify_binary.exists():
                    self.run_command([str(verify_binary), "--schema", "python_signed.json",
                                    "--public-key", "python_public.pem"], cwd=temp_path)
                    print("✅ Go verified Python signature")
                
                # Generate signature with Go
                keygen_binary = temp_path / "schemapin-keygen"
                sign_binary = temp_path / "schemapin-sign"
                
                if keygen_binary.exists() and sign_binary.exists():
                    # Generate Go keys
                    self.run_command([str(keygen_binary), "--developer", "Go Test",
                                    "--contact", "go@test.com", "--private-key", "go_private.pem",
                                    "--public-key", "go_public.pem"], cwd=temp_path)
                    
                    # Create and sign schema with Go
                    go_schema = temp_path / "go_schema.json"
                    go_schema.write_text('{"name": "go_test", "type": "object"}')
                    
                    self.run_command([str(sign_binary), "--key", "go_private.pem",
                                    "--schema", "go_schema.json", "--output", "go_signed.json"],
                                   cwd=temp_path)
                    
                    # Verify Go signature with Python
                    python_verify_script = temp_path / "python_verifier.py"
                    python_verify_script.write_text("""
import json
from schemapin.crypto import KeyManager
from schemapin.utils import SchemaVerificationWorkflow

# Load Go public key
with open("go_public.pem", "r") as f:
    public_key_pem = f.read()

# Load Go signed schema
with open("go_signed.json", "r") as f:
    signed_data = json.load(f)

# Verify with Python
workflow = SchemaVerificationWorkflow()
public_key = KeyManager.load_public_key_pem(public_key_pem)
is_valid = workflow.verify_schema_signature(
    signed_data["schema"],
    signed_data["signature"],
    public_key
)

if is_valid:
    print("✅ Python verified Go signature")
else:
    print("❌ Python failed to verify Go signature")
    exit(1)
""")
                    
                    self.run_command([str(python_exe), "python_verifier.py"], cwd=temp_path)
                
                print("✅ Go cross-language compatibility test passed")
                return True
                
            except subprocess.CalledProcessError as e:
                print(f"❌ Go cross-language compatibility test failed: {e}")
                print(f"stdout: {e.stdout}")
                print(f"stderr: {e.stderr}")
                return False
    
    def validate_package_metadata(self) -> bool:
        """Validate package metadata and structure."""
        print("📋 Validating package metadata...")
        
        # Check Python package metadata
        wheels = list(self.dist_dir.glob("*.whl"))
        sdists = list(self.dist_dir.glob("*.tar.gz"))
        tarballs = list(self.dist_dir.glob("*.tgz"))
        go_binaries = list((self.dist_dir / "go").glob("*")) if (self.dist_dir / "go").exists() else []
        
        if not wheels or not sdists or not tarballs:
            print("❌ Missing package files")
            return False
        
        print(f"✅ Found Python wheel: {wheels[0].name}")
        print(f"✅ Found Python sdist: {sdists[0].name}")
        print(f"✅ Found JavaScript package: {tarballs[0].name}")
        
        if go_binaries:
            print(f"✅ Found Go binaries: {[b.name for b in go_binaries]}")
        else:
            print("⚠️  No Go binaries found")
        
        # Validate package sizes (basic sanity check)
        all_packages = [wheels[0], sdists[0], tarballs[0]]
        if go_binaries:
            all_packages.extend(go_binaries)
        
        for package in all_packages:
            size_kb = package.stat().st_size / 1024
            if size_kb < 10:  # Packages should be at least 10KB
                print(f"⚠️  Package {package.name} seems too small ({size_kb:.1f} KB)")
            elif size_kb > 10000:  # Packages shouldn't be huge
                print(f"⚠️  Package {package.name} seems too large ({size_kb:.1f} KB)")
            else:
                print(f"✅ Package {package.name} size OK ({size_kb:.1f} KB)")
        
        return True
    
    def test_all(self) -> bool:
        """Run all package tests."""
        print("🧪 Starting comprehensive package testing...")
        
        if not self.dist_dir.exists():
            print("❌ No dist directory found. Run build_packages.py first.")
            return False
        
        tests = [
            ("Package metadata validation", self.validate_package_metadata),
            ("Python package installation", self.test_python_package_installation),
            ("JavaScript package installation", self.test_javascript_package_installation),
            ("Go package installation", self.test_go_package_installation),
            ("Cross-language compatibility", self.test_cross_language_compatibility),
            ("Go cross-language compatibility", self.test_go_cross_compatibility),
        ]
        
        results = []
        for test_name, test_func in tests:
            print(f"\n--- {test_name} ---")
            try:
                result = test_func()
                results.append((test_name, result))
                if result:
                    print(f"✅ {test_name} passed")
                else:
                    print(f"❌ {test_name} failed")
            except Exception as e:
                print(f"❌ {test_name} failed with exception: {e}")
                results.append((test_name, False))
        
        # Summary
        print("\n" + "="*50)
        print("📊 Test Results Summary:")
        passed = sum(1 for _, result in results if result)
        total = len(results)
        
        for test_name, result in results:
            status = "✅ PASS" if result else "❌ FAIL"
            print(f"  {status} {test_name}")
        
        print(f"\nOverall: {passed}/{total} tests passed")
        
        if passed == total:
            print("🎉 All package tests passed!")
            return True
        else:
            print("❌ Some package tests failed")
            return False


def main():
    """Main entry point."""
    tester = PackageTester()
    
    if len(sys.argv) > 1:
        command = sys.argv[1]
        if command == "python":
            success = tester.test_python_package_installation()
        elif command == "javascript":
            success = tester.test_javascript_package_installation()
        elif command == "go":
            success = tester.test_go_package_installation()
        elif command == "compatibility":
            success = tester.test_cross_language_compatibility()
        elif command == "go-compatibility":
            success = tester.test_go_cross_compatibility()
        elif command == "metadata":
            success = tester.validate_package_metadata()
        else:
            print(f"Unknown command: {command}")
            print("Available commands: python, javascript, go, compatibility, go-compatibility, metadata")
            sys.exit(1)
    else:
        success = tester.test_all()
    
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()