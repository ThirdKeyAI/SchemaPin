#!/usr/bin/env python3
"""
Python package publishing script for SchemaPin.

This script handles publishing to PyPI with proper validation and safety checks.
"""

import os
import sys
import subprocess
import getpass
from pathlib import Path
from typing import Optional, List


class PythonPublisher:
    """Handles publishing Python packages to PyPI."""
    
    def __init__(self, root_dir: Optional[Path] = None):
        """Initialize the publisher."""
        self.root_dir = root_dir or Path(__file__).parent.parent
        self.python_dir = self.root_dir / "python"
        self.dist_dir = self.root_dir / "dist"
        
    def run_command(self, cmd: List[str], cwd: Optional[Path] = None, 
                   check: bool = True) -> subprocess.CompletedProcess:
        """Run a command and return the result."""
        cwd = cwd or self.root_dir
        print(f"Running: {' '.join(cmd)} (in {cwd})")
        return subprocess.run(cmd, cwd=cwd, check=check, capture_output=True, text=True)
    
    def check_prerequisites(self) -> bool:
        """Check that all prerequisites are met for publishing."""
        print("🔍 Checking publishing prerequisites...")
        
        # Check if twine is installed
        try:
            self.run_command(["twine", "--version"])
            print("✅ Twine is installed")
        except (subprocess.CalledProcessError, FileNotFoundError):
            print("❌ Twine is not installed. Install with: pip install twine")
            return False
        
        # Check if packages exist
        wheels = list(self.dist_dir.glob("*.whl"))
        sdists = list(self.dist_dir.glob("*.tar.gz"))
        
        if not wheels:
            print("❌ No wheel files found in dist/")
            return False
        
        if not sdists:
            print("❌ No source distribution found in dist/")
            return False
        
        print(f"✅ Found wheel: {wheels[0].name}")
        print(f"✅ Found sdist: {sdists[0].name}")
        
        # Check if git repo is clean
        try:
            result = self.run_command(["git", "status", "--porcelain"])
            if result.stdout.strip():
                print("⚠️  Git repository has uncommitted changes")
                print("Consider committing changes before publishing")
            else:
                print("✅ Git repository is clean")
        except subprocess.CalledProcessError:
            print("⚠️  Not in a git repository or git not available")
        
        return True
    
    def validate_packages(self) -> bool:
        """Validate packages before publishing."""
        print("🔍 Validating packages...")
        
        # Find Python packages
        python_packages = []
        python_packages.extend(self.dist_dir.glob("*.whl"))
        python_packages.extend(self.dist_dir.glob("*.tar.gz"))
        
        if not python_packages:
            print("❌ No Python packages found")
            return False
        
        try:
            # Use twine check to validate packages
            package_paths = [str(p) for p in python_packages]
            result = self.run_command(["twine", "check"] + package_paths)
            print("✅ Package validation passed")
            return True
        except subprocess.CalledProcessError as e:
            print(f"❌ Package validation failed: {e}")
            print(f"stdout: {e.stdout}")
            print(f"stderr: {e.stderr}")
            return False
    
    def get_pypi_credentials(self, test_pypi: bool = False) -> tuple:
        """Get PyPI credentials from user."""
        repository = "TestPyPI" if test_pypi else "PyPI"
        print(f"\n🔐 Enter {repository} credentials:")
        
        username = input(f"{repository} username: ").strip()
        if not username:
            print("❌ Username cannot be empty")
            return None, None
        
        password = getpass.getpass(f"{repository} password/token: ")
        if not password:
            print("❌ Password cannot be empty")
            return None, None
        
        return username, password
    
    def publish_to_test_pypi(self) -> bool:
        """Publish packages to Test PyPI."""
        print("🧪 Publishing to Test PyPI...")
        
        username, password = self.get_pypi_credentials(test_pypi=True)
        if not username or not password:
            return False
        
        # Find packages to upload
        packages = []
        packages.extend(self.dist_dir.glob("*.whl"))
        packages.extend(self.dist_dir.glob("*.tar.gz"))
        
        try:
            cmd = [
                "twine", "upload",
                "--repository", "testpypi",
                "--username", username,
                "--password", password,
            ] + [str(p) for p in packages]
            
            result = self.run_command(cmd)
            print("✅ Successfully published to Test PyPI")
            print("🔗 Check your package at: https://test.pypi.org/project/schemapin/")
            return True
            
        except subprocess.CalledProcessError as e:
            print(f"❌ Test PyPI upload failed: {e}")
            print(f"stdout: {e.stdout}")
            print(f"stderr: {e.stderr}")
            return False
    
    def publish_to_pypi(self) -> bool:
        """Publish packages to PyPI."""
        print("🚀 Publishing to PyPI...")
        
        # Final confirmation
        print("\n⚠️  WARNING: You are about to publish to the LIVE PyPI repository!")
        print("This action cannot be undone. Make sure you have:")
        print("  - Tested the package thoroughly")
        print("  - Updated the version number")
        print("  - Updated the changelog")
        print("  - Committed all changes to git")
        
        confirm = input("\nType 'yes' to continue with PyPI upload: ").strip().lower()
        if confirm != 'yes':
            print("❌ PyPI upload cancelled")
            return False
        
        username, password = self.get_pypi_credentials(test_pypi=False)
        if not username or not password:
            return False
        
        # Find packages to upload
        packages = []
        packages.extend(self.dist_dir.glob("*.whl"))
        packages.extend(self.dist_dir.glob("*.tar.gz"))
        
        try:
            cmd = [
                "twine", "upload",
                "--username", username,
                "--password", password,
            ] + [str(p) for p in packages]
            
            result = self.run_command(cmd)
            print("✅ Successfully published to PyPI!")
            print("🔗 Check your package at: https://pypi.org/project/schemapin/")
            return True
            
        except subprocess.CalledProcessError as e:
            print(f"❌ PyPI upload failed: {e}")
            print(f"stdout: {e.stdout}")
            print(f"stderr: {e.stderr}")
            return False
    
    def test_installation_from_pypi(self, test_pypi: bool = False) -> bool:
        """Test installation from PyPI."""
        repository = "Test PyPI" if test_pypi else "PyPI"
        print(f"🧪 Testing installation from {repository}...")
        
        import tempfile
        
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
                
                # Install from PyPI
                if test_pypi:
                    cmd = [
                        str(pip_path), "install",
                        "--index-url", "https://test.pypi.org/simple/",
                        "--extra-index-url", "https://pypi.org/simple/",
                        "schemapin"
                    ]
                else:
                    cmd = [str(pip_path), "install", "schemapin"]
                
                self.run_command(cmd)
                
                # Test basic functionality
                test_script = temp_path / "test.py"
                test_script.write_text("""
import schemapin
from schemapin.crypto import KeyManager
print("✅ Package installed and imports work")
""")
                
                self.run_command([str(python_path), str(test_script)])
                print(f"✅ Installation from {repository} successful")
                return True
                
            except subprocess.CalledProcessError as e:
                print(f"❌ Installation test failed: {e}")
                return False
    
    def publish_workflow(self, test_first: bool = True) -> bool:
        """Complete publishing workflow."""
        print("🚀 Starting Python package publishing workflow...")
        
        # Check prerequisites
        if not self.check_prerequisites():
            return False
        
        # Validate packages
        if not self.validate_packages():
            return False
        
        if test_first:
            # Publish to Test PyPI first
            print("\n--- Publishing to Test PyPI ---")
            if not self.publish_to_test_pypi():
                return False
            
            # Test installation from Test PyPI
            if not self.test_installation_from_pypi(test_pypi=True):
                print("⚠️  Test PyPI installation failed, but continuing...")
            
            # Ask if user wants to continue to live PyPI
            print("\n" + "="*50)
            continue_to_pypi = input("Continue to live PyPI? (yes/no): ").strip().lower()
            if continue_to_pypi != 'yes':
                print("✅ Published to Test PyPI only")
                return True
        
        # Publish to live PyPI
        print("\n--- Publishing to Live PyPI ---")
        if not self.publish_to_pypi():
            return False
        
        # Test installation from PyPI
        print("\n--- Testing Installation ---")
        if not self.test_installation_from_pypi(test_pypi=False):
            print("⚠️  PyPI installation test failed")
            return False
        
        print("\n🎉 Python package publishing completed successfully!")
        return True


def main():
    """Main entry point."""
    publisher = PythonPublisher()
    
    if len(sys.argv) > 1:
        command = sys.argv[1]
        if command == "check":
            success = publisher.check_prerequisites() and publisher.validate_packages()
        elif command == "test-pypi":
            success = publisher.publish_to_test_pypi()
        elif command == "pypi":
            success = publisher.publish_to_pypi()
        elif command == "test-install":
            test_pypi = len(sys.argv) > 2 and sys.argv[2] == "test"
            success = publisher.test_installation_from_pypi(test_pypi)
        elif command == "workflow":
            test_first = "--skip-test" not in sys.argv
            success = publisher.publish_workflow(test_first)
        else:
            print(f"Unknown command: {command}")
            print("Available commands: check, test-pypi, pypi, test-install, workflow")
            sys.exit(1)
    else:
        success = publisher.publish_workflow()
    
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()