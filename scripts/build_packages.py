#!/usr/bin/env python3
"""
Automated package building script for SchemaPin.

This script builds both Python and JavaScript packages with proper validation
and integrity checks.
"""

import os
import sys
import subprocess
import shutil
import json
from pathlib import Path
from typing import Dict, List, Optional


class PackageBuilder:
    """Handles building and validation of SchemaPin packages."""
    
    def __init__(self, root_dir: Optional[Path] = None):
        """Initialize the package builder."""
        self.root_dir = root_dir or Path(__file__).parent.parent
        self.python_dir = self.root_dir / "python"
        self.javascript_dir = self.root_dir / "javascript"
        self.dist_dir = self.root_dir / "dist"
        
    def run_command(self, cmd: List[str], cwd: Optional[Path] = None, 
                   check: bool = True) -> subprocess.CompletedProcess:
        """Run a command and return the result."""
        cwd = cwd or self.root_dir
        print(f"Running: {' '.join(cmd)} (in {cwd})")
        return subprocess.run(cmd, cwd=cwd, check=check, capture_output=True, text=True)
    
    def validate_version_consistency(self) -> bool:
        """Validate that versions are consistent across all package files."""
        print("🔍 Validating version consistency...")
        
        # Read Python version from pyproject.toml
        python_pyproject = self.python_dir / "pyproject.toml"
        with open(python_pyproject) as f:
            content = f.read()
            for line in content.split('\n'):
                if line.strip().startswith('version = '):
                    python_version = line.split('"')[1]
                    break
        
        # Read JavaScript version from package.json
        js_package = self.javascript_dir / "package.json"
        with open(js_package) as f:
            js_data = json.load(f)
            js_version = js_data["version"]
        
        # Read Python setup.py version
        python_setup = self.python_dir / "setup.py"
        with open(python_setup) as f:
            content = f.read()
            for line in content.split('\n'):
                if 'version=' in line and '"' in line:
                    setup_version = line.split('"')[1]
                    break
        
        versions = {
            "pyproject.toml": python_version,
            "package.json": js_version,
            "setup.py": setup_version
        }
        
        print(f"Versions found: {versions}")
        
        if len(set(versions.values())) != 1:
            print("❌ Version mismatch detected!")
            return False
        
        print(f"✅ All versions consistent: {python_version}")
        return True
    
    def clean_build_artifacts(self):
        """Clean existing build artifacts."""
        print("🧹 Cleaning build artifacts...")
        
        # Clean Python artifacts
        python_artifacts = [
            self.python_dir / "build",
            self.python_dir / "dist",
            self.python_dir / "schemapin.egg-info"
        ]
        
        for artifact in python_artifacts:
            if artifact.exists():
                shutil.rmtree(artifact)
                print(f"Removed {artifact}")
        
        # Clean JavaScript artifacts
        js_artifacts = [
            self.javascript_dir / "node_modules" / ".cache",
            self.javascript_dir / "coverage"
        ]
        
        for artifact in js_artifacts:
            if artifact.exists():
                shutil.rmtree(artifact)
                print(f"Removed {artifact}")
        
        # Clean global dist directory
        if self.dist_dir.exists():
            shutil.rmtree(self.dist_dir)
        self.dist_dir.mkdir(exist_ok=True)
        
        print("✅ Build artifacts cleaned")
    
    def run_python_tests(self) -> bool:
        """Run Python tests and quality checks."""
        print("🐍 Running Python tests and quality checks...")
        
        try:
            # Install test dependencies first
            print("📦 Installing test dependencies...")
            result = self.run_command(["python", "-m", "pip", "install", "-e", ".[dev]"],
                                    cwd=self.python_dir)
            print("✅ Test dependencies installed")
            
            # Run tests
            result = self.run_command(["python", "-m", "pytest", "tests/", "-v"],
                                    cwd=self.python_dir)
            print("✅ Python tests passed")
            
            # Run ruff
            result = self.run_command(["ruff", "check", "."], cwd=self.python_dir)
            print("✅ Ruff checks passed")
            
            # Run bandit
            result = self.run_command(["bandit", "-r", ".", "--exclude", "tests/"],
                                    cwd=self.python_dir)
            print("✅ Bandit security checks passed")
            
            return True
        except subprocess.CalledProcessError as e:
            print(f"❌ Python quality checks failed: {e}")
            print(f"stdout: {e.stdout}")
            print(f"stderr: {e.stderr}")
            return False
    
    def run_javascript_tests(self) -> bool:
        """Run JavaScript tests."""
        print("📦 Running JavaScript tests...")
        
        try:
            result = self.run_command(["npm", "test"], cwd=self.javascript_dir)
            print("✅ JavaScript tests passed")
            return True
        except subprocess.CalledProcessError as e:
            print(f"❌ JavaScript tests failed: {e}")
            print(f"stdout: {e.stdout}")
            print(f"stderr: {e.stderr}")
            return False
    
    def build_python_package(self) -> bool:
        """Build Python package."""
        print("🐍 Building Python package...")
        
        try:
            # Install build dependencies
            print("📦 Installing build dependencies...")
            result = self.run_command(["python", "-m", "pip", "install", "build", "wheel"],
                                    cwd=self.python_dir)
            print("✅ Build dependencies installed")
            
            # Build using build module
            result = self.run_command(["python", "-m", "build"], cwd=self.python_dir)
            print("✅ Python package built successfully")
            
            # Copy to dist directory
            python_dist = self.python_dir / "dist"
            for file in python_dist.glob("*"):
                shutil.copy2(file, self.dist_dir)
                print(f"Copied {file.name} to dist/")
            
            return True
        except subprocess.CalledProcessError as e:
            print(f"❌ Python package build failed: {e}")
            print(f"stdout: {e.stdout}")
            print(f"stderr: {e.stderr}")
            return False
    
    def build_javascript_package(self) -> bool:
        """Build JavaScript package."""
        print("📦 Building JavaScript package...")
        
        try:
            # Create npm package
            result = self.run_command(["npm", "pack"], cwd=self.javascript_dir)
            
            # Move tarball to dist directory
            for tarball in self.javascript_dir.glob("*.tgz"):
                shutil.move(str(tarball), self.dist_dir)
                print(f"Moved {tarball.name} to dist/")
            
            print("✅ JavaScript package built successfully")
            return True
        except subprocess.CalledProcessError as e:
            print(f"❌ JavaScript package build failed: {e}")
            print(f"stdout: {e.stdout}")
            print(f"stderr: {e.stderr}")
            return False
    
    def validate_packages(self) -> bool:
        """Validate built packages."""
        print("🔍 Validating built packages...")
        
        # Check Python packages exist
        python_wheel = list(self.dist_dir.glob("*.whl"))
        python_sdist = list(self.dist_dir.glob("*.tar.gz"))
        js_package = list(self.dist_dir.glob("*.tgz"))
        
        if not python_wheel:
            print("❌ Python wheel not found")
            return False
        
        if not python_sdist:
            print("❌ Python source distribution not found")
            return False
        
        if not js_package:
            print("❌ JavaScript package not found")
            return False
        
        print(f"✅ Found Python wheel: {python_wheel[0].name}")
        print(f"✅ Found Python sdist: {python_sdist[0].name}")
        print(f"✅ Found JavaScript package: {js_package[0].name}")
        
        return True
    
    def build_all(self) -> bool:
        """Build all packages with full validation."""
        print("🚀 Starting SchemaPin package build process...")
        
        # Validate version consistency
        if not self.validate_version_consistency():
            return False
        
        # Clean artifacts
        self.clean_build_artifacts()
        
        # Run tests
        if not self.run_python_tests():
            return False
        
        if not self.run_javascript_tests():
            return False
        
        # Build packages
        if not self.build_python_package():
            return False
        
        if not self.build_javascript_package():
            return False
        
        # Validate results
        if not self.validate_packages():
            return False
        
        print("🎉 All packages built successfully!")
        print(f"📦 Packages available in: {self.dist_dir}")
        
        # List built packages
        for package in self.dist_dir.iterdir():
            if package.is_file():
                size = package.stat().st_size / 1024  # KB
                print(f"  - {package.name} ({size:.1f} KB)")
        
        return True


def main():
    """Main entry point."""
    builder = PackageBuilder()
    
    if len(sys.argv) > 1:
        command = sys.argv[1]
        if command == "clean":
            builder.clean_build_artifacts()
        elif command == "test":
            success = builder.run_python_tests() and builder.run_javascript_tests()
            sys.exit(0 if success else 1)
        elif command == "python":
            success = builder.build_python_package()
            sys.exit(0 if success else 1)
        elif command == "javascript":
            success = builder.build_javascript_package()
            sys.exit(0 if success else 1)
        else:
            print(f"Unknown command: {command}")
            sys.exit(1)
    else:
        success = builder.build_all()
        sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()