"""Setup script for SchemaPin Python implementation."""

from setuptools import find_packages, setup

try:
    with open("../README.md", encoding="utf-8") as fh:
        long_description = fh.read()
except FileNotFoundError:
    # Fallback for build environments where README.md might not be available
    long_description = "Cryptographic schema integrity verification for AI tools"

setup(
    name="schemapin",
    version="1.1.0",
    author="ThirdKey",
    author_email="contact@thirdkey.ai",
    description="Cryptographic schema integrity verification for AI tools",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/thirdkey/schemapin",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security :: Cryptography",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    python_requires=">=3.8",
    install_requires=[
        "cryptography>=41.0.0",
        "requests>=2.31.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.4.0",
            "ruff>=0.1.0",
            "bandit>=1.7.5",
        ],
    },
    entry_points={
        "console_scripts": [
            "schemapin-keygen=tools.keygen:main",
            "schemapin-sign=tools.schema_signer:main",
            "schemapin-verify=tools.verify_schema:main",
        ],
    },
)
