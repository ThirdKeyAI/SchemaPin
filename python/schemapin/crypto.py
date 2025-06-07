"""Cryptographic operations for SchemaPin using ECDSA P-256."""

import base64
import hashlib
from typing import Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
)


class KeyManager:
    """Manages ECDSA P-256 key generation and serialization."""

    @staticmethod
    def generate_keypair() -> Tuple[EllipticCurvePrivateKey, EllipticCurvePublicKey]:
        """
        Generate new ECDSA P-256 key pair.

        Returns:
            Tuple of (private_key, public_key)
        """
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_key = private_key.public_key()
        return private_key, public_key

    @staticmethod
    def export_private_key_pem(private_key: EllipticCurvePrivateKey) -> str:
        """
        Export private key to PEM format.

        Args:
            private_key: ECDSA private key

        Returns:
            PEM-encoded private key string
        """
        pem_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        return pem_bytes.decode('utf-8')

    @staticmethod
    def export_public_key_pem(public_key: EllipticCurvePublicKey) -> str:
        """
        Export public key to PEM format.

        Args:
            public_key: ECDSA public key

        Returns:
            PEM-encoded public key string
        """
        pem_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return pem_bytes.decode('utf-8')

    @staticmethod
    def load_private_key_pem(pem_data: str) -> EllipticCurvePrivateKey:
        """
        Load private key from PEM format.

        Args:
            pem_data: PEM-encoded private key string

        Returns:
            ECDSA private key
        """
        return serialization.load_pem_private_key(
            pem_data.encode('utf-8'),
            password=None
        )

    @staticmethod
    def load_public_key_pem(pem_data: str) -> EllipticCurvePublicKey:
        """
        Load public key from PEM format.

        Args:
            pem_data: PEM-encoded public key string

        Returns:
            ECDSA public key
        """
        return serialization.load_pem_public_key(pem_data.encode('utf-8'))

    @staticmethod
    def calculate_key_fingerprint(public_key: EllipticCurvePublicKey) -> str:
        """
        Calculate SHA-256 fingerprint of public key.

        Args:
            public_key: ECDSA public key

        Returns:
            SHA-256 fingerprint in format 'sha256:hexstring'
        """
        der_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        fingerprint = hashlib.sha256(der_bytes).hexdigest()
        return f"sha256:{fingerprint}"

    @staticmethod
    def calculate_key_fingerprint_from_pem(public_key_pem: str) -> str:
        """
        Calculate SHA-256 fingerprint from PEM-encoded public key.

        Args:
            public_key_pem: PEM-encoded public key string

        Returns:
            SHA-256 fingerprint in format 'sha256:hexstring'
        """
        public_key = KeyManager.load_public_key_pem(public_key_pem)
        return KeyManager.calculate_key_fingerprint(public_key)


class SignatureManager:
    """Manages ECDSA signature creation and verification."""

    @staticmethod
    def sign_hash(hash_bytes: bytes, private_key: EllipticCurvePrivateKey) -> str:
        """
        Sign hash using ECDSA P-256 and return Base64-encoded signature.

        Args:
            hash_bytes: SHA-256 hash to sign
            private_key: ECDSA private key

        Returns:
            Base64-encoded signature
        """
        signature = private_key.sign(hash_bytes, ec.ECDSA(hashes.SHA256()))
        return base64.b64encode(signature).decode('ascii')

    @staticmethod
    def verify_signature(hash_bytes: bytes, signature_b64: str, public_key: EllipticCurvePublicKey) -> bool:
        """
        Verify ECDSA signature against hash.

        Args:
            hash_bytes: Original SHA-256 hash
            signature_b64: Base64-encoded signature
            public_key: ECDSA public key

        Returns:
            True if signature is valid, False otherwise
        """
        try:
            signature = base64.b64decode(signature_b64)
            public_key.verify(signature, hash_bytes, ec.ECDSA(hashes.SHA256()))
            return True
        except Exception:
            return False

    @classmethod
    def sign_schema_hash(cls, schema_hash: bytes, private_key: EllipticCurvePrivateKey) -> str:
        """
        Sign schema hash and return Base64 signature.

        Args:
            schema_hash: SHA-256 hash of canonical schema
            private_key: ECDSA private key

        Returns:
            Base64-encoded signature
        """
        return cls.sign_hash(schema_hash, private_key)

    @classmethod
    def verify_schema_signature(
        cls,
        schema_hash: bytes,
        signature_b64: str,
        public_key: EllipticCurvePublicKey
    ) -> bool:
        """
        Verify schema signature against hash.

        Args:
            schema_hash: SHA-256 hash of canonical schema
            signature_b64: Base64-encoded signature
            public_key: ECDSA public key

        Returns:
            True if signature is valid, False otherwise
        """
        return cls.verify_signature(schema_hash, signature_b64, public_key)
