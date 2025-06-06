"""Tests for cryptographic operations."""

from schemapin.crypto import KeyManager, SignatureManager


class TestKeyManager:
    """Test key generation and serialization."""

    def test_generate_keypair(self):
        """Test ECDSA P-256 key pair generation."""
        private_key, public_key = KeyManager.generate_keypair()
        
        # Keys should be valid ECDSA objects
        assert hasattr(private_key, 'private_bytes')
        assert hasattr(public_key, 'public_bytes')

    def test_export_private_key_pem(self):
        """Test private key PEM export."""
        private_key, _ = KeyManager.generate_keypair()
        pem_data = KeyManager.export_private_key_pem(private_key)
        
        # Should be valid PEM format
        assert pem_data.startswith('-----BEGIN PRIVATE KEY-----')
        assert pem_data.endswith('-----END PRIVATE KEY-----\n')

    def test_export_public_key_pem(self):
        """Test public key PEM export."""
        _, public_key = KeyManager.generate_keypair()
        pem_data = KeyManager.export_public_key_pem(public_key)
        
        # Should be valid PEM format
        assert pem_data.startswith('-----BEGIN PUBLIC KEY-----')
        assert pem_data.endswith('-----END PUBLIC KEY-----\n')

    def test_load_private_key_pem(self):
        """Test private key PEM loading."""
        private_key, _ = KeyManager.generate_keypair()
        pem_data = KeyManager.export_private_key_pem(private_key)
        
        # Should be able to load the exported key
        loaded_key = KeyManager.load_private_key_pem(pem_data)
        assert hasattr(loaded_key, 'private_bytes')

    def test_load_public_key_pem(self):
        """Test public key PEM loading."""
        _, public_key = KeyManager.generate_keypair()
        pem_data = KeyManager.export_public_key_pem(public_key)
        
        # Should be able to load the exported key
        loaded_key = KeyManager.load_public_key_pem(pem_data)
        assert hasattr(loaded_key, 'public_bytes')

    def test_key_roundtrip(self):
        """Test key export/import roundtrip."""
        private_key, public_key = KeyManager.generate_keypair()
        
        # Export and reload private key
        private_pem = KeyManager.export_private_key_pem(private_key)
        loaded_private = KeyManager.load_private_key_pem(private_pem)
        
        # Export and reload public key
        public_pem = KeyManager.export_public_key_pem(public_key)
        loaded_public = KeyManager.load_public_key_pem(public_pem)
        
        # Keys should be functionally equivalent
        assert KeyManager.export_private_key_pem(loaded_private) == private_pem
        assert KeyManager.export_public_key_pem(loaded_public) == public_pem


class TestSignatureManager:
    """Test signature creation and verification."""

    def test_sign_and_verify_hash(self):
        """Test basic signature creation and verification."""
        private_key, public_key = KeyManager.generate_keypair()
        test_hash = b'test_hash_32_bytes_exactly_here!'
        
        # Sign the hash
        signature_b64 = SignatureManager.sign_hash(test_hash, private_key)
        
        # Signature should be Base64 encoded
        assert isinstance(signature_b64, str)
        
        # Verify the signature
        is_valid = SignatureManager.verify_signature(test_hash, signature_b64, public_key)
        assert is_valid

    def test_verify_invalid_signature(self):
        """Test verification of invalid signature."""
        private_key, public_key = KeyManager.generate_keypair()
        test_hash = b'test_hash_32_bytes_exactly_here!'
        
        # Create valid signature
        signature_b64 = SignatureManager.sign_hash(test_hash, private_key)
        
        # Modify signature to make it invalid
        invalid_signature = signature_b64[:-4] + 'XXXX'
        
        # Should fail verification
        is_valid = SignatureManager.verify_signature(test_hash, invalid_signature, public_key)
        assert not is_valid

    def test_verify_wrong_hash(self):
        """Test verification with wrong hash."""
        private_key, public_key = KeyManager.generate_keypair()
        original_hash = b'original_hash_32_bytes_exactly!'
        different_hash = b'different_hash_32_bytes_exactly'
        
        # Sign original hash
        signature_b64 = SignatureManager.sign_hash(original_hash, private_key)
        
        # Try to verify with different hash
        is_valid = SignatureManager.verify_signature(different_hash, signature_b64, public_key)
        assert not is_valid

    def test_verify_wrong_key(self):
        """Test verification with wrong public key."""
        private_key1, _ = KeyManager.generate_keypair()
        _, public_key2 = KeyManager.generate_keypair()
        test_hash = b'test_hash_32_bytes_exactly_here!'
        
        # Sign with first key
        signature_b64 = SignatureManager.sign_hash(test_hash, private_key1)
        
        # Try to verify with second key
        is_valid = SignatureManager.verify_signature(test_hash, signature_b64, public_key2)
        assert not is_valid

    def test_schema_signature_methods(self):
        """Test schema-specific signature methods."""
        private_key, public_key = KeyManager.generate_keypair()
        schema_hash = b'schema_hash_32_bytes_exactly_!!'
        
        # Sign schema hash
        signature_b64 = SignatureManager.sign_schema_hash(schema_hash, private_key)
        
        # Verify schema signature
        is_valid = SignatureManager.verify_schema_signature(schema_hash, signature_b64, public_key)
        assert is_valid

    def test_signature_deterministic(self):
        """Test that signatures are deterministic for same input."""
        private_key, _ = KeyManager.generate_keypair()
        test_hash = b'test_hash_32_bytes_exactly_here!'
        
        # Note: ECDSA signatures are NOT deterministic by design (they use random nonce)
        # This test verifies that different signatures for same data still verify correctly
        signature1 = SignatureManager.sign_hash(test_hash, private_key)
        signature2 = SignatureManager.sign_hash(test_hash, private_key)
        
        # Signatures should be different (due to random nonce)
        assert signature1 != signature2
        
        # But both should verify correctly
        public_key = private_key.public_key()
        assert SignatureManager.verify_signature(test_hash, signature1, public_key)
        assert SignatureManager.verify_signature(test_hash, signature2, public_key)