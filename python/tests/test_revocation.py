"""Tests for key revocation functionality."""

from schemapin.crypto import KeyManager
from schemapin.discovery import PublicKeyDiscovery
from schemapin.utils import create_well_known_response


class TestKeyRevocation:
    """Test key revocation functionality."""

    def test_calculate_key_fingerprint(self):
        """Test key fingerprint calculation."""
        # Generate a test key pair
        private_key, public_key = KeyManager.generate_keypair()

        # Calculate fingerprint
        fingerprint = KeyManager.calculate_key_fingerprint(public_key)

        # Verify format
        assert fingerprint.startswith('sha256:')
        assert len(fingerprint) == 71  # 'sha256:' + 64 hex chars

        # Verify consistency
        fingerprint2 = KeyManager.calculate_key_fingerprint(public_key)
        assert fingerprint == fingerprint2

    def test_calculate_key_fingerprint_from_pem(self):
        """Test key fingerprint calculation from PEM."""
        # Generate a test key pair
        private_key, public_key = KeyManager.generate_keypair()
        public_key_pem = KeyManager.export_public_key_pem(public_key)

        # Calculate fingerprint from object and PEM
        fingerprint1 = KeyManager.calculate_key_fingerprint(public_key)
        fingerprint2 = KeyManager.calculate_key_fingerprint_from_pem(public_key_pem)

        # Should be identical
        assert fingerprint1 == fingerprint2

    def test_check_key_revocation_empty_list(self):
        """Test revocation check with empty revocation list."""
        # Generate a test key
        _, public_key = KeyManager.generate_keypair()
        public_key_pem = KeyManager.export_public_key_pem(public_key)

        # Empty revocation list should return False
        assert not PublicKeyDiscovery.check_key_revocation(public_key_pem, [])

    def test_check_key_revocation_not_in_list(self):
        """Test revocation check with key not in revocation list."""
        # Generate test keys
        _, public_key1 = KeyManager.generate_keypair()
        _, public_key2 = KeyManager.generate_keypair()

        public_key1_pem = KeyManager.export_public_key_pem(public_key1)
        fingerprint2 = KeyManager.calculate_key_fingerprint(public_key2)

        # Key1 should not be revoked when only key2 is in revocation list
        revoked_keys = [fingerprint2]
        assert not PublicKeyDiscovery.check_key_revocation(public_key1_pem, revoked_keys)

    def test_check_key_revocation_in_list(self):
        """Test revocation check with key in revocation list."""
        # Generate a test key
        _, public_key = KeyManager.generate_keypair()
        public_key_pem = KeyManager.export_public_key_pem(public_key)
        fingerprint = KeyManager.calculate_key_fingerprint(public_key)

        # Key should be revoked when in revocation list
        revoked_keys = [fingerprint]
        assert PublicKeyDiscovery.check_key_revocation(public_key_pem, revoked_keys)

    def test_check_key_revocation_multiple_keys(self):
        """Test revocation check with multiple keys in revocation list."""
        # Generate test keys
        _, public_key1 = KeyManager.generate_keypair()
        _, public_key2 = KeyManager.generate_keypair()
        _, public_key3 = KeyManager.generate_keypair()

        public_key2_pem = KeyManager.export_public_key_pem(public_key2)
        fingerprint1 = KeyManager.calculate_key_fingerprint(public_key1)
        fingerprint2 = KeyManager.calculate_key_fingerprint(public_key2)
        fingerprint3 = KeyManager.calculate_key_fingerprint(public_key3)

        # Key2 should be revoked when in list with other keys
        revoked_keys = [fingerprint1, fingerprint2, fingerprint3]
        assert PublicKeyDiscovery.check_key_revocation(public_key2_pem, revoked_keys)

    def test_create_well_known_response_with_revoked_keys(self):
        """Test creating well-known response with revoked keys."""
        # Generate test data
        _, public_key = KeyManager.generate_keypair()
        public_key_pem = KeyManager.export_public_key_pem(public_key)

        revoked_keys = [
            "sha256:abc123def456",
            "sha256:789xyz012uvw"
        ]

        # Create response with revoked keys
        response = create_well_known_response(
            public_key_pem=public_key_pem,
            developer_name="Test Developer",
            contact="test@example.com",
            revoked_keys=revoked_keys,
            schema_version="1.1"
        )

        # Verify response structure
        assert response['schema_version'] == '1.1'
        assert response['developer_name'] == 'Test Developer'
        assert response['public_key_pem'] == public_key_pem
        assert response['contact'] == 'test@example.com'
        assert response['revoked_keys'] == revoked_keys

    def test_create_well_known_response_without_revoked_keys(self):
        """Test creating well-known response without revoked keys."""
        # Generate test data
        _, public_key = KeyManager.generate_keypair()
        public_key_pem = KeyManager.export_public_key_pem(public_key)

        # Create response without revoked keys
        response = create_well_known_response(
            public_key_pem=public_key_pem,
            developer_name="Test Developer"
        )

        # Verify response structure
        assert response['schema_version'] == '1.2'
        assert response['developer_name'] == 'Test Developer'
        assert response['public_key_pem'] == public_key_pem
        assert 'revoked_keys' not in response

    def test_create_well_known_response_empty_revoked_keys(self):
        """Test creating well-known response with empty revoked keys list."""
        # Generate test data
        _, public_key = KeyManager.generate_keypair()
        public_key_pem = KeyManager.export_public_key_pem(public_key)

        # Create response with empty revoked keys
        response = create_well_known_response(
            public_key_pem=public_key_pem,
            developer_name="Test Developer",
            revoked_keys=[]
        )

        # Verify response structure (empty list should not be included)
        assert response['schema_version'] == '1.2'
        assert response['developer_name'] == 'Test Developer'
        assert response['public_key_pem'] == public_key_pem
        assert 'revoked_keys' not in response

    def test_backward_compatibility_schema_version_1_0(self):
        """Test backward compatibility with schema version 1.0."""
        # Generate test data
        _, public_key = KeyManager.generate_keypair()
        public_key_pem = KeyManager.export_public_key_pem(public_key)

        # Create response with schema version 1.0
        response = create_well_known_response(
            public_key_pem=public_key_pem,
            developer_name="Test Developer",
            schema_version="1.0"
        )

        # Verify response structure
        assert response['schema_version'] == '1.0'
        assert response['developer_name'] == 'Test Developer'
        assert response['public_key_pem'] == public_key_pem
        assert 'revoked_keys' not in response
