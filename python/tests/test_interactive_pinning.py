"""Tests for interactive key pinning functionality."""

import os
import tempfile
import unittest
from unittest.mock import Mock, patch

from schemapin.crypto import KeyManager
from schemapin.interactive import (
    CallbackInteractiveHandler,
    InteractivePinningManager,
    KeyInfo,
    PromptContext,
    PromptType,
    UserDecision,
)
from schemapin.pinning import KeyPinning, PinningMode, PinningPolicy


class TestInteractivePinningManager(unittest.TestCase):
    """Test interactive pinning manager functionality."""

    def setUp(self):
        """Set up test fixtures."""
        self.mock_handler = Mock()
        self.manager = InteractivePinningManager(self.mock_handler)

        # Generate test keys
        self.private_key, self.public_key = KeyManager.generate_keypair()
        self.public_key_pem = KeyManager.export_public_key_pem(self.public_key)

        # Test data
        self.tool_id = "test-tool"
        self.domain = "example.com"
        self.developer_name = "Test Developer"

    def test_create_key_info(self):
        """Test KeyInfo creation from public key data."""
        key_info = self.manager.create_key_info(
            self.public_key_pem,
            self.domain,
            self.developer_name
        )

        self.assertIsInstance(key_info, KeyInfo)
        self.assertEqual(key_info.domain, self.domain)
        self.assertEqual(key_info.developer_name, self.developer_name)
        self.assertIsNotNone(key_info.fingerprint)
        self.assertTrue(key_info.fingerprint.startswith("sha256:"))

    def test_prompt_first_time_key(self):
        """Test first-time key encounter prompt."""
        self.mock_handler.prompt_user.return_value = UserDecision.ACCEPT

        decision = self.manager.prompt_first_time_key(
            self.tool_id,
            self.domain,
            self.public_key_pem,
            {"developer_name": self.developer_name}
        )

        self.assertEqual(decision, UserDecision.ACCEPT)
        self.mock_handler.prompt_user.assert_called_once()

        # Check context passed to handler
        call_args = self.mock_handler.prompt_user.call_args[0][0]
        self.assertEqual(call_args.prompt_type, PromptType.FIRST_TIME_KEY)
        self.assertEqual(call_args.tool_id, self.tool_id)
        self.assertEqual(call_args.domain, self.domain)

    def test_prompt_key_change(self):
        """Test key change prompt."""
        # Generate second key
        _, new_public_key = KeyManager.generate_keypair()
        new_public_key_pem = KeyManager.export_public_key_pem(new_public_key)

        self.mock_handler.prompt_user.return_value = UserDecision.REJECT

        decision = self.manager.prompt_key_change(
            self.tool_id,
            self.domain,
            self.public_key_pem,
            new_public_key_pem,
            {"developer_name": self.developer_name}
        )

        self.assertEqual(decision, UserDecision.REJECT)
        self.mock_handler.prompt_user.assert_called_once()

        # Check context
        call_args = self.mock_handler.prompt_user.call_args[0][0]
        self.assertEqual(call_args.prompt_type, PromptType.KEY_CHANGE)
        self.assertIsNotNone(call_args.current_key)
        self.assertIsNotNone(call_args.new_key)

    def test_prompt_revoked_key(self):
        """Test revoked key prompt."""
        self.mock_handler.prompt_user.return_value = UserDecision.REJECT

        decision = self.manager.prompt_revoked_key(
            self.tool_id,
            self.domain,
            self.public_key_pem,
            {"developer_name": self.developer_name}
        )

        self.assertEqual(decision, UserDecision.REJECT)
        self.mock_handler.prompt_user.assert_called_once()

        # Check context
        call_args = self.mock_handler.prompt_user.call_args[0][0]
        self.assertEqual(call_args.prompt_type, PromptType.REVOKED_KEY)
        self.assertTrue(call_args.current_key.is_revoked)


class TestCallbackInteractiveHandler(unittest.TestCase):
    """Test callback-based interactive handler."""

    def test_callback_handler(self):
        """Test callback handler functionality."""
        mock_callback = Mock(return_value=UserDecision.ACCEPT)
        handler = CallbackInteractiveHandler(mock_callback)

        context = PromptContext(
            prompt_type=PromptType.FIRST_TIME_KEY,
            tool_id="test-tool",
            domain="example.com"
        )

        decision = handler.prompt_user(context)

        self.assertEqual(decision, UserDecision.ACCEPT)
        mock_callback.assert_called_once_with(context)

    def test_display_key_info(self):
        """Test key info display formatting."""
        handler = CallbackInteractiveHandler(Mock())

        key_info = KeyInfo(
            fingerprint="sha256:abc123",
            pem_data="test-pem",
            domain="example.com",
            developer_name="Test Dev"
        )

        display_text = handler.display_key_info(key_info)

        self.assertIn("sha256:abc123", display_text)
        self.assertIn("example.com", display_text)
        self.assertIn("Test Dev", display_text)


class TestKeyPinningInteractive(unittest.TestCase):
    """Test KeyPinning class with interactive functionality."""

    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.temp_dir, "test_pinning.db")

        # Mock interactive handler
        self.mock_handler = Mock()

        # Generate test keys
        self.private_key, self.public_key = KeyManager.generate_keypair()
        self.public_key_pem = KeyManager.export_public_key_pem(self.public_key)

        # Test data
        self.tool_id = "test-tool"
        self.domain = "example.com"
        self.developer_name = "Test Developer"

    def tearDown(self):
        """Clean up test fixtures."""
        if os.path.exists(self.db_path):
            os.unlink(self.db_path)
        os.rmdir(self.temp_dir)

    def test_automatic_mode_pinning(self):
        """Test automatic mode pinning."""
        pinning = KeyPinning(
            db_path=self.db_path,
            mode=PinningMode.AUTOMATIC
        )

        # Should pin automatically without prompts
        result = pinning.interactive_pin_key(
            self.tool_id,
            self.public_key_pem,
            self.domain,
            self.developer_name
        )

        self.assertTrue(result)
        self.assertTrue(pinning.is_key_pinned(self.tool_id))

    def test_interactive_mode_first_time_accept(self):
        """Test interactive mode with first-time key acceptance."""
        pinning = KeyPinning(
            db_path=self.db_path,
            mode=PinningMode.INTERACTIVE,
            interactive_handler=self.mock_handler
        )

        # Mock user accepting the key
        pinning.interactive_manager.prompt_first_time_key = Mock(
            return_value=UserDecision.ACCEPT
        )

        with patch('schemapin.pinning.PublicKeyDiscovery.validate_key_not_revoked', return_value=True):
            result = pinning.interactive_pin_key(
                self.tool_id,
                self.public_key_pem,
                self.domain,
                self.developer_name
            )

        self.assertTrue(result)
        self.assertTrue(pinning.is_key_pinned(self.tool_id))

    def test_interactive_mode_first_time_reject(self):
        """Test interactive mode with first-time key rejection."""
        pinning = KeyPinning(
            db_path=self.db_path,
            mode=PinningMode.INTERACTIVE,
            interactive_handler=self.mock_handler
        )

        # Mock user rejecting the key
        pinning.interactive_manager.prompt_first_time_key = Mock(
            return_value=UserDecision.REJECT
        )

        with patch('schemapin.pinning.PublicKeyDiscovery.validate_key_not_revoked', return_value=True):
            result = pinning.interactive_pin_key(
                self.tool_id,
                self.public_key_pem,
                self.domain,
                self.developer_name
            )

        self.assertFalse(result)
        self.assertFalse(pinning.is_key_pinned(self.tool_id))

    def test_key_change_scenario(self):
        """Test key change handling."""
        pinning = KeyPinning(
            db_path=self.db_path,
            mode=PinningMode.INTERACTIVE,
            interactive_handler=self.mock_handler
        )

        # Pin initial key
        pinning.pin_key(self.tool_id, self.public_key_pem, self.domain, self.developer_name)

        # Generate new key
        _, new_public_key = KeyManager.generate_keypair()
        new_public_key_pem = KeyManager.export_public_key_pem(new_public_key)

        # Mock user accepting key change
        pinning.interactive_manager.prompt_key_change = Mock(
            return_value=UserDecision.ACCEPT
        )

        with patch('schemapin.pinning.PublicKeyDiscovery.validate_key_not_revoked', return_value=True):
            result = pinning.interactive_pin_key(
                self.tool_id,
                new_public_key_pem,
                self.domain,
                self.developer_name
            )

        self.assertTrue(result)
        # Should have new key pinned
        self.assertEqual(pinning.get_pinned_key(self.tool_id), new_public_key_pem)

    def test_domain_policy_always_trust(self):
        """Test always trust domain policy."""
        pinning = KeyPinning(
            db_path=self.db_path,
            mode=PinningMode.INTERACTIVE,
            interactive_handler=self.mock_handler
        )

        # Set always trust policy
        pinning.set_domain_policy(self.domain, PinningPolicy.ALWAYS_TRUST)

        # Should pin without prompts
        result = pinning.interactive_pin_key(
            self.tool_id,
            self.public_key_pem,
            self.domain,
            self.developer_name
        )

        self.assertTrue(result)
        self.assertTrue(pinning.is_key_pinned(self.tool_id))

    def test_domain_policy_never_trust(self):
        """Test never trust domain policy."""
        pinning = KeyPinning(
            db_path=self.db_path,
            mode=PinningMode.INTERACTIVE,
            interactive_handler=self.mock_handler
        )

        # Set never trust policy
        pinning.set_domain_policy(self.domain, PinningPolicy.NEVER_TRUST)

        # Should reject without prompts
        result = pinning.interactive_pin_key(
            self.tool_id,
            self.public_key_pem,
            self.domain,
            self.developer_name
        )

        self.assertFalse(result)
        self.assertFalse(pinning.is_key_pinned(self.tool_id))

    def test_strict_mode_key_change_rejection(self):
        """Test strict mode rejecting key changes."""
        pinning = KeyPinning(
            db_path=self.db_path,
            mode=PinningMode.STRICT,
            interactive_handler=self.mock_handler
        )

        # Pin initial key
        pinning.pin_key(self.tool_id, self.public_key_pem, self.domain, self.developer_name)

        # Generate new key
        _, new_public_key = KeyManager.generate_keypair()
        new_public_key_pem = KeyManager.export_public_key_pem(new_public_key)

        # Should reject key change in strict mode
        result = pinning.interactive_pin_key(
            self.tool_id,
            new_public_key_pem,
            self.domain,
            self.developer_name
        )

        self.assertFalse(result)
        # Should still have original key
        self.assertEqual(pinning.get_pinned_key(self.tool_id), self.public_key_pem)

    @patch('schemapin.pinning.PublicKeyDiscovery.validate_key_not_revoked')
    def test_revoked_key_handling(self, mock_validate):
        """Test handling of revoked keys."""
        mock_validate.return_value = False  # Key is revoked

        pinning = KeyPinning(
            db_path=self.db_path,
            mode=PinningMode.INTERACTIVE,
            interactive_handler=self.mock_handler
        )

        # Mock user rejecting revoked key
        pinning.interactive_manager.prompt_revoked_key = Mock(
            return_value=UserDecision.REJECT
        )

        result = pinning.interactive_pin_key(
            self.tool_id,
            self.public_key_pem,
            self.domain,
            self.developer_name
        )

        self.assertFalse(result)
        self.assertFalse(pinning.is_key_pinned(self.tool_id))


if __name__ == '__main__':
    unittest.main()
