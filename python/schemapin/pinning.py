"""Key pinning storage and management for Trust-On-First-Use (TOFU)."""

import json
import sqlite3
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional

from .discovery import PublicKeyDiscovery
from .interactive import InteractiveHandler, InteractivePinningManager, UserDecision


class PinningMode(Enum):
    """Pinning operation modes."""
    AUTOMATIC = "automatic"
    INTERACTIVE = "interactive"
    STRICT = "strict"


class PinningPolicy(Enum):
    """Per-domain pinning policies."""
    DEFAULT = "default"
    ALWAYS_TRUST = "always_trust"
    NEVER_TRUST = "never_trust"
    INTERACTIVE_ONLY = "interactive_only"


class KeyPinning:
    """Manages key pinning storage using SQLite."""

    def __init__(self,
                 db_path: Optional[str] = None,
                 mode: PinningMode = PinningMode.AUTOMATIC,
                 interactive_handler: Optional[InteractiveHandler] = None):
        """
        Initialize key pinning storage.

        Args:
            db_path: Path to SQLite database file. If None, uses default location.
            mode: Pinning operation mode (automatic, interactive, strict)
            interactive_handler: Handler for interactive prompts
        """
        if db_path is None:
            db_path = str(Path.home() / '.schemapin' / 'pinned_keys.db')

        self.db_path = db_path
        self.mode = mode
        self.interactive_manager = InteractivePinningManager(interactive_handler) if mode == PinningMode.INTERACTIVE else None
        self._ensure_db_directory()
        self._init_database()

    def _ensure_db_directory(self) -> None:
        """Ensure database directory exists."""
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)

    def _init_database(self) -> None:
        """Initialize database schema."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS pinned_keys (
                    tool_id TEXT PRIMARY KEY,
                    public_key_pem TEXT NOT NULL,
                    domain TEXT NOT NULL,
                    developer_name TEXT,
                    pinned_at TEXT NOT NULL,
                    last_verified TEXT
                )
            ''')

            # Add domain policies table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS domain_policies (
                    domain TEXT PRIMARY KEY,
                    policy TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
            ''')
            conn.commit()

    def pin_key(
        self,
        tool_id: str,
        public_key_pem: str,
        domain: str,
        developer_name: Optional[str] = None
    ) -> bool:
        """
        Pin a public key for a tool.

        Args:
            tool_id: Unique tool identifier
            public_key_pem: PEM-encoded public key
            domain: Tool provider domain
            developer_name: Optional developer name

        Returns:
            True if key was pinned successfully, False if already exists
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('''
                    INSERT INTO pinned_keys
                    (tool_id, public_key_pem, domain, developer_name, pinned_at)
                    VALUES (?, ?, ?, ?, ?)
                ''', (
                    tool_id,
                    public_key_pem,
                    domain,
                    developer_name,
                    datetime.now(UTC).isoformat()
                ))
                conn.commit()
                return True
        except sqlite3.IntegrityError:
            return False

    def get_pinned_key(self, tool_id: str) -> Optional[str]:
        """
        Get pinned public key for tool.

        Args:
            tool_id: Tool identifier

        Returns:
            PEM-encoded public key if pinned, None otherwise
        """
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                'SELECT public_key_pem FROM pinned_keys WHERE tool_id = ?',
                (tool_id,)
            )
            result = cursor.fetchone()
            return result[0] if result else None

    def is_key_pinned(self, tool_id: str) -> bool:
        """
        Check if key is pinned for tool.

        Args:
            tool_id: Tool identifier

        Returns:
            True if key is pinned, False otherwise
        """
        return self.get_pinned_key(tool_id) is not None

    def update_last_verified(self, tool_id: str) -> bool:
        """
        Update last verification timestamp for tool.

        Args:
            tool_id: Tool identifier

        Returns:
            True if updated successfully, False if tool not found
        """
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute('''
                UPDATE pinned_keys
                SET last_verified = ?
                WHERE tool_id = ?
            ''', (datetime.now(UTC).isoformat(), tool_id))
            conn.commit()
            return cursor.rowcount > 0

    def list_pinned_keys(self) -> List[Dict[str, str]]:
        """
        List all pinned keys with metadata.

        Returns:
            List of dictionaries containing key information
        """
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute('''
                SELECT tool_id, domain, developer_name, pinned_at, last_verified
                FROM pinned_keys
                ORDER BY pinned_at DESC
            ''')
            return [dict(row) for row in cursor.fetchall()]

    def remove_pinned_key(self, tool_id: str) -> bool:
        """
        Remove pinned key for tool.

        Args:
            tool_id: Tool identifier

        Returns:
            True if removed successfully, False if not found
        """
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                'DELETE FROM pinned_keys WHERE tool_id = ?',
                (tool_id,)
            )
            conn.commit()
            return cursor.rowcount > 0

    def get_key_info(self, tool_id: str) -> Optional[Dict[str, str]]:
        """
        Get complete information about pinned key.

        Args:
            tool_id: Tool identifier

        Returns:
            Dictionary with key information if found, None otherwise
        """
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute('''
                SELECT tool_id, public_key_pem, domain, developer_name,
                       pinned_at, last_verified
                FROM pinned_keys
                WHERE tool_id = ?
            ''', (tool_id,))
            result = cursor.fetchone()
            return dict(result) if result else None

    def export_pinned_keys(self) -> str:
        """
        Export all pinned keys to JSON format.

        Returns:
            JSON string containing all pinned keys
        """
        keys = self.list_pinned_keys()
        # Add public key data for export
        for key_info in keys:
            key_info['public_key_pem'] = self.get_pinned_key(key_info['tool_id'])

        return json.dumps(keys, indent=2)

    def import_pinned_keys(self, json_data: str, overwrite: bool = False) -> int:
        """
        Import pinned keys from JSON format.

        Args:
            json_data: JSON string containing key data
            overwrite: Whether to overwrite existing keys

        Returns:
            Number of keys imported
        """
        try:
            keys = json.loads(json_data)
            imported = 0

            for key_info in keys:
                if overwrite and self.is_key_pinned(key_info['tool_id']):
                    self.remove_pinned_key(key_info['tool_id'])

                if self.pin_key(
                    key_info['tool_id'],
                    key_info['public_key_pem'],
                    key_info['domain'],
                    key_info.get('developer_name')
                ):
                    imported += 1

            return imported
        except (json.JSONDecodeError, KeyError):
            return 0

    def set_domain_policy(self, domain: str, policy: PinningPolicy) -> bool:
        """
        Set pinning policy for a domain.

        Args:
            domain: Domain to set policy for
            policy: Pinning policy to apply

        Returns:
            True if policy was set successfully
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('''
                    INSERT OR REPLACE INTO domain_policies
                    (domain, policy, created_at)
                    VALUES (?, ?, ?)
                ''', (domain, policy.value, datetime.now(UTC).isoformat()))
                conn.commit()
                return True
        except sqlite3.Error:
            return False

    def get_domain_policy(self, domain: str) -> PinningPolicy:
        """
        Get pinning policy for a domain.

        Args:
            domain: Domain to get policy for

        Returns:
            Pinning policy for domain, defaults to DEFAULT
        """
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                'SELECT policy FROM domain_policies WHERE domain = ?',
                (domain,)
            )
            result = cursor.fetchone()
            if result:
                try:
                    return PinningPolicy(result[0])
                except ValueError:
                    return PinningPolicy.DEFAULT
            return PinningPolicy.DEFAULT

    def interactive_pin_key(self,
                           tool_id: str,
                           public_key_pem: str,
                           domain: str,
                           developer_name: Optional[str] = None,
                           force_prompt: bool = False) -> bool:
        """
        Pin a key with interactive user confirmation.

        Args:
            tool_id: Unique tool identifier
            public_key_pem: PEM-encoded public key
            domain: Tool provider domain
            developer_name: Optional developer name
            force_prompt: Force interactive prompt even in automatic mode

        Returns:
            True if key was pinned, False if rejected or error
        """
        # Check domain policy first
        domain_policy = self.get_domain_policy(domain)

        if domain_policy == PinningPolicy.NEVER_TRUST:
            return False
        elif domain_policy == PinningPolicy.ALWAYS_TRUST:
            return self.pin_key(tool_id, public_key_pem, domain, developer_name)

        # Check if key is already pinned
        existing_key = self.get_pinned_key(tool_id)
        if existing_key:
            if existing_key == public_key_pem:
                # Same key, just update verification time
                self.update_last_verified(tool_id)
                return True
            else:
                # Different key - handle key change
                return self._handle_key_change(tool_id, domain, existing_key,
                                             public_key_pem, developer_name)

        # First-time key encounter
        return self._handle_first_time_key(tool_id, domain, public_key_pem,
                                         developer_name, force_prompt)

    def _handle_first_time_key(self,
                              tool_id: str,
                              domain: str,
                              public_key_pem: str,
                              developer_name: Optional[str],
                              force_prompt: bool) -> bool:
        """Handle first-time key encounter."""
        # Check if key is revoked
        if not PublicKeyDiscovery.validate_key_not_revoked(public_key_pem, domain):
            if self.interactive_manager:
                decision = self.interactive_manager.prompt_revoked_key(
                    tool_id, domain, public_key_pem,
                    {'developer_name': developer_name}
                )
                return decision == UserDecision.TEMPORARY_ACCEPT
            return False

        # Automatic mode without force prompt
        if self.mode == PinningMode.AUTOMATIC and not force_prompt:
            return self.pin_key(tool_id, public_key_pem, domain, developer_name)

        # Interactive mode or forced prompt
        if self.interactive_manager:
            developer_info = PublicKeyDiscovery.get_developer_info(domain)
            decision = self.interactive_manager.prompt_first_time_key(
                tool_id, domain, public_key_pem, developer_info
            )

            if decision == UserDecision.ACCEPT:
                return self.pin_key(tool_id, public_key_pem, domain, developer_name)
            elif decision == UserDecision.ALWAYS_TRUST:
                self.set_domain_policy(domain, PinningPolicy.ALWAYS_TRUST)
                return self.pin_key(tool_id, public_key_pem, domain, developer_name)
            elif decision == UserDecision.NEVER_TRUST:
                self.set_domain_policy(domain, PinningPolicy.NEVER_TRUST)
                return False
            elif decision == UserDecision.TEMPORARY_ACCEPT:
                # Don't pin, but allow this verification
                return True

        return False

    def _handle_key_change(self,
                          tool_id: str,
                          domain: str,
                          current_key_pem: str,
                          new_key_pem: str,
                          developer_name: Optional[str]) -> bool:
        """Handle key change scenario."""
        # Check if new key is revoked
        if not PublicKeyDiscovery.validate_key_not_revoked(new_key_pem, domain):
            if self.interactive_manager:
                decision = self.interactive_manager.prompt_revoked_key(
                    tool_id, domain, new_key_pem,
                    {'developer_name': developer_name}
                )
                return decision == UserDecision.TEMPORARY_ACCEPT
            return False

        # In strict mode, always reject key changes
        if self.mode == PinningMode.STRICT:
            return False

        # Interactive prompt for key change
        if self.interactive_manager:
            current_key_info = self.get_key_info(tool_id)
            developer_info = PublicKeyDiscovery.get_developer_info(domain)

            decision = self.interactive_manager.prompt_key_change(
                tool_id, domain, current_key_pem, new_key_pem,
                current_key_info, developer_info
            )

            if decision == UserDecision.ACCEPT:
                # Remove old key and pin new one
                self.remove_pinned_key(tool_id)
                return self.pin_key(tool_id, new_key_pem, domain, developer_name)
            elif decision == UserDecision.ALWAYS_TRUST:
                self.set_domain_policy(domain, PinningPolicy.ALWAYS_TRUST)
                self.remove_pinned_key(tool_id)
                return self.pin_key(tool_id, new_key_pem, domain, developer_name)
            elif decision == UserDecision.NEVER_TRUST:
                self.set_domain_policy(domain, PinningPolicy.NEVER_TRUST)
                return False
            elif decision == UserDecision.TEMPORARY_ACCEPT:
                # Don't update pinned key, but allow this verification
                return True

        return False

    def verify_with_interactive_pinning(self,
                                      tool_id: str,
                                      domain: str,
                                      public_key_pem: str,
                                      developer_name: Optional[str] = None) -> bool:
        """
        Verify and potentially pin a key with interactive prompts.

        Args:
            tool_id: Tool identifier
            domain: Tool provider domain
            public_key_pem: PEM-encoded public key to verify
            developer_name: Optional developer name

        Returns:
            True if key is verified/pinned and can be used, False otherwise
        """
        return self.interactive_pin_key(tool_id, public_key_pem, domain, developer_name)
