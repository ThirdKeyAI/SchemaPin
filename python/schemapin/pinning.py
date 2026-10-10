"""Key pinning storage and management for Trust-On-First-Use (TOFU).

.. deprecated:: 1.4.0
    :class:`KeyPinning` is the legacy PEM-by-tool store used by
    :class:`~schemapin.utils.SchemaVerificationWorkflow`. New code should use
    :class:`~schemapin.verification.KeyPinStore` (fingerprint pins keyed by
    ``tool_id@domain``) with :func:`~schemapin.verification.verify_schema_offline`;
    this class is retained as a persistence backend for existing deployments.

Pins are keyed by ``(tool_id, domain)``. A pin made for one domain is never
returned for another, so a key pinned for ``evil.com`` cannot satisfy a
verification for ``good.com`` that happens to reuse the same tool id.
"""

import json
import os
import sqlite3
import warnings
from datetime import datetime, timezone
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
        warnings.warn(
            "KeyPinning is the legacy PEM-by-tool pin store; prefer "
            "schemapin.verification.KeyPinStore with verify_schema_offline",
            DeprecationWarning,
            stacklevel=2,
        )
        if db_path is None:
            db_path = str(Path.home() / '.schemapin' / 'pinned_keys.db')

        self.db_path = db_path
        self.mode = mode
        self.interactive_manager = InteractivePinningManager(interactive_handler) if mode == PinningMode.INTERACTIVE else None
        self._ensure_db_directory()
        self._init_database()

    def _ensure_db_directory(self) -> None:
        """Ensure database directory exists (owner-only)."""
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True, mode=0o700)

    def _init_database(self) -> None:
        """Initialize database schema, migrating legacy single-key tables."""
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT sql FROM sqlite_master WHERE type='table' AND name='pinned_keys'"
            ).fetchone()
            if row and "PRIMARY KEY (tool_id, domain)" not in row[0]:
                # Legacy schema keyed by tool_id only: rebuild with the
                # composite key, preserving every existing row.
                conn.execute("ALTER TABLE pinned_keys RENAME TO pinned_keys_legacy")
                conn.execute('''
                    CREATE TABLE pinned_keys (
                        tool_id TEXT NOT NULL,
                        public_key_pem TEXT NOT NULL,
                        domain TEXT NOT NULL,
                        developer_name TEXT,
                        pinned_at TEXT NOT NULL,
                        last_verified TEXT,
                        PRIMARY KEY (tool_id, domain)
                    )
                ''')
                conn.execute('''
                    INSERT OR IGNORE INTO pinned_keys
                    SELECT tool_id, public_key_pem, domain, developer_name, pinned_at, last_verified
                    FROM pinned_keys_legacy
                ''')
                conn.execute("DROP TABLE pinned_keys_legacy")
            conn.execute('''
                CREATE TABLE IF NOT EXISTS pinned_keys (
                    tool_id TEXT NOT NULL,
                    public_key_pem TEXT NOT NULL,
                    domain TEXT NOT NULL,
                    developer_name TEXT,
                    pinned_at TEXT NOT NULL,
                    last_verified TEXT,
                    PRIMARY KEY (tool_id, domain)
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
        try:
            os.chmod(self.db_path, 0o600)
        except OSError:
            pass

    @staticmethod
    def _where(tool_id: str, domain: Optional[str]) -> tuple:
        """Build the lookup predicate; ``domain=None`` is the deprecated
        tool-id-only lookup kept for callers that predate domain binding."""
        if domain is None:
            return "tool_id = ?", (tool_id,)
        return "tool_id = ? AND domain = ?", (tool_id, domain)

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
                    datetime.now(timezone.utc).isoformat()
                ))
                conn.commit()
                return True
        except sqlite3.IntegrityError:
            return False

    def get_pinned_key(self, tool_id: str, domain: Optional[str] = None) -> Optional[str]:
        """
        Get the pinned public key for a tool at a domain.

        Args:
            tool_id: Tool identifier
            domain: Tool provider domain. Always pass it: a pin recorded for
                a different domain is never returned. ``None`` performs the
                deprecated tool-id-only lookup and returns ``None`` when the
                tool id is pinned for more than one domain.

        Returns:
            PEM-encoded public key if pinned, None otherwise
        """
        where, params = self._where(tool_id, domain)
        with sqlite3.connect(self.db_path) as conn:
            rows = conn.execute(
                f'SELECT public_key_pem FROM pinned_keys WHERE {where}', params
            ).fetchall()
            if len(rows) != 1:
                return None
            return rows[0][0]

    def is_key_pinned(self, tool_id: str, domain: Optional[str] = None) -> bool:
        """
        Check if a key is pinned for a tool at a domain.

        Args:
            tool_id: Tool identifier
            domain: Tool provider domain (see :meth:`get_pinned_key`)

        Returns:
            True if key is pinned, False otherwise
        """
        return self.get_pinned_key(tool_id, domain) is not None

    def update_last_verified(self, tool_id: str, domain: Optional[str] = None) -> bool:
        """
        Update last verification timestamp for tool.

        Args:
            tool_id: Tool identifier
            domain: Tool provider domain

        Returns:
            True if updated successfully, False if tool not found
        """
        where, params = self._where(tool_id, domain)
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                f'UPDATE pinned_keys SET last_verified = ? WHERE {where}',
                (datetime.now(timezone.utc).isoformat(), *params),
            )
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

    def remove_pinned_key(self, tool_id: str, domain: Optional[str] = None) -> bool:
        """
        Remove pinned key for tool.

        Args:
            tool_id: Tool identifier
            domain: Tool provider domain (``None`` removes every domain's pin)

        Returns:
            True if removed successfully, False if not found
        """
        where, params = self._where(tool_id, domain)
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(f'DELETE FROM pinned_keys WHERE {where}', params)
            conn.commit()
            return cursor.rowcount > 0

    def get_key_info(self, tool_id: str, domain: Optional[str] = None) -> Optional[Dict[str, str]]:
        """
        Get complete information about pinned key.

        Args:
            tool_id: Tool identifier
            domain: Tool provider domain (see :meth:`get_pinned_key`)

        Returns:
            Dictionary with key information if found, None otherwise
        """
        where, params = self._where(tool_id, domain)
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(f'''
                SELECT tool_id, public_key_pem, domain, developer_name,
                       pinned_at, last_verified
                FROM pinned_keys
                WHERE {where}
            ''', params).fetchall()
            if len(rows) != 1:
                return None
            return dict(rows[0])

    def export_pinned_keys(self) -> str:
        """
        Export all pinned keys to JSON format.

        Returns:
            JSON string containing all pinned keys
        """
        keys = self.list_pinned_keys()
        # Add public key data for export
        for key_info in keys:
            key_info['public_key_pem'] = self.get_pinned_key(key_info['tool_id'], key_info['domain'])

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
                if overwrite and self.is_key_pinned(key_info['tool_id'], key_info['domain']):
                    self.remove_pinned_key(key_info['tool_id'], key_info['domain'])

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
                ''', (domain, policy.value, datetime.now(timezone.utc).isoformat()))
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

        # Check if key is already pinned for this tool at this domain
        existing_key = self.get_pinned_key(tool_id, domain)
        if existing_key:
            if existing_key == public_key_pem:
                # Same key, just update verification time
                self.update_last_verified(tool_id, domain)
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
            current_key_info = self.get_key_info(tool_id, domain)
            developer_info = PublicKeyDiscovery.get_developer_info(domain)

            decision = self.interactive_manager.prompt_key_change(
                tool_id, domain, current_key_pem, new_key_pem,
                current_key_info, developer_info
            )

            if decision == UserDecision.ACCEPT:
                # Remove old key and pin new one
                self.remove_pinned_key(tool_id, domain)
                return self.pin_key(tool_id, new_key_pem, domain, developer_name)
            elif decision == UserDecision.ALWAYS_TRUST:
                self.set_domain_policy(domain, PinningPolicy.ALWAYS_TRUST)
                self.remove_pinned_key(tool_id, domain)
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
