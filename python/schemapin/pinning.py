"""Key pinning storage and management for Trust-On-First-Use (TOFU)."""

import json
import sqlite3
from pathlib import Path
from typing import Dict, Optional, List
from datetime import datetime


class KeyPinning:
    """Manages key pinning storage using SQLite."""

    def __init__(self, db_path: Optional[str] = None):
        """
        Initialize key pinning storage.
        
        Args:
            db_path: Path to SQLite database file. If None, uses default location.
        """
        if db_path is None:
            db_path = str(Path.home() / '.schemapin' / 'pinned_keys.db')
        
        self.db_path = db_path
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
                    datetime.utcnow().isoformat()
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
            ''', (datetime.utcnow().isoformat(), tool_id))
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