"""Interactive key pinning interface for user prompts and decisions."""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import Callable, Dict, Optional

from .crypto import KeyManager


class PromptType(Enum):
    """Types of interactive prompts for key pinning."""
    FIRST_TIME_KEY = "first_time_key"
    KEY_CHANGE = "key_change"
    REVOKED_KEY = "revoked_key"
    EXPIRED_KEY = "expired_key"


class UserDecision(Enum):
    """User decisions for key pinning prompts."""
    ACCEPT = "accept"
    REJECT = "reject"
    ALWAYS_TRUST = "always_trust"
    NEVER_TRUST = "never_trust"
    TEMPORARY_ACCEPT = "temporary_accept"


@dataclass
class KeyInfo:
    """Information about a public key for display to users."""
    fingerprint: str
    pem_data: str
    domain: str
    developer_name: Optional[str] = None
    pinned_at: Optional[str] = None
    last_verified: Optional[str] = None
    is_revoked: bool = False


@dataclass
class PromptContext:
    """Context information for interactive prompts."""
    prompt_type: PromptType
    tool_id: str
    domain: str
    current_key: Optional[KeyInfo] = None
    new_key: Optional[KeyInfo] = None
    developer_info: Optional[Dict[str, str]] = None
    security_warning: Optional[str] = None


class InteractiveHandler(ABC):
    """Abstract base class for interactive key pinning handlers."""

    @abstractmethod
    def prompt_user(self, context: PromptContext) -> UserDecision:
        """
        Prompt user for decision on key pinning.

        Args:
            context: Context information for the prompt

        Returns:
            User's decision
        """
        pass

    @abstractmethod
    def display_key_info(self, key_info: KeyInfo) -> str:
        """
        Format key information for display.

        Args:
            key_info: Key information to display

        Returns:
            Formatted string for display
        """
        pass

    @abstractmethod
    def display_security_warning(self, warning: str) -> None:
        """
        Display security warning to user.

        Args:
            warning: Warning message to display
        """
        pass


class ConsoleInteractiveHandler(InteractiveHandler):
    """Console-based interactive handler for key pinning."""

    def prompt_user(self, context: PromptContext) -> UserDecision:
        """Prompt user via console for key pinning decision."""
        print("\n" + "="*60)
        print("SCHEMAPIN SECURITY PROMPT")
        print("="*60)

        if context.prompt_type == PromptType.FIRST_TIME_KEY:
            self._display_first_time_prompt(context)
        elif context.prompt_type == PromptType.KEY_CHANGE:
            self._display_key_change_prompt(context)
        elif context.prompt_type == PromptType.REVOKED_KEY:
            self._display_revoked_key_prompt(context)

        return self._get_user_choice(context.prompt_type)

    def display_key_info(self, key_info: KeyInfo) -> str:
        """Format key information for console display."""
        info_lines = [
            f"Fingerprint: {key_info.fingerprint}",
            f"Domain: {key_info.domain}",
        ]

        if key_info.developer_name:
            info_lines.append(f"Developer: {key_info.developer_name}")

        if key_info.pinned_at:
            info_lines.append(f"Pinned: {key_info.pinned_at}")

        if key_info.last_verified:
            info_lines.append(f"Last Verified: {key_info.last_verified}")

        if key_info.is_revoked:
            info_lines.append("⚠️  STATUS: REVOKED")

        return "\n".join(info_lines)

    def display_security_warning(self, warning: str) -> None:
        """Display security warning to console."""
        print(f"\n⚠️  SECURITY WARNING: {warning}\n")

    def _display_first_time_prompt(self, context: PromptContext) -> None:
        """Display first-time key encounter prompt."""
        print(f"\nFirst-time key encounter for tool: {context.tool_id}")
        print(f"Domain: {context.domain}")

        if context.developer_info:
            print(f"Developer: {context.developer_info.get('developer_name', 'Unknown')}")

        if context.new_key:
            print("\nNew Key Information:")
            print(self.display_key_info(context.new_key))

        print("\nThis is the first time you're encountering this tool.")
        print("Do you want to pin this key for future verification?")

    def _display_key_change_prompt(self, context: PromptContext) -> None:
        """Display key change prompt."""
        print(f"\n⚠️  KEY CHANGE DETECTED for tool: {context.tool_id}")
        print(f"Domain: {context.domain}")

        if context.current_key:
            print("\nCurrently Pinned Key:")
            print(self.display_key_info(context.current_key))

        if context.new_key:
            print("\nNew Key Being Offered:")
            print(self.display_key_info(context.new_key))

        print("\n⚠️  The tool is using a different key than previously pinned!")
        print("This could indicate a legitimate key rotation or a security compromise.")

    def _display_revoked_key_prompt(self, context: PromptContext) -> None:
        """Display revoked key prompt."""
        print(f"\n🚨 REVOKED KEY DETECTED for tool: {context.tool_id}")
        print(f"Domain: {context.domain}")

        if context.current_key:
            print("\nRevoked Key Information:")
            print(self.display_key_info(context.current_key))

        print("\n🚨 This key has been marked as revoked by the developer!")
        print("Using this tool is NOT RECOMMENDED.")

        if context.security_warning:
            self.display_security_warning(context.security_warning)

    def _get_user_choice(self, prompt_type: PromptType) -> UserDecision:
        """Get user's choice from console input."""
        if prompt_type == PromptType.REVOKED_KEY:
            choices = {
                'r': UserDecision.REJECT,
                'n': UserDecision.NEVER_TRUST,
            }
            prompt = "\nChoices:\n  r) Reject (recommended)\n  n) Never trust this domain\nChoice [r]: "
            default = UserDecision.REJECT
        else:
            choices = {
                'a': UserDecision.ACCEPT,
                'r': UserDecision.REJECT,
                't': UserDecision.ALWAYS_TRUST,
                'n': UserDecision.NEVER_TRUST,
                'o': UserDecision.TEMPORARY_ACCEPT,
            }
            prompt = ("\nChoices:\n"
                     "  a) Accept and pin this key\n"
                     "  r) Reject this key\n"
                     "  t) Always trust this domain\n"
                     "  n) Never trust this domain\n"
                     "  o) Accept once (temporary)\n"
                     "Choice [r]: ")
            default = UserDecision.REJECT

        while True:
            try:
                choice = input(prompt).lower().strip()
                if not choice:
                    return default
                if choice in choices:
                    return choices[choice]
                print("Invalid choice. Please try again.")
            except (KeyboardInterrupt, EOFError):
                return UserDecision.REJECT


class CallbackInteractiveHandler(InteractiveHandler):
    """Callback-based interactive handler for custom implementations."""

    def __init__(self,
                 prompt_callback: Callable[[PromptContext], UserDecision],
                 display_callback: Optional[Callable[[str], None]] = None):
        """
        Initialize callback handler.

        Args:
            prompt_callback: Function to handle user prompts
            display_callback: Optional function to display messages
        """
        self.prompt_callback = prompt_callback
        self.display_callback = display_callback or print

    def prompt_user(self, context: PromptContext) -> UserDecision:
        """Prompt user via callback function."""
        return self.prompt_callback(context)

    def display_key_info(self, key_info: KeyInfo) -> str:
        """Format key information for display."""
        info_parts = [
            f"Fingerprint: {key_info.fingerprint}",
            f"Domain: {key_info.domain}",
        ]

        if key_info.developer_name:
            info_parts.append(f"Developer: {key_info.developer_name}")

        if key_info.is_revoked:
            info_parts.append("STATUS: REVOKED")

        return " | ".join(info_parts)

    def display_security_warning(self, warning: str) -> None:
        """Display security warning via callback."""
        if self.display_callback:
            self.display_callback(f"SECURITY WARNING: {warning}")


class InteractivePinningManager:
    """Manages interactive key pinning with user prompts."""

    def __init__(self, handler: Optional[InteractiveHandler] = None):
        """
        Initialize interactive pinning manager.

        Args:
            handler: Interactive handler for user prompts. Defaults to console handler.
        """
        self.handler = handler or ConsoleInteractiveHandler()

    def create_key_info(self, public_key_pem: str, domain: str,
                       developer_name: Optional[str] = None,
                       pinned_at: Optional[str] = None,
                       last_verified: Optional[str] = None,
                       is_revoked: bool = False) -> KeyInfo:
        """
        Create KeyInfo object from public key data.

        Args:
            public_key_pem: PEM-encoded public key
            domain: Tool provider domain
            developer_name: Optional developer name
            pinned_at: Optional pinning timestamp
            last_verified: Optional last verification timestamp
            is_revoked: Whether key is revoked

        Returns:
            KeyInfo object
        """
        try:
            fingerprint = KeyManager.calculate_key_fingerprint_from_pem(public_key_pem)
        except Exception:
            fingerprint = "Invalid key"

        return KeyInfo(
            fingerprint=fingerprint,
            pem_data=public_key_pem,
            domain=domain,
            developer_name=developer_name,
            pinned_at=pinned_at,
            last_verified=last_verified,
            is_revoked=is_revoked
        )

    def prompt_first_time_key(self, tool_id: str, domain: str,
                             public_key_pem: str,
                             developer_info: Optional[Dict[str, str]] = None) -> UserDecision:
        """
        Prompt user for first-time key encounter.

        Args:
            tool_id: Tool identifier
            domain: Tool provider domain
            public_key_pem: PEM-encoded public key
            developer_info: Optional developer information

        Returns:
            User's decision
        """
        new_key = self.create_key_info(public_key_pem, domain,
                                      developer_info.get('developer_name') if developer_info else None)

        context = PromptContext(
            prompt_type=PromptType.FIRST_TIME_KEY,
            tool_id=tool_id,
            domain=domain,
            new_key=new_key,
            developer_info=developer_info
        )

        return self.handler.prompt_user(context)

    def prompt_key_change(self, tool_id: str, domain: str,
                         current_key_pem: str, new_key_pem: str,
                         current_key_info: Optional[Dict[str, str]] = None,
                         developer_info: Optional[Dict[str, str]] = None) -> UserDecision:
        """
        Prompt user for key change.

        Args:
            tool_id: Tool identifier
            domain: Tool provider domain
            current_key_pem: Currently pinned key
            new_key_pem: New key being offered
            current_key_info: Optional current key metadata
            developer_info: Optional developer information

        Returns:
            User's decision
        """
        current_key = self.create_key_info(
            current_key_pem, domain,
            current_key_info.get('developer_name') if current_key_info else None,
            current_key_info.get('pinned_at') if current_key_info else None,
            current_key_info.get('last_verified') if current_key_info else None
        )

        new_key = self.create_key_info(
            new_key_pem, domain,
            developer_info.get('developer_name') if developer_info else None
        )

        context = PromptContext(
            prompt_type=PromptType.KEY_CHANGE,
            tool_id=tool_id,
            domain=domain,
            current_key=current_key,
            new_key=new_key,
            developer_info=developer_info
        )

        return self.handler.prompt_user(context)

    def prompt_revoked_key(self, tool_id: str, domain: str,
                          revoked_key_pem: str,
                          key_info: Optional[Dict[str, str]] = None) -> UserDecision:
        """
        Prompt user for revoked key detection.

        Args:
            tool_id: Tool identifier
            domain: Tool provider domain
            revoked_key_pem: Revoked key
            key_info: Optional key metadata

        Returns:
            User's decision
        """
        revoked_key = self.create_key_info(
            revoked_key_pem, domain,
            key_info.get('developer_name') if key_info else None,
            key_info.get('pinned_at') if key_info else None,
            key_info.get('last_verified') if key_info else None,
            is_revoked=True
        )

        context = PromptContext(
            prompt_type=PromptType.REVOKED_KEY,
            tool_id=tool_id,
            domain=domain,
            current_key=revoked_key,
            security_warning="This key has been revoked by the developer. Do not use this tool."
        )

        return self.handler.prompt_user(context)
