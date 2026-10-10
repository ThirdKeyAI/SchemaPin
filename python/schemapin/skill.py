"""Skill folder signing and verification for SchemaPin v1.3 / v1.4.

Extends SchemaPin's ECDSA P-256 signing to cover file-based skill folders
(AgentSkills spec). Same keys, same .well-known discovery, new canonicalization
target.

Wire formats
------------

``schemapin_version: "1.4"`` (the default for every new signature):

* The directory is canonicalized with :meth:`SkillSigner.canonicalize_skill`
  (skill canonicalization v2, spec section 4b): every entry is hashed as
  ``SHA-256("f" || be64(len(path)) || path || be64(len(content)) || content)``
  and the root hash is ``SHA-256`` over ``be64(len(path)) || path || digest``
  for every entry in code-point path order. Symlinks are rejected.
* ``skill_hash`` is ``"sha256:" + hex(root_hash)``.
* The signature covers the **entire signature document**: the document is
  built with ``signature: ""``, canonicalized with ``schemapin-v1`` and signed
  as ``ECDSA-P256(SHA-256(canonical_bytes))``. ``expires_at``,
  ``schema_version``, ``previous_hash``, ``canonicalization``, ``domain``,
  ``skill_name``, ``signer_kid``, ``signed_at`` and ``file_manifest`` are
  therefore all integrity-protected.

``schemapin_version: "1.3"`` (legacy, verify-only):

* Entries hashed as ``SHA-256(path || content)``, root hash ``SHA-256`` of the
  concatenated hex digests, symlinks silently skipped, and the signature
  covers only the 32-byte root hash. None of the metadata fields are signed;
  verifiers surface a ``legacy_signature_format`` warning.

Verification is fail-closed on expiration and on domain mismatch.
"""

import hashlib
import json
import os
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from .core import SchemaPinCore
from .crypto import KeyManager, SignatureManager
from .dns import DnsTxtRecord, verify_dns_match
from .domain import InvalidDomainError, validate_domain
from .resolver import SchemaResolver
from .revocation import RevocationDocument, check_revocation_combined
from .verification import (
    EXPIRATION_SKEW_SECONDS,
    ErrorCode,
    KeyPinningStatus,
    KeyPinStore,
    VerificationResult,
    check_canonicalization,
)

SIGNATURE_FILENAME = ".schemapin.sig"
#: ``schemapin_version`` written on every new signature (signed-document format).
SCHEMAPIN_VERSION = "1.4"
#: Alias kept for callers that imported the v1.4 constant explicitly.
SCHEMAPIN_VERSION_V1_4 = "1.4"
#: Legacy root-hash-only format; accepted on verification, never written.
SCHEMAPIN_VERSION_LEGACY = "1.3"

#: Caps enforced by :meth:`SkillSigner.canonicalize_skill`.
MAX_SKILL_FILES = 10_000
MAX_SKILL_TOTAL_BYTES = 256 * 1024 * 1024

#: Fields covered by a v1.4 signature document, in no particular order
#: (``schemapin-v1`` canonicalization sorts them).
SIGNED_FIELDS = (
    "schemapin_version",
    "skill_name",
    "skill_hash",
    "signature",
    "signed_at",
    "expires_at",
    "schema_version",
    "previous_hash",
    "canonicalization",
    "domain",
    "signer_kid",
    "file_manifest",
)
_REQUIRED_FIELDS = (
    "schemapin_version",
    "skill_name",
    "skill_hash",
    "signature",
    "signed_at",
    "domain",
    "signer_kid",
    "file_manifest",
)
_OPTIONAL_FIELDS = ("expires_at", "schema_version", "previous_hash", "canonicalization")


class SkillCanonicalizationError(ValueError):
    """Raised when a skill directory cannot be canonicalized."""


@dataclass
class SignOptions:
    """Optional sign-time parameters for :meth:`SkillSigner.sign_with_options`.

    Mirrors the Rust ``SignOptions`` builder. All fields default to ``None``
    so call sites can pass only what they need::

        from datetime import timedelta
        opts = SignOptions(expires_in=timedelta(days=30))
        SkillSigner.sign_with_options(skill_dir, priv_pem, "example.com", opts)
    """

    signer_kid: Optional[str] = None
    skill_name: Optional[str] = None
    expires_in: Optional[timedelta] = None
    # Caller-supplied semver string identifying *this* version of the signed
    # artifact. Surfaced via VerificationResult for policy use.
    schema_version: Optional[str] = None
    # ``sha256:<hex>`` of the prior signed version's ``skill_hash``, forming a
    # hash chain. Pair with :func:`verify_chain` / :class:`LineageStore`.
    previous_hash: Optional[str] = None
    # Canonicalization algorithm identifier written to the signature. ``None``
    # is wire-equivalent to the implicit "schemapin-v1" default.
    canonicalization: Optional[str] = None


def _be64(n: int) -> bytes:
    return n.to_bytes(8, "big")


def _version_tuple(version: Any) -> Optional[Tuple[int, int]]:
    """Parse ``"major.minor"`` into a tuple, or ``None`` when malformed."""
    if not isinstance(version, str):
        return None
    m = re.match(r"^(\d+)\.(\d+)$", version)
    if m is None:
        return None
    return int(m.group(1)), int(m.group(2))


def _is_legacy_version(version: Any) -> bool:
    parsed = _version_tuple(version)
    return parsed is not None and parsed < (1, 4)


class SkillSigner:
    """Sign and verify file-based skill folders using ECDSA P-256.

    Mirrors the SchemaPinCore pattern -- static/classmethod only.
    """

    @staticmethod
    def canonicalize_skill(
        skill_dir: Union[str, Path],
    ) -> Tuple[bytes, Dict[str, str]]:
        """Walk a skill directory deterministically and compute the v2 root hash.

        Algorithm (spec section 4b):
          1. Walk the tree; directories are not entries. The top-level
             ``.schemapin.sig`` is excluded.
          2. Any symlink (file or directory) or non-regular file aborts
             canonicalization -- unsigned content must not be reachable from
             a signed skill.
          3. Paths are relative, forward-slash separated, UTF-8, and sorted by
             code point.
          4. Per entry: ``SHA-256(0x66 || be64(len(path)) || path ||
             be64(len(content)) || content)``.
          5. Root: ``SHA-256`` over ``be64(len(path)) || path || entry_digest``
             for every entry in sorted order.

        Returns:
            Tuple of (root_hash_bytes, manifest) where manifest maps relative
            paths to ``"sha256:<hexdigest>"``.

        Raises:
            SkillCanonicalizationError: on symlinks, special files, non-UTF-8
                paths, an empty directory, or when the file-count / total-size
                caps are exceeded.
        """
        skill_path = Path(skill_dir)
        if not skill_path.is_dir():
            raise SkillCanonicalizationError(f"not a directory: {skill_dir}")
        skill_path = skill_path.resolve()
        entries: List[Tuple[str, bytes]] = []
        total = 0

        for dirpath, dirnames, filenames in os.walk(skill_path, followlinks=False):
            current = Path(dirpath)
            for d in dirnames:
                if (current / d).is_symlink():
                    raise SkillCanonicalizationError(
                        f"symlink not permitted in skill directory: {current / d}"
                    )
            dirnames.sort()
            for fname in filenames:
                full = current / fname
                if full.is_symlink():
                    raise SkillCanonicalizationError(
                        f"symlink not permitted in skill directory: {full}"
                    )
                if not full.is_file():
                    raise SkillCanonicalizationError(
                        f"non-regular file in skill directory: {full}"
                    )
                if current == skill_path and fname == SIGNATURE_FILENAME:
                    continue
                rel_str = full.relative_to(skill_path).as_posix()
                try:
                    path_bytes = rel_str.encode("utf-8")
                except UnicodeEncodeError as e:
                    raise SkillCanonicalizationError(
                        f"path is not valid UTF-8: {rel_str!r}"
                    ) from e
                data = full.read_bytes()
                total += len(data)
                if len(entries) + 1 > MAX_SKILL_FILES:
                    raise SkillCanonicalizationError(
                        f"skill exceeds {MAX_SKILL_FILES} files"
                    )
                if total > MAX_SKILL_TOTAL_BYTES:
                    raise SkillCanonicalizationError(
                        f"skill exceeds {MAX_SKILL_TOTAL_BYTES} bytes"
                    )
                h = hashlib.sha256()
                h.update(b"f")
                h.update(_be64(len(path_bytes)))
                h.update(path_bytes)
                h.update(_be64(len(data)))
                h.update(data)
                entries.append((rel_str, h.digest()))

        if not entries:
            raise SkillCanonicalizationError(
                f"Skill directory is empty or contains no signable files: {skill_dir}"
            )

        entries.sort(key=lambda e: e[0])
        root = hashlib.sha256()
        manifest: Dict[str, str] = {}
        for rel_str, digest in entries:
            path_bytes = rel_str.encode("utf-8")
            root.update(_be64(len(path_bytes)))
            root.update(path_bytes)
            root.update(digest)
            manifest[rel_str] = f"sha256:{digest.hex()}"
        return root.digest(), manifest

    @staticmethod
    def canonicalize_skill_v1(
        skill_dir: Union[str, Path],
    ) -> Tuple[bytes, Dict[str, str]]:
        """Legacy (``schemapin_version: "1.3"``) skill canonicalization.

        Kept only so that pre-1.4 signatures still verify. Per-file digest is
        ``SHA-256(path || content)``, the root hash is ``SHA-256`` of the
        concatenated hex digests, symlinks are skipped and ``.schemapin.sig``
        is excluded at any depth. Do not use for new signatures.
        """
        skill_path = Path(skill_dir).resolve()
        manifest: Dict[str, str] = {}

        for dirpath, dirnames, filenames in os.walk(skill_path):
            dirnames.sort()
            for fname in sorted(filenames):
                if fname == SIGNATURE_FILENAME:
                    continue
                full = Path(dirpath) / fname
                if full.is_symlink():
                    continue
                rel_str = full.relative_to(skill_path).as_posix()
                file_bytes = full.read_bytes()
                digest = hashlib.sha256(
                    rel_str.encode("utf-8") + file_bytes
                ).hexdigest()
                manifest[rel_str] = f"sha256:{digest}"

        if not manifest:
            raise SkillCanonicalizationError(
                f"Skill directory is empty or contains no signable files: {skill_dir}"
            )

        sorted_digests = [manifest[k].split(":", 1)[1] for k in sorted(manifest)]
        root_hash = hashlib.sha256("".join(sorted_digests).encode("utf-8")).digest()
        return root_hash, manifest

    @staticmethod
    def parse_skill_name(skill_dir: Union[str, Path]) -> str:
        """Extract the skill name from SKILL.md frontmatter.

        Falls back to the directory basename if SKILL.md is missing or
        has no ``name:`` field.
        """
        skill_path = Path(skill_dir)
        skill_md = skill_path / "SKILL.md"
        if skill_md.is_file():
            try:
                text = skill_md.read_text(encoding="utf-8")
                fm_match = re.search(
                    r"^---\s*\n(.*?)\n---", text, re.DOTALL
                )
                if fm_match:
                    frontmatter = fm_match.group(1)
                    name_match = re.search(
                        r"^name:\s*['\"]?([^'\"#\n]+?)['\"]?\s*$",
                        frontmatter,
                        re.MULTILINE,
                    )
                    if name_match:
                        return name_match.group(1).strip()
            except (OSError, UnicodeDecodeError):
                pass
        return skill_path.resolve().name

    @staticmethod
    def load_signature(
        skill_dir: Union[str, Path],
    ) -> Dict[str, Any]:
        """Read and parse the .schemapin.sig file from a skill directory.

        Raises:
            FileNotFoundError: If .schemapin.sig does not exist.
            ValueError: If the file is not a JSON object.
        """
        sig_path = Path(skill_dir) / SIGNATURE_FILENAME
        text = sig_path.read_text(encoding="utf-8")
        data = json.loads(text)
        if not isinstance(data, dict):
            raise ValueError(".schemapin.sig must contain a JSON object")
        return data

    @staticmethod
    def signing_input(signature_data: Dict[str, Any]) -> bytes:
        """Build the canonical bytes a v1.4 signature covers.

        Takes the known signature fields (unknown fields are ignored and
        therefore unprotected), drops absent / empty optional fields, forces
        ``signature`` to ``""`` and canonicalizes with ``schemapin-v1``.

        Raises:
            ValueError: if a required field is missing or has the wrong type.
        """
        doc: Dict[str, Any] = {}
        for key in _REQUIRED_FIELDS:
            if key == "signature":
                continue
            value = signature_data.get(key)
            if key == "file_manifest":
                if not isinstance(value, dict):
                    raise ValueError("file_manifest must be an object")
            elif not isinstance(value, str):
                raise ValueError(f"signature document field {key!r} is missing")
            doc[key] = value
        for key in _OPTIONAL_FIELDS:
            value = signature_data.get(key)
            if value is None or value == "":
                continue
            if not isinstance(value, str):
                raise ValueError(f"signature document field {key!r} must be a string")
            doc[key] = value
        doc["signature"] = ""
        return SchemaPinCore.canonicalize_schema(doc).encode("utf-8")

    @staticmethod
    def sign_skill(
        skill_dir: Union[str, Path],
        private_key_pem: str,
        domain: str,
        signer_kid: Optional[str] = None,
        skill_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Canonicalize a skill directory, sign, and write .schemapin.sig.

        Convenience wrapper over :meth:`sign_with_options`.

        Args:
            skill_dir: Path to the skill folder.
            private_key_pem: PEM-encoded ECDSA P-256 private key.
            domain: Signing domain (e.g. "thirdkey.ai").
            signer_kid: Optional key ID (fingerprint). Auto-computed if None.
            skill_name: Override for the skill name. Parsed from SKILL.md
                if not provided.

        Returns:
            The signature document dict that was written.
        """
        return SkillSigner.sign_with_options(
            skill_dir,
            private_key_pem,
            domain,
            SignOptions(signer_kid=signer_kid, skill_name=skill_name),
        )

    @staticmethod
    def sign_with_options(
        skill_dir: Union[str, Path],
        private_key_pem: str,
        domain: str,
        options: SignOptions,
    ) -> Dict[str, Any]:
        """Sign a skill directory and write a v1.4 signature document.

        The whole document (including ``expires_at`` when
        ``options.expires_in`` is set, written as RFC 3339 ``Z`` with second
        precision) is covered by the signature. See the module docstring.

        Raises:
            InvalidDomainError: if ``domain`` is not a valid hostname.
            SkillCanonicalizationError: if the directory cannot be hashed.
        """
        skill_path = Path(skill_dir)
        domain = validate_domain(domain)
        private_key = KeyManager.load_private_key_pem(private_key_pem)
        public_key = private_key.public_key()

        root_hash, manifest = SkillSigner.canonicalize_skill(skill_path)

        skill_name = options.skill_name
        if skill_name is None:
            skill_name = SkillSigner.parse_skill_name(skill_path)

        signer_kid = options.signer_kid
        if signer_kid is None:
            signer_kid = KeyManager.calculate_key_fingerprint(public_key)

        now = datetime.now(timezone.utc)
        signed_at = _format_rfc3339(now)
        expires_at: Optional[str] = None
        if options.expires_in is not None:
            expires_at = _format_rfc3339(now + options.expires_in)

        sig_doc: Dict[str, Any] = {
            "schemapin_version": SCHEMAPIN_VERSION,
            "skill_name": skill_name,
            "skill_hash": f"sha256:{root_hash.hex()}",
            "signature": "",
            "signed_at": signed_at,
        }
        if expires_at is not None:
            sig_doc["expires_at"] = expires_at
        if options.schema_version is not None:
            sig_doc["schema_version"] = options.schema_version
        if options.previous_hash is not None:
            sig_doc["previous_hash"] = options.previous_hash
        if options.canonicalization is not None:
            sig_doc["canonicalization"] = options.canonicalization
        sig_doc["domain"] = domain
        sig_doc["signer_kid"] = signer_kid
        sig_doc["file_manifest"] = manifest

        sig_doc["signature"] = SignatureManager.sign_hash(
            SkillSigner.signing_input(sig_doc), private_key
        )

        sig_path = skill_path / SIGNATURE_FILENAME
        sig_path.write_text(
            json.dumps(sig_doc, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )
        return sig_doc

    @staticmethod
    def verify_skill_offline(
        skill_dir: Union[str, Path],
        discovery: Dict[str, Any],
        signature_data: Optional[Dict[str, Any]] = None,
        revocation_doc: Optional[RevocationDocument] = None,
        pin_store: Optional[KeyPinStore] = None,
        tool_id: Optional[str] = None,
        domain: Optional[str] = None,
        allow_expired: bool = False,
    ) -> VerificationResult:
        """Verify a signed skill folder offline.

        Steps:
          1. Load or accept signature data; check ``canonicalization``
          2. Bind the domain: when ``domain`` is given it must equal the
             signature's ``domain`` (``DOMAIN_MISMATCH`` otherwise). Pass it
             whenever you know which domain the discovery document belongs
             to -- the signature's own ``domain`` field is display-only.
          3. Validate discovery document, load key, compute fingerprint
          4. Check revocation
          5. TOFU pin check (read-only)
          6. Recompute the root hash, require ``skill_hash`` to match, and
             verify the signature (over the whole document for 1.4, over the
             root hash for legacy 1.3)
          7. Expiration check (fail-closed unless ``allow_expired``)
          8. Pin on first use, return the result with lineage metadata
        """
        skill_path = Path(skill_dir)

        # Step 1: Load signature data
        if signature_data is None:
            try:
                signature_data = SkillSigner.load_signature(skill_path)
            except (FileNotFoundError, ValueError) as e:
                return VerificationResult(
                    valid=False,
                    error_code=ErrorCode.SIGNATURE_INVALID,
                    error_message=f"No usable .schemapin.sig found in skill directory: {e}",
                )

        sig_domain = signature_data.get("domain")
        if tool_id is None:
            tool_id = signature_data.get("skill_name") or skill_path.name

        unsupported = check_canonicalization(signature_data.get("canonicalization"))
        if unsupported is not None:
            return VerificationResult(
                valid=False,
                domain=domain,
                error_code=ErrorCode.CANONICALIZATION_UNSUPPORTED,
                error_message=f"Unsupported canonicalization algorithm: {unsupported}",
            )

        # Step 2: Domain binding
        warnings: List[str] = []
        if domain is not None:
            try:
                domain = validate_domain(domain)
            except InvalidDomainError as e:
                return VerificationResult(
                    valid=False,
                    domain=domain,
                    error_code=ErrorCode.DOMAIN_INVALID,
                    error_message=str(e),
                )
            if not isinstance(sig_domain, str) or sig_domain.lower() != domain:
                return VerificationResult(
                    valid=False,
                    domain=domain,
                    error_code=ErrorCode.DOMAIN_MISMATCH,
                    error_message=(
                        f"signature domain {sig_domain!r} does not match expected domain {domain!r}"
                    ),
                )
        else:
            try:
                domain = validate_domain(sig_domain if isinstance(sig_domain, str) else "")
            except InvalidDomainError as e:
                return VerificationResult(
                    valid=False,
                    error_code=ErrorCode.DOMAIN_INVALID,
                    error_message=f"signature domain is invalid: {e}",
                )
            warnings.append("domain_unbound")

        # Step 3: Validate discovery document
        public_key_pem = discovery.get("public_key_pem")
        if (
            not public_key_pem
            or "-----BEGIN PUBLIC KEY-----" not in public_key_pem
        ):
            return VerificationResult(
                valid=False,
                domain=domain,
                error_code=ErrorCode.DISCOVERY_INVALID,
                error_message="Discovery document missing or invalid public_key_pem",
            )

        try:
            public_key = KeyManager.load_public_key_pem(public_key_pem)
            fingerprint = KeyManager.calculate_key_fingerprint(public_key)
        except Exception as e:
            return VerificationResult(
                valid=False,
                domain=domain,
                error_code=ErrorCode.KEY_NOT_FOUND,
                error_message=f"Failed to load public key: {e}",
            )

        # Step 4: Check revocation
        simple_revoked: List[str] = discovery.get("revoked_keys", [])
        try:
            check_revocation_combined(simple_revoked, revocation_doc, fingerprint)
        except ValueError as e:
            return VerificationResult(
                valid=False,
                domain=domain,
                error_code=ErrorCode.KEY_REVOKED,
                error_message=str(e),
            )

        # Step 5: TOFU pin check (read-only until the signature verifies)
        pin_result: Optional[str] = None
        if pin_store is not None:
            pin_result = pin_store.check(tool_id, domain, fingerprint)
            if pin_result == "changed":
                return VerificationResult(
                    valid=False,
                    domain=domain,
                    error_code=ErrorCode.KEY_PIN_MISMATCH,
                    error_message="Key fingerprint changed since last use",
                )

        # Step 6: Canonicalize and verify
        version = signature_data.get("schemapin_version")
        if _version_tuple(version) is None:
            return VerificationResult(
                valid=False,
                domain=domain,
                error_code=ErrorCode.SIGNATURE_INVALID,
                error_message=f"unsupported schemapin_version {version!r}",
            )
        legacy = _is_legacy_version(version)
        try:
            if legacy:
                root_hash, _manifest = SkillSigner.canonicalize_skill_v1(skill_path)
            else:
                root_hash, _manifest = SkillSigner.canonicalize_skill(skill_path)
        except Exception as e:
            return VerificationResult(
                valid=False,
                domain=domain,
                error_code=ErrorCode.SCHEMA_CANONICALIZATION_FAILED,
                error_message=f"Failed to canonicalize skill: {e}",
            )

        signature_b64 = signature_data.get("signature", "")
        if legacy:
            valid = SignatureManager.verify_signature(root_hash, signature_b64, public_key)
            warnings.append("legacy_signature_format")
        else:
            expected_hash = f"sha256:{root_hash.hex()}"
            if signature_data.get("skill_hash") != expected_hash:
                return VerificationResult(
                    valid=False,
                    domain=domain,
                    error_code=ErrorCode.SIGNATURE_INVALID,
                    error_message="skill_hash does not match the directory contents",
                )
            try:
                signing_input = SkillSigner.signing_input(signature_data)
            except ValueError as e:
                return VerificationResult(
                    valid=False,
                    domain=domain,
                    error_code=ErrorCode.SIGNATURE_INVALID,
                    error_message=f"malformed signature document: {e}",
                )
            valid = SignatureManager.verify_signature(signing_input, signature_b64, public_key)

        if not valid:
            return VerificationResult(
                valid=False,
                domain=domain,
                error_code=ErrorCode.SIGNATURE_INVALID,
                error_message="Signature verification failed",
            )

        # Step 7: Expiration (fail-closed by default)
        result = VerificationResult(
            valid=True,
            domain=domain,
            developer_name=discovery.get("developer_name"),
            warnings=warnings,
        )
        result = result.with_expiration_check(
            signature_data.get("expires_at"),
            allow_expired=allow_expired,
            skew_seconds=EXPIRATION_SKEW_SECONDS,
        )
        if not result.valid:
            return result

        # Step 8: Pin only now, then surface lineage metadata
        if pin_store is not None and pin_result == "first_use":
            pin_store.pin(tool_id, domain, fingerprint)
        if pin_result is not None:
            result.key_pinning = KeyPinningStatus(status=pin_result)
        return result.with_lineage_metadata(
            signature_data.get("schema_version"),
            signature_data.get("previous_hash"),
        )

    @staticmethod
    def verify_skill_offline_with_dns(
        skill_dir: Union[str, Path],
        discovery: Dict[str, Any],
        signature_data: Optional[Dict[str, Any]] = None,
        revocation_doc: Optional[RevocationDocument] = None,
        pin_store: Optional[KeyPinStore] = None,
        tool_id: Optional[str] = None,
        dns_txt: Optional[DnsTxtRecord] = None,
        domain: Optional[str] = None,
        allow_expired: bool = False,
    ) -> VerificationResult:
        """Offline verify with an additional DNS TXT cross-check (v1.4).

        Behaves identically to :meth:`verify_skill_offline`, with a DNS TXT
        fingerprint cross-check performed first when ``dns_txt`` is given. A
        mismatch is a hard :attr:`ErrorCode.DOMAIN_MISMATCH` failure and
        nothing is pinned.
        """
        if dns_txt is not None:
            try:
                verify_dns_match(discovery, dns_txt)
            except ValueError as e:
                return VerificationResult(
                    valid=False,
                    domain=domain,
                    error_code=ErrorCode.DOMAIN_MISMATCH,
                    error_message=str(e),
                )
        return SkillSigner.verify_skill_offline(
            skill_dir,
            discovery,
            signature_data=signature_data,
            revocation_doc=revocation_doc,
            pin_store=pin_store,
            tool_id=tool_id,
            domain=domain,
            allow_expired=allow_expired,
        )

    @staticmethod
    def verify_skill_with_resolver(
        skill_dir: Union[str, Path],
        domain: str,
        resolver: Optional[SchemaResolver] = None,
        pin_store: Optional[KeyPinStore] = None,
        tool_id: Optional[str] = None,
        allow_expired: bool = False,
        allow_unreachable_revocation: bool = False,
    ) -> VerificationResult:
        """Verify a signed skill folder using a resolver for discovery.

        The signature's ``domain`` must equal ``domain`` (checked before any
        network I/O); the discovery document is fetched for ``domain`` and
        the pin is keyed by it.

        Args:
            skill_dir: Path to the skill folder.
            domain: Domain to resolve discovery for and bind the skill to.
            resolver: SchemaResolver instance. If None, uses WellKnownResolver.
            pin_store: Optional TOFU pin store.
            tool_id: Optional tool identifier for pinning.
            allow_expired: Accept expired signatures (degraded) instead of
                failing with ``SIGNATURE_EXPIRED``.
            allow_unreachable_revocation: Treat a revocation fetch failure
                as "no revocations" instead of failing closed.

        Returns:
            VerificationResult.
        """
        from .revocation import RevocationFetchError

        try:
            domain = validate_domain(domain)
        except InvalidDomainError as e:
            return VerificationResult(
                valid=False,
                domain=domain,
                error_code=ErrorCode.DOMAIN_INVALID,
                error_message=str(e),
            )

        try:
            signature_data = SkillSigner.load_signature(skill_dir)
        except (FileNotFoundError, ValueError) as e:
            return VerificationResult(
                valid=False,
                domain=domain,
                error_code=ErrorCode.SIGNATURE_INVALID,
                error_message=f"No usable .schemapin.sig found in skill directory: {e}",
            )
        sig_domain = signature_data.get("domain")
        if not isinstance(sig_domain, str) or sig_domain.lower() != domain:
            return VerificationResult(
                valid=False,
                domain=domain,
                error_code=ErrorCode.DOMAIN_MISMATCH,
                error_message=(
                    f"signature domain {sig_domain!r} does not match expected domain {domain!r}"
                ),
            )

        if resolver is None:
            from .resolver import WellKnownResolver

            resolver = WellKnownResolver()

        discovery = resolver.resolve_discovery(domain)
        if discovery is None:
            return VerificationResult(
                valid=False,
                domain=domain,
                error_code=ErrorCode.DISCOVERY_FETCH_FAILED,
                error_message=f"Could not resolve discovery for domain: {domain}",
            )

        try:
            revocation = resolver.resolve_revocation(domain, discovery)
        except RevocationFetchError as e:
            if not allow_unreachable_revocation:
                return VerificationResult(
                    valid=False,
                    domain=domain,
                    error_code=ErrorCode.DISCOVERY_FETCH_FAILED,
                    error_message=f"Revocation document unreachable (fail-closed): {e}",
                )
            revocation = None

        return SkillSigner.verify_skill_offline(
            skill_dir,
            discovery,
            signature_data=signature_data,
            revocation_doc=revocation,
            pin_store=pin_store,
            tool_id=tool_id,
            domain=domain,
            allow_expired=allow_expired,
        )

    @staticmethod
    def detect_tampered_files(
        current_manifest: Dict[str, str],
        signed_manifest: Dict[str, str],
    ) -> Dict[str, List[str]]:
        """Compare current file manifest against the signed manifest.

        Only meaningful for ``schemapin_version >= "1.4"`` documents, whose
        ``file_manifest`` is covered by the signature; for legacy 1.3 documents
        the manifest is unsigned and this is a diagnostic aid only.

        Returns:
            Dict with keys "modified", "added", "removed" -- each a list of
            relative file paths.
        """
        current_keys = set(current_manifest)
        signed_keys = set(signed_manifest)

        added = sorted(current_keys - signed_keys)
        removed = sorted(signed_keys - current_keys)
        modified = sorted(
            k
            for k in current_keys & signed_keys
            if current_manifest[k] != signed_manifest[k]
        )

        return {"modified": modified, "added": added, "removed": removed}


def _format_rfc3339(ts: datetime) -> str:
    """Format ``ts`` as RFC 3339 with ``Z`` suffix and second precision.

    Mirrors the Rust ``to_rfc3339_opts(SecondsFormat::Secs, true)`` output
    used by the reference implementation so cross-language round-trips
    produce identical strings.
    """
    if ts.tzinfo is None:
        raise ValueError("RFC 3339 formatting requires a timezone-aware datetime")
    utc_ts = ts.astimezone(timezone.utc).replace(microsecond=0)
    # ``isoformat`` would emit ``+00:00``; the spec mandates ``Z``.
    return utc_ts.strftime("%Y-%m-%dT%H:%M:%SZ")


class ChainError(ValueError):
    """Raised by :func:`verify_chain` when the lineage check fails.

    Subclass of :class:`ValueError` so callers can ``except ValueError`` if they
    don't care about distinguishing chain failures from generic validation.
    """


def verify_chain(current: Dict[str, Any], previous: Dict[str, Any]) -> None:
    """Verify ``current`` is the legitimate successor of ``previous``.

    Checks ``current["previous_hash"] == previous["skill_hash"]``.

    This is a pure-metadata check -- no cryptography is re-evaluated. Both
    signatures must already be cryptographically verified separately via
    :meth:`SkillSigner.verify_skill_offline` for the chain check to be
    meaningful, and both must be ``schemapin_version >= "1.4"`` documents so
    that ``skill_hash`` and ``previous_hash`` are actually covered by their
    signatures (legacy 1.3 documents are rejected).

    Raises:
        ChainError: If ``current`` has no ``previous_hash`` field, if it
            does not match ``previous["skill_hash"]``, or if either document
            is a legacy 1.3 signature.
    """
    for label, doc in (("current", current), ("previous", previous)):
        if _is_legacy_version(doc.get("schemapin_version")):
            raise ChainError(
                f"{label} signature is a legacy 1.3 document; its skill_hash is unsigned"
            )
    claimed = current.get("previous_hash")
    if claimed is None:
        raise ChainError("current signature has no previous_hash field")
    expected = previous.get("skill_hash")
    if claimed != expected:
        raise ChainError(
            f"previous_hash mismatch: current.previous_hash = {claimed}, "
            f"previous.skill_hash = {expected}"
        )
