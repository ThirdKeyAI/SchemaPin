"""Skill folder signing and verification for SchemaPin v1.3 / v1.4.

Extends SchemaPin's ECDSA P-256 signing to cover file-based skill folders
(AgentSkills spec). Same keys, same .well-known discovery, new canonicalization
target.

v1.4 additions (additive, backward-compatible with v1.3 verifiers):

- Optional ``expires_at`` field on the ``.schemapin.sig`` document. When set,
  the signature uses ``schemapin_version: "1.4"`` and verifiers degrade
  (warn) past expiration rather than failing.
- Optional DNS TXT cross-verification via
  :func:`SkillSigner.verify_skill_offline_with_dns`.
"""

import hashlib
import json
import os
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from .crypto import KeyManager, SignatureManager
from .dns import DnsTxtRecord, verify_dns_match
from .resolver import SchemaResolver
from .revocation import RevocationDocument, check_revocation_combined
from .verification import (
    ErrorCode,
    KeyPinningStatus,
    KeyPinStore,
    VerificationResult,
)

SIGNATURE_FILENAME = ".schemapin.sig"
# Default ``schemapin_version`` written when no v1.4 features are used.
SCHEMAPIN_VERSION = "1.3"
# Version written when a v1.4 feature (e.g. expires_at) is present.
SCHEMAPIN_VERSION_V1_4 = "1.4"


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
    # v1.4 alpha.2: caller-supplied semver string identifying *this* version of
    # the signed artifact. Surfaced via VerificationResult for policy use.
    schema_version: Optional[str] = None
    # v1.4 alpha.2: ``sha256:<hex>`` of the prior signed version's
    # ``skill_hash``, forming a hash chain. Pair with :func:`verify_chain`.
    previous_hash: Optional[str] = None


class SkillSigner:
    """Sign and verify file-based skill folders using ECDSA P-256.

    Mirrors the SchemaPinCore pattern — static/classmethod only.
    """

    @staticmethod
    def canonicalize_skill(
        skill_dir: Union[str, Path],
    ) -> Tuple[bytes, Dict[str, str]]:
        """Walk a skill directory deterministically and compute a root hash.

        Algorithm:
          1. os.walk() with sorted dirnames for deterministic order
          2. Skip .schemapin.sig and symlinks
          3. Normalize paths to forward slashes
          4. Per-file: sha256(rel_path_utf8 + file_bytes).hexdigest()
          5. Root: sha256(concat of all hexdigests, sorted by rel_path).digest()

        Returns:
            Tuple of (root_hash_bytes, manifest) where manifest maps
            relative paths to "sha256:<hexdigest>".

        Raises:
            ValueError: If the directory is empty (no files after filtering).
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
                rel = full.relative_to(skill_path)
                # Normalize to forward slashes
                rel_str = rel.as_posix()
                file_bytes = full.read_bytes()
                digest = hashlib.sha256(
                    rel_str.encode("utf-8") + file_bytes
                ).hexdigest()
                manifest[rel_str] = f"sha256:{digest}"

        if not manifest:
            raise ValueError(
                f"Skill directory is empty or contains no signable files: {skill_dir}"
            )

        # Root hash: sorted by rel_path, concat hex digests
        sorted_digests = [
            manifest[k].split(":", 1)[1] for k in sorted(manifest)
        ]
        root_hash = hashlib.sha256(
            "".join(sorted_digests).encode("utf-8")
        ).digest()
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
            except OSError:
                pass
        return skill_path.resolve().name

    @staticmethod
    def load_signature(
        skill_dir: Union[str, Path],
    ) -> Dict[str, Any]:
        """Read and parse the .schemapin.sig file from a skill directory.

        Raises:
            FileNotFoundError: If .schemapin.sig does not exist.
        """
        sig_path = Path(skill_dir) / SIGNATURE_FILENAME
        text = sig_path.read_text(encoding="utf-8")
        return json.loads(text)

    @staticmethod
    def sign_skill(
        skill_dir: Union[str, Path],
        private_key_pem: str,
        domain: str,
        signer_kid: Optional[str] = None,
        skill_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Canonicalize a skill directory, sign, and write .schemapin.sig.

        Backward-compatible v1.3 entry point. For v1.4 features (signature
        expiration), use :meth:`sign_with_options`.

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
        """Sign a skill directory with extended v1.4 options.

        When ``options.expires_in`` is set, an ``expires_at`` ISO 8601
        timestamp (RFC 3339, ``Z`` suffix, second precision) is written and
        ``schemapin_version`` becomes ``"1.4"``. Otherwise the document is
        identical to :meth:`sign_skill` output (v1.3 wire format).

        Verifiers past ``expires_at`` emit a ``signature_expired`` warning
        but do **not** mark the result invalid -- expiration is a
        confidence/policy signal, not a hard failure.
        """
        skill_path = Path(skill_dir)
        private_key = KeyManager.load_private_key_pem(private_key_pem)
        public_key = private_key.public_key()

        root_hash, manifest = SkillSigner.canonicalize_skill(skill_path)

        skill_name = options.skill_name
        if skill_name is None:
            skill_name = SkillSigner.parse_skill_name(skill_path)

        signer_kid = options.signer_kid
        if signer_kid is None:
            signer_kid = KeyManager.calculate_key_fingerprint(public_key)

        signature_b64 = SignatureManager.sign_hash(root_hash, private_key)

        now = datetime.now(timezone.utc)
        signed_at = _format_rfc3339(now)
        expires_at: Optional[str] = None
        if options.expires_in is not None:
            expires_at = _format_rfc3339(now + options.expires_in)

        uses_v1_4_field = (
            expires_at is not None
            or options.schema_version is not None
            or options.previous_hash is not None
        )
        version = SCHEMAPIN_VERSION_V1_4 if uses_v1_4_field else SCHEMAPIN_VERSION

        sig_doc: Dict[str, Any] = {
            "schemapin_version": version,
            "skill_name": skill_name,
            "skill_hash": f"sha256:{root_hash.hex()}",
            "signature": signature_b64,
            "signed_at": signed_at,
            "domain": domain,
            "signer_kid": signer_kid,
            "file_manifest": manifest,
        }
        # Only emit v1.4 optional fields when set, so v1.3 verifiers see an
        # unchanged document on the wire.
        if expires_at is not None:
            sig_doc["expires_at"] = expires_at
        if options.schema_version is not None:
            sig_doc["schema_version"] = options.schema_version
        if options.previous_hash is not None:
            sig_doc["previous_hash"] = options.previous_hash

        sig_path = skill_path / SIGNATURE_FILENAME
        sig_path.write_text(
            json.dumps(sig_doc, indent=2) + "\n", encoding="utf-8"
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
    ) -> VerificationResult:
        """Verify a signed skill folder offline (7-step flow).

        Mirrors verify_schema_offline():
          1. Load or accept signature data
          2. Validate discovery document
          3. Extract public key and compute fingerprint
          4. Check revocation
          5. TOFU key pinning
          6. Canonicalize skill and verify ECDSA signature
          7. Return structured result
        """
        skill_path = Path(skill_dir)

        # Step 1: Load signature data
        if signature_data is None:
            try:
                signature_data = SkillSigner.load_signature(skill_path)
            except FileNotFoundError:
                return VerificationResult(
                    valid=False,
                    error_code=ErrorCode.SIGNATURE_INVALID,
                    error_message="No .schemapin.sig found in skill directory",
                )

        domain = signature_data.get("domain", "")
        if tool_id is None:
            tool_id = signature_data.get("skill_name", skill_path.name)

        # Step 2: Validate discovery document
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

        # Step 3: Extract public key and compute fingerprint
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
            check_revocation_combined(
                simple_revoked, revocation_doc, fingerprint
            )
        except ValueError as e:
            return VerificationResult(
                valid=False,
                domain=domain,
                error_code=ErrorCode.KEY_REVOKED,
                error_message=str(e),
            )

        # Step 5: TOFU key pinning
        pinning_status: Optional[KeyPinningStatus] = None
        if pin_store is not None:
            pin_result = pin_store.check_and_pin(tool_id, domain, fingerprint)
            if pin_result == "changed":
                return VerificationResult(
                    valid=False,
                    domain=domain,
                    error_code=ErrorCode.KEY_PIN_MISMATCH,
                    error_message="Key fingerprint changed since last use",
                )
            pinning_status = KeyPinningStatus(status=pin_result)

        # Step 6: Canonicalize and verify signature
        try:
            root_hash, _manifest = SkillSigner.canonicalize_skill(skill_path)
        except Exception as e:
            return VerificationResult(
                valid=False,
                domain=domain,
                error_code=ErrorCode.SCHEMA_CANONICALIZATION_FAILED,
                error_message=f"Failed to canonicalize skill: {e}",
            )

        signature_b64 = signature_data.get("signature", "")
        valid = SignatureManager.verify_signature(
            root_hash, signature_b64, public_key
        )

        if not valid:
            return VerificationResult(
                valid=False,
                domain=domain,
                error_code=ErrorCode.SIGNATURE_INVALID,
                error_message="Signature verification failed",
            )

        # Step 7: Return success, applying optional v1.4 expiration check
        # and surfacing lineage metadata (schema_version + previous_hash).
        developer_name = discovery.get("developer_name")
        result = VerificationResult(
            valid=True,
            domain=domain,
            developer_name=developer_name,
            key_pinning=pinning_status,
        )
        result = result.with_expiration_check(signature_data.get("expires_at"))
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
    ) -> VerificationResult:
        """Offline verify with an additional DNS TXT cross-check (v1.4).

        Behaves identically to :meth:`verify_skill_offline`, then -- when
        ``dns_txt`` is not ``None`` -- verifies that the DNS TXT record's
        fingerprint matches the discovery key. A mismatch converts the
        result into a hard failure with
        :attr:`ErrorCode.DOMAIN_MISMATCH`. When ``dns_txt`` is ``None``,
        behaviour is unchanged (DNS TXT is an optional, additive trust
        signal).
        """
        result = SkillSigner.verify_skill_offline(
            skill_dir,
            discovery,
            signature_data=signature_data,
            revocation_doc=revocation_doc,
            pin_store=pin_store,
            tool_id=tool_id,
        )
        if not result.valid or dns_txt is None:
            return result
        try:
            verify_dns_match(discovery, dns_txt)
        except ValueError as e:
            return VerificationResult(
                valid=False,
                domain=result.domain,
                error_code=ErrorCode.DOMAIN_MISMATCH,
                error_message=str(e),
            )
        return result

    @staticmethod
    def verify_skill_with_resolver(
        skill_dir: Union[str, Path],
        domain: str,
        resolver: Optional[SchemaResolver] = None,
        pin_store: Optional[KeyPinStore] = None,
        tool_id: Optional[str] = None,
    ) -> VerificationResult:
        """Verify a signed skill folder using a resolver for discovery.

        Args:
            skill_dir: Path to the skill folder.
            domain: Domain to resolve discovery for.
            resolver: SchemaResolver instance. If None, uses WellKnownResolver.
            pin_store: Optional TOFU pin store.
            tool_id: Optional tool identifier for pinning.

        Returns:
            VerificationResult.
        """
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

        revocation = resolver.resolve_revocation(domain, discovery)

        return SkillSigner.verify_skill_offline(
            skill_dir,
            discovery,
            revocation_doc=revocation,
            pin_store=pin_store,
            tool_id=tool_id,
        )

    @staticmethod
    def detect_tampered_files(
        current_manifest: Dict[str, str],
        signed_manifest: Dict[str, str],
    ) -> Dict[str, List[str]]:
        """Compare current file manifest against the signed manifest.

        Returns:
            Dict with keys "modified", "added", "removed" — each a list of
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
    """Verify ``current`` is the legitimate successor of ``previous`` (v1.4 alpha.2).

    Checks ``current["previous_hash"] == previous["skill_hash"]``.

    This is a pure-metadata check -- no cryptography is re-evaluated. Both
    signatures must already be cryptographically verified separately via
    :meth:`SkillSigner.verify_skill_offline` for the chain check to be
    meaningful.

    Use this to defend against rug-pull attacks where an attacker substitutes
    a schema/skill out-of-band: a legitimate update declares the prior
    version's hash; an unauthorized substitution either omits ``previous_hash``
    or points at a hash the verifier has not accepted as a valid ancestor.

    Args:
        current: The new signature dict (must have ``previous_hash`` set).
        previous: The prior signature dict (must have ``skill_hash`` set).

    Raises:
        ChainError: If ``current`` has no ``previous_hash`` field, or if it
            does not match ``previous["skill_hash"]``.
    """
    claimed = current.get("previous_hash")
    if claimed is None:
        raise ChainError("current signature has no previous_hash field")
    expected = previous.get("skill_hash")
    if claimed != expected:
        raise ChainError(
            f"previous_hash mismatch: current.previous_hash = {claimed}, "
            f"previous.skill_hash = {expected}"
        )
