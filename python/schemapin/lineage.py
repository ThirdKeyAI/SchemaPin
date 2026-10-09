"""Verifier-side lineage store for schema-version binding (spec section 18.4).

:func:`schemapin.skill.verify_chain` compares two signature documents the
caller already holds. A verifier that wants protection against rollback and
forks needs to remember the *latest accepted* ``skill_hash`` for each tool
and insist that every new signature descends from it. :class:`LineageStore`
is that memory.

Only feed it signature documents that :meth:`SkillSigner.verify_skill_offline`
has already accepted, and only ``schemapin_version >= "1.4"`` documents:
their ``skill_hash``, ``previous_hash`` and ``schema_version`` are covered by
the signature, which is what makes the chain meaningful. Legacy 1.3 documents
are refused.
"""

import json
import re
from dataclasses import asdict, dataclass
from typing import Any, Dict, Optional, Tuple

from .skill import _is_legacy_version


class LineageError(ValueError):
    """Raised when a signature does not descend from the recorded lineage."""


@dataclass
class LineageRecord:
    """Latest accepted lineage state for a ``tool_id@domain``."""

    skill_hash: str
    schema_version: Optional[str] = None


_SEMVER_RE = re.compile(r"^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?")


def _version_key(version: str) -> Optional[Tuple[int, int, int]]:
    m = _SEMVER_RE.match(version)
    if m is None:
        return None
    return tuple(int(g or 0) for g in m.groups())  # type: ignore[return-value]


def version_increases(previous: str, current: str) -> bool:
    """Return ``True`` when ``current`` sorts strictly after ``previous``.

    Numeric ``major.minor.patch`` prefixes compare numerically (``1.10.0`` >
    ``1.9.0``); when either side is not semver-like the comparison falls back
    to a plain string comparison, which still rejects reuse of the same value.
    """
    p, c = _version_key(previous), _version_key(current)
    if p is not None and c is not None and p != c:
        return c > p
    return current > previous


class LineageStore:
    """In-memory ``latest_known_hash`` store keyed by ``tool_id@domain``."""

    def __init__(self) -> None:
        self._latest: Dict[str, LineageRecord] = {}

    @staticmethod
    def _key(tool_id: str, domain: str) -> str:
        return f"{tool_id}@{domain}"

    def get(self, tool_id: str, domain: str) -> Optional[LineageRecord]:
        """Return the latest accepted record, or ``None``."""
        return self._latest.get(self._key(tool_id, domain))

    def seed(
        self,
        tool_id: str,
        domain: str,
        skill_hash: str,
        schema_version: Optional[str] = None,
    ) -> None:
        """Pre-seed the latest accepted state (for example from a trusted manifest)."""
        self._latest[self._key(tool_id, domain)] = LineageRecord(skill_hash, schema_version)

    def check_and_advance(
        self,
        tool_id: str,
        domain: str,
        signature_data: Dict[str, Any],
        require_chain: bool = True,
    ) -> str:
        """Check ``signature_data`` against the lineage and advance on success.

        Returns:
            ``"first_use"`` when nothing was recorded yet (the document is
            recorded as the lineage head), ``"unchanged"`` when the document's
            ``skill_hash`` is already the head, or ``"advanced"`` when the
            document is a valid successor and becomes the new head.

        Raises:
            LineageError: for legacy 1.3 documents, a missing ``previous_hash``
                (when ``require_chain``), a ``previous_hash`` that is not the
                current head (fork / rollback), or a ``schema_version`` that
                does not increase.
        """
        version = signature_data.get("schemapin_version")
        if _is_legacy_version(version):
            raise LineageError(
                "legacy 1.3 signature documents carry an unsigned skill_hash and cannot anchor a lineage"
            )
        skill_hash = signature_data.get("skill_hash")
        if not isinstance(skill_hash, str) or not skill_hash:
            raise LineageError("signature document has no skill_hash")
        schema_version = signature_data.get("schema_version")

        key = self._key(tool_id, domain)
        record = self._latest.get(key)
        if record is None:
            self._latest[key] = LineageRecord(skill_hash, schema_version)
            return "first_use"
        if record.skill_hash == skill_hash:
            return "unchanged"

        previous_hash = signature_data.get("previous_hash")
        if previous_hash is None:
            if require_chain:
                raise LineageError(
                    f"signature for {key} has no previous_hash; expected a descendant of {record.skill_hash}"
                )
        elif previous_hash != record.skill_hash:
            raise LineageError(
                f"previous_hash {previous_hash} does not match the latest accepted "
                f"skill_hash {record.skill_hash} for {key} (fork or rollback)"
            )
        if (
            isinstance(schema_version, str)
            and record.schema_version is not None
            and not version_increases(record.schema_version, schema_version)
        ):
            raise LineageError(
                f"schema_version {schema_version!r} does not increase over "
                f"{record.schema_version!r} for {key}"
            )

        self._latest[key] = LineageRecord(skill_hash, schema_version)
        return "advanced"

    def to_json(self) -> str:
        """Serialize the store to JSON."""
        return json.dumps({k: asdict(v) for k, v in self._latest.items()}, sort_keys=True)

    @classmethod
    def from_json(cls, json_str: str) -> "LineageStore":
        """Deserialize a store from JSON."""
        store = cls()
        data = json.loads(json_str)
        if not isinstance(data, dict):
            raise ValueError("lineage store JSON must be an object")
        for key, value in data.items():
            if not isinstance(value, dict) or not isinstance(value.get("skill_hash"), str):
                raise ValueError("lineage store entries must carry a skill_hash")
            store._latest[key] = LineageRecord(value["skill_hash"], value.get("schema_version"))
        return store
