"""A2A verification context for SchemaPin (v1.4 alpha.3).

Mirrors the Rust ``schemapin::types::a2a`` module and the AgentPin v0.3
``AllowedDomains`` semantics (AgentPin technical specification §4.11).

When a SchemaPin verification crosses an A2A (Agent-to-Agent) trust boundary,
the verifier needs to scope the result to the intersection of *caller-trusted*
domains and the *tool provider's* domain. ``A2aVerificationContext`` carries
that scoping data; pair it with :func:`schemapin.verification.verify_schema_for_a2a`.

AllowedDomains convention
-------------------------

The allow-list semantics follow AgentPin v0.3 exactly:

    An empty ``trusted_domains`` list means *unrestricted* — all domains
    trusted. This is the opposite of the naïve set-theoretic interpretation
    (where an empty set allows nothing) but it matches the existing v1.3
    behaviour where an *omitted* ``allowed_domains`` field allowed all
    domains.

SchemaPin defines these helpers locally rather than depending on the
``agentpin`` Python package — keeping SchemaPin self-contained for users
who only consume tool-integrity, and avoiding a circular trust-stack
dependency. Callers who *do* install both packages can pass the result of
``agentpin.AllowedDomains.intersect(...)`` directly into
``A2aVerificationContext(trusted_domains=...)`` — the wire and in-memory
shapes are identical.
"""

from dataclasses import dataclass, field
from typing import Iterable, List, Optional


@dataclass
class A2aVerificationContext:
    """Scope a schema verification to an A2A interaction.

    Pair with :func:`schemapin.verification.verify_schema_for_a2a` to run
    the standard 7-step verification flow with the additional A2A scope
    check.
    """

    #: Caller's agent identity (URN-style, matching AgentPin). Informational
    #: only — SchemaPin does not validate the URN shape.
    caller_agent_id: str

    #: Depth in the A2A delegation chain. ``0`` = direct caller.
    #: Verifiers SHOULD reject ``delegation_depth > 3`` to match the AgentPin
    #: ``max_delegation_depth`` cap (AgentPin spec §4.3).
    delegation_depth: int = 0

    #: Originating domain of the A2A request. Informational; the scope check
    #: uses ``trusted_domains`` vs. tool provider domain.
    originating_domain: str = ""

    #: Caller-trusted domains. Uses the AgentPin convention: an empty list
    #: means *unrestricted* (all domains trusted), not "deny-all".
    trusted_domains: List[str] = field(default_factory=list)

    @classmethod
    def unrestricted(cls, caller_agent_id: str) -> "A2aVerificationContext":
        """Build a context placing no restriction on provider domains."""
        return cls(
            caller_agent_id=caller_agent_id,
            delegation_depth=0,
            originating_domain="",
            trusted_domains=[],
        )


# ---------------------------------------------------------------------------
# AllowedDomains helpers
# ---------------------------------------------------------------------------
#
# Spec source of truth: AgentPin technical specification §4.11. This module
# re-implements the helpers locally rather than depending on the agentpin
# package (see module-level docs for rationale). Update both projects in
# lockstep if the convention ever changes.


def is_unrestricted(list_: Optional[List[str]]) -> bool:
    """``True`` when ``list_`` is empty (no restriction)."""
    return not list_


def allows(list_: Optional[List[str]], domain: str) -> bool:
    """``True`` when ``domain`` is permitted under ``list_``.

    An empty ``list_`` allows everything. A non-empty list allows ``domain``
    when it exactly matches an entry OR matches one of the entry's wildcard
    patterns. Pattern matching follows AgentPin spec §5.5: a leading ``*.``
    matches any subdomain (e.g. ``*.client.com`` matches ``api.client.com``
    but not ``client.com`` itself).
    """
    if is_unrestricted(list_):
        return True
    return any(_pattern_matches(p, domain) for p in list_)


def intersect(lhs: Optional[Iterable[str]], rhs: Optional[Iterable[str]]) -> List[str]:
    """Intersection of two allow-lists honouring the ``empty = unrestricted``
    convention.

    - ``unrestricted ∩ X = X``
    - ``X ∩ unrestricted = X``
    - Otherwise: literal set intersection (string equality; no wildcard
      expansion), preserving the order of ``lhs``.

    An intersection that yields an empty list from two non-empty inputs is
    *re-interpreted as unrestricted* under the same convention — see
    AgentPin spec §4.11.4. Callers needing to distinguish "intentionally
    restricted to nothing" from "no restriction" must track that outside
    the allow-list value.
    """
    lhs_list = list(lhs) if lhs is not None else []
    rhs_list = list(rhs) if rhs is not None else []
    if is_unrestricted(lhs_list):
        return list(rhs_list)
    if is_unrestricted(rhs_list):
        return list(lhs_list)
    rhs_set = set(rhs_list)
    return [d for d in lhs_list if d in rhs_set]


def _pattern_matches(pattern: str, domain: str) -> bool:
    """Wildcard-aware domain pattern matcher.

    ``*.example.com`` matches ``api.example.com`` and ``a.b.example.com`` but
    NOT ``example.com`` itself. Anything without a leading ``*.`` is a
    literal equality check.
    """
    if pattern.startswith("*."):
        suffix = pattern[2:]
        if len(domain) <= len(suffix):
            return False
        if not domain.endswith(suffix):
            return False
        # Char before the suffix must be a literal '.'
        return domain[-(len(suffix) + 1)] == "."
    return pattern == domain
