/**
 * @file A2A verification context for SchemaPin (v1.4 alpha.3).
 *
 * Mirrors the Rust `schemapin::types::a2a` module and the AgentPin v0.3
 * `AllowedDomains` semantics (AgentPin technical specification §4.11).
 *
 * When a SchemaPin verification crosses an A2A (Agent-to-Agent) trust
 * boundary, the verifier needs to scope the result to the intersection of
 * *caller-trusted* domains and the *tool provider's* domain.
 * {@link A2aVerificationContext} carries that scoping data; pair it with
 * {@link verifySchemaForA2A}.
 *
 * ## AllowedDomains convention
 *
 * The allow-list semantics follow AgentPin v0.3 exactly:
 *
 * > An empty `trustedDomains` list means **unrestricted** — all domains
 * > trusted. This is the opposite of the naïve set-theoretic interpretation
 * > but matches v1.3 behaviour where an *omitted* `allowed_domains` field
 * > allowed all domains.
 *
 * SchemaPin defines these helpers locally rather than depending on the
 * `agentpin` npm package — keeping SchemaPin self-contained and avoiding a
 * circular trust-stack dependency. Callers who *do* install both packages
 * can pass the result of `agentpin.AllowedDomains.intersect(...)` into
 * `trustedDomains` directly — the wire and in-memory shapes are identical.
 */

/**
 * Scope a schema verification to an A2A interaction.
 *
 * Pair with {@link verifySchemaForA2A} (re-exported from `./verification.js`)
 * to run the standard 7-step verification flow with the additional A2A
 * scope check.
 */
export class A2aVerificationContext {
    /**
     * @param {Object} init
     * @param {string} init.callerAgentId - Caller's agent identity (URN-style,
     *   matching AgentPin). Informational only.
     * @param {number} [init.delegationDepth=0] - Depth in the A2A delegation
     *   chain (0 = direct caller). Verifiers SHOULD reject `> 3` to match
     *   AgentPin's `max_delegation_depth` cap.
     * @param {string} [init.originatingDomain=''] - Originating domain of the
     *   A2A request. Informational.
     * @param {string[]} [init.trustedDomains=[]] - Caller-trusted domains.
     *   Empty list = unrestricted (all domains trusted) per AgentPin
     *   convention.
     */
    constructor({ callerAgentId, delegationDepth = 0, originatingDomain = '', trustedDomains = [] }) {
        this.callerAgentId = callerAgentId;
        this.delegationDepth = delegationDepth;
        this.originatingDomain = originatingDomain;
        this.trustedDomains = [...trustedDomains];
    }

    /** Build a context placing no restriction on provider domains. */
    static unrestricted(callerAgentId) {
        return new A2aVerificationContext({ callerAgentId });
    }
}

// ─────────────────────────────────────────────────────────────────────────
// AllowedDomains helpers
// ─────────────────────────────────────────────────────────────────────────
//
// Spec source of truth: AgentPin technical specification §4.11. This module
// re-implements the helpers locally rather than linking the agentpin npm
// package (see module docs above for rationale). Update both projects in
// lockstep if the convention ever changes.

/**
 * `true` when `list` is empty / null / undefined (no restriction).
 *
 * @param {string[]|null|undefined} list
 * @returns {boolean}
 */
export function a2aIsUnrestricted(list) {
    return !list || list.length === 0;
}

/**
 * `true` when `domain` is permitted under `list`.
 *
 * An empty `list` allows everything. A non-empty list allows `domain` when
 * it exactly matches an entry OR matches one of the entry's wildcard
 * patterns. Pattern matching follows AgentPin spec §5.5: a leading `*.`
 * matches any subdomain (e.g. `*.client.com` matches `api.client.com` but
 * NOT `client.com` itself).
 *
 * @param {string[]|null|undefined} list
 * @param {string} domain
 * @returns {boolean}
 */
export function a2aAllows(list, domain) {
    if (a2aIsUnrestricted(list)) {
        return true;
    }
    return list.some((pattern) => patternMatches(pattern, domain));
}

/**
 * Intersection of two allow-lists honouring the empty-is-unrestricted
 * convention.
 *
 * - `unrestricted ∩ X = X`
 * - `X ∩ unrestricted = X`
 * - Otherwise: literal set intersection (string equality; no wildcard
 *   expansion), preserving the order of `lhs`.
 *
 * An intersection that yields an empty list from two non-empty inputs is
 * *re-interpreted as unrestricted* under the same convention — see AgentPin
 * spec §4.11.4. Callers needing to distinguish "intentionally restricted to
 * nothing" from "no restriction" must track that outside the value.
 *
 * @param {string[]|null|undefined} lhs
 * @param {string[]|null|undefined} rhs
 * @returns {string[]}
 */
export function a2aIntersect(lhs, rhs) {
    if (a2aIsUnrestricted(lhs)) return rhs ? [...rhs] : [];
    if (a2aIsUnrestricted(rhs)) return [...lhs];
    const rhsSet = new Set(rhs);
    return lhs.filter((d) => rhsSet.has(d));
}

/**
 * Wildcard-aware domain pattern matcher.
 *
 * `*.example.com` matches `api.example.com` and `a.b.example.com` but NOT
 * `example.com` itself. Anything without a leading `*.` is a literal
 * equality check.
 */
function patternMatches(pattern, domain) {
    if (pattern.startsWith('*.')) {
        const suffix = pattern.slice(2);
        if (domain.length <= suffix.length) return false;
        if (!domain.endsWith(suffix)) return false;
        return domain[domain.length - suffix.length - 1] === '.';
    }
    return pattern === domain;
}
