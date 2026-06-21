package verification

// A2A verification context for SchemaPin (v1.4 alpha.3).
//
// Mirrors the Rust schemapin::types::a2a module and the AgentPin v0.3
// AllowedDomains semantics (AgentPin technical specification §4.11).
//
// When a SchemaPin verification crosses an A2A (Agent-to-Agent) trust
// boundary, the verifier needs to scope the result to the intersection of
// caller-trusted domains and the tool provider's domain. A2AVerificationContext
// carries that scoping data; pair it with VerifySchemaForA2A.
//
// AllowedDomains convention
//
// The allow-list semantics follow AgentPin v0.3 exactly:
//
//	An empty TrustedDomains list means UNRESTRICTED — all domains trusted.
//	This is the opposite of the naïve set-theoretic interpretation but
//	matches v1.3 behaviour where an *omitted* allowed_domains field allowed
//	all domains.
//
// SchemaPin re-implements these helpers locally rather than depending on
// the agentpin Go module — keeping SchemaPin self-contained and avoiding a
// circular trust-stack dependency. Callers who *do* depend on both modules
// can pass the result of agentpin's intersection helper directly into
// TrustedDomains — the wire and in-memory shapes are identical.

// A2AMaxDelegationDepth is the maximum A2A delegation depth allowed by
// this verifier (v1.4 alpha.3).
//
// Mirrors the AgentPin max_delegation_depth cap (AgentPin spec §4.3).
// Bumping this on the SchemaPin side without a matching bump on AgentPin
// would let SchemaPin accept chains AgentPin would reject — keep in lockstep.
const A2AMaxDelegationDepth uint8 = 3

// A2AVerificationContext scopes a schema verification to an A2A interaction.
//
// Pair with VerifySchemaForA2A to run the standard 7-step verification flow
// with the additional A2A scope check.
type A2AVerificationContext struct {
	// CallerAgentID is the caller's agent identity (URN-style, matching
	// AgentPin). Informational only — SchemaPin does not validate the URN
	// shape.
	CallerAgentID string

	// DelegationDepth is the depth in the A2A delegation chain. 0 = direct
	// caller. Verifiers SHOULD reject DelegationDepth > A2AMaxDelegationDepth.
	DelegationDepth uint8

	// OriginatingDomain is the originating domain of the A2A request.
	// Informational; the scope check uses TrustedDomains vs. provider domain.
	OriginatingDomain string

	// TrustedDomains is the caller-trusted domain allow-list. Uses the
	// AgentPin convention: an empty slice means UNRESTRICTED (all domains
	// trusted), not "deny-all".
	TrustedDomains []string
}

// NewUnrestrictedA2AContext constructs a context that places no restriction
// on which provider domains may be verified through.
func NewUnrestrictedA2AContext(callerAgentID string) *A2AVerificationContext {
	return &A2AVerificationContext{
		CallerAgentID:   callerAgentID,
		DelegationDepth: 0,
	}
}

// AllowedDomains helpers
//
// Spec source of truth: AgentPin technical specification §4.11. This file
// re-implements the helpers locally rather than linking the agentpin Go
// module. Update both projects in lockstep if the convention ever changes.

// A2AIsUnrestricted returns true when list is empty (no restriction).
func A2AIsUnrestricted(list []string) bool {
	return len(list) == 0
}

// A2AAllows returns true when domain is permitted under list.
//
// An empty list allows everything. A non-empty list allows domain when it
// exactly matches an entry OR matches one of the entry's wildcard
// patterns. Pattern matching follows AgentPin spec §5.5: a leading "*."
// matches any subdomain (e.g. "*.client.com" matches "api.client.com" but
// NOT "client.com" itself).
func A2AAllows(list []string, domain string) bool {
	if A2AIsUnrestricted(list) {
		return true
	}
	for _, p := range list {
		if patternMatches(p, domain) {
			return true
		}
	}
	return false
}

// A2AIntersect returns the intersection of two allow-lists, honouring the
// empty-is-unrestricted convention.
//
//   - unrestricted ∩ X = X
//   - X ∩ unrestricted = X
//   - Otherwise: literal set intersection (string equality; no wildcard
//     expansion), preserving the order of lhs.
//
// An intersection that yields an empty slice from two non-empty inputs is
// *re-interpreted as unrestricted* under the same convention — see AgentPin
// spec §4.11.4. Callers needing to distinguish "intentionally restricted to
// nothing" from "no restriction" must track that outside the slice.
func A2AIntersect(lhs, rhs []string) []string {
	if A2AIsUnrestricted(lhs) {
		out := make([]string, len(rhs))
		copy(out, rhs)
		return out
	}
	if A2AIsUnrestricted(rhs) {
		out := make([]string, len(lhs))
		copy(out, lhs)
		return out
	}
	rhsSet := make(map[string]struct{}, len(rhs))
	for _, d := range rhs {
		rhsSet[d] = struct{}{}
	}
	out := make([]string, 0)
	for _, d := range lhs {
		if _, ok := rhsSet[d]; ok {
			out = append(out, d)
		}
	}
	return out
}

// patternMatches is a wildcard-aware domain pattern matcher.
//
// "*.example.com" matches "api.example.com" and "a.b.example.com" but NOT
// "example.com" itself. Anything without a leading "*." is a literal
// equality check.
func patternMatches(pattern, domain string) bool {
	if len(pattern) > 2 && pattern[0] == '*' && pattern[1] == '.' {
		suffix := pattern[2:]
		if len(domain) <= len(suffix) {
			return false
		}
		if domain[len(domain)-len(suffix):] != suffix {
			return false
		}
		return domain[len(domain)-len(suffix)-1] == '.'
	}
	return pattern == domain
}
