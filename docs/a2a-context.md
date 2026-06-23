# A2A Verification Context

> **Status:** v1.4.0-alpha.3 — implemented in **Rust, Python, JavaScript, and Go**. Mirrors the AgentPin v0.3 `AllowedDomains` convention so the two trust stacks compose.

When agents collaborate over A2A (Agent-to-Agent), a tool schema verified by one agent crosses a trust boundary into another. The standard offline verification answers *"is this schema authentically signed by its provider?"* — but in an A2A flow you also need to answer *"is this provider's domain one the calling agent is allowed to trust?"*

`verify_schema_for_a2a` runs the standard verification and adds two A2A-aware checks:

1. **Delegation-depth cap** — reject when `delegation_depth` exceeds `A2A_MAX_DELEGATION_DEPTH` (3), matching AgentPin's `max_delegation_depth`.
2. **Scope check** — reject when the tool provider's domain is not allowed by the caller's trusted-domains allow-list.

The cryptographic outcome is unchanged — A2A context only adds a *policy* gate. A failure surfaces as the `A2A_SCOPE_VIOLATION` error code.

---

## AllowedDomains convention

The `trusted_domains` allow-list follows AgentPin v0.3's `AllowedDomains` semantics exactly:

- **An empty list means *unrestricted*** (all domains trusted) — not "deny-all". This matches v1.3 behaviour where an omitted allow-list permitted all domains.
- A non-empty list allows a domain when it matches an entry literally, or via a leading `*.` wildcard (`*.client.com` matches `api.client.com` but not `client.com` itself).
- Intersection follows AgentPin spec §4.11.4: `unrestricted ∩ X = X`.

SchemaPin re-implements these helpers (`is_unrestricted` / `allows` / `intersect`) locally rather than depending on the AgentPin package, keeping the tool-integrity library self-contained. The wire and in-memory shapes are identical, so callers who *do* link AgentPin can pass `agentpin.AllowedDomains.intersect(...)` results straight into `trusted_domains`.

See [Technical specification §20](https://github.com/ThirdKeyAI/SchemaPin/blob/main/TECHNICAL_SPECIFICATION.md) for the normative definition.

---

## `A2aVerificationContext`

| Field | Meaning |
|-------|---------|
| `caller_agent_id` | Caller's agent identity (URN-style, matching AgentPin). Informational. |
| `delegation_depth` | Depth in the A2A delegation chain; `0` = direct caller. Rejected above 3. |
| `originating_domain` | Originating domain of the A2A request. Informational. |
| `trusted_domains` | Caller-trusted domains. **Empty = unrestricted.** |

(Field names are camel/Pascal-cased per language — e.g. `delegationDepth` in JS, `DelegationDepth` in Go.)

---

## Usage

### Rust

```rust
use schemapin::A2aVerificationContext;
use schemapin::verification::verify_schema_for_a2a;
use schemapin::pinning::KeyPinStore;

let context = A2aVerificationContext {
    caller_agent_id: "urn:agent:coordinator".to_string(),
    delegation_depth: 1,
    originating_domain: "coordinator.example".to_string(),
    trusted_domains: vec!["*.thirdkey.ai".to_string()],
};

let result = verify_schema_for_a2a(
    &schema,
    &signature_b64,
    "api.thirdkey.ai",   // tool provider domain
    "calculate_sum",     // tool_id
    &discovery,
    None,                // revocation
    &mut KeyPinStore::new(),
    &context,
    None,                // canonicalization (default schemapin-v1)
);
assert!(result.valid);
```

Use `A2aVerificationContext::unrestricted("urn:agent:...")` to verify with no domain restriction.

### Python

```python
from schemapin.a2a import A2aVerificationContext
from schemapin.verification import verify_schema_for_a2a, KeyPinStore

context = A2aVerificationContext(
    caller_agent_id="urn:agent:coordinator",
    delegation_depth=1,
    originating_domain="coordinator.example",
    trusted_domains=["*.thirdkey.ai"],
)

result = verify_schema_for_a2a(
    schema, signature_b64, "api.thirdkey.ai", "calculate_sum",
    discovery, None, KeyPinStore(), context,
)
assert result.valid
```

### JavaScript

```javascript
import { A2aVerificationContext } from "schemapin";
import { verifySchemaForA2a, KeyPinStore } from "schemapin";

const context = new A2aVerificationContext({
  callerAgentId: "urn:agent:coordinator",
  delegationDepth: 1,
  originatingDomain: "coordinator.example",
  trustedDomains: ["*.thirdkey.ai"],
});

const result = verifySchemaForA2a(
  schema, signatureB64, "api.thirdkey.ai", "calculate_sum",
  discovery, null, new KeyPinStore(), context,
);
```

### Go

```go
ctx := &verification.A2AVerificationContext{
    CallerAgentID:     "urn:agent:coordinator",
    DelegationDepth:   1,
    OriginatingDomain: "coordinator.example",
    TrustedDomains:    []string{"*.thirdkey.ai"},
}

result := verification.VerifySchemaForA2A(
    schema, signatureB64, "api.thirdkey.ai", "calculate_sum",
    discovery, nil, pinStore, ctx,
)
```

---

## Failure modes

| Condition | Result |
|-----------|--------|
| `delegation_depth > 3` | `A2A_SCOPE_VIOLATION` (checked before any crypto) |
| Provider domain not in a non-empty `trusted_domains` | `A2A_SCOPE_VIOLATION` |
| Standard verification fails (bad signature, revoked key, pin mismatch, …) | the underlying error, unchanged |

A2A context never makes a cryptographically invalid schema pass — it can only add a restriction.

---

## Related

- [Trust Bundle Distribution](trust-bundle-distribution.md) — sign and exchange trust bundles between agents over A2A.
