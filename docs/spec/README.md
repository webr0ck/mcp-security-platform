# Architecture PRD — Specification Set

**Status:** matches code at HEAD (`4dfa7b5`).

This directory is the **language-agnostic re-implementation spec** for the MCP Security Platform. It
tells a re-implementer — in any language, on any stack — *what* the system must do and *what* must be
true before it may be called done. It is a PRD, not a tutorial: terse, normative, and matched to code.

## Relationship to the other docs (authority order)

Three documents describe this system at different altitudes. When they conflict, resolve in this order:

1. **README "Enforced today vs Roadmap" table** — the per-control **status** authority. If a control is
   not in the "Enforced today" column, it is roadmap, full stop. This table wins on *what is live*.
2. **`docs/ARCHITECTURE.md`** — the canonical architecture overview and the security-invariant list
   (§10). It wins on *what an invariant means* and how the pieces fit.
3. **`docs/spec/*` (this set)** — the detailed re-implementation requirements. It wins on nothing; it
   elaborates 1 and 2. If a spec detail contradicts the README table or §10, the spec is wrong — fix it.

Rule: **keep the specs matched to code.** A spec claim without backing code is a bug, exactly as in the
main docs-honesty policy.

## The specification set

| File | Scope (one line) |
|------|------------------|
| [`01-authentication.md`](01-authentication.md) | Identity & auth: three client-auth methods and their priority, the zero-credential OAuth 2.1 PKCE/DCR wire flow, token-validation rules (iss/aud/JTI fail-closed), browser OIDC session, two-layer RBAC + append-only role assignments. |
| [`02-credential-broker.md`](02-credential-broker.md) | Credential brokering: Vault master secret, per-identity HKDF-SHA256 KEK, AES-256-GCM with identity-bound AAD, injection modes and the three downstream flows, enrollment nonce flow, adapter plugin model, re-provisioning ops. |
| [`03-policy-and-detections.md`](03-policy-and-detections.md) | The single invocation chokepoint: deny-by-default OPA (fail-closed), signed bundles, grants sync, quarantine/entitlement, injection-pattern single source of truth, trust envelopes (passive), Biba taint floor, SSRF, SBOM/LLM registration audit, the 8 Sigma detections. |
| [`04-audit-and-observability.md`](04-audit-and-observability.md) | Synchronous audit-before-response (emit-or-500), event schema contract, redaction (INV-002), tamper-evidence stated honestly (HMAC in prod, no hash chain, GOVERNANCE ≠ WORM), Loki/Grafana/Wazuh pipeline, MUST-preserve vs MAY-swap. |
| [`05-integrations.md`](05-integrations.md) | Every external system (Keycloak, Vault, OPA, Postgres, Redis, Ollama, step-ca, Dex, Wazuh, Jira webhook), its interface, config, and failure behavior; backend MCP server onboarding; the zero-credential client pattern; the three real-service integration shapes. |
| [`06-implementation-lessons.md`](06-implementation-lessons.md) | Hard-won pitfalls a re-implementer WILL hit: OAuth enrollment-URL surfacing, dynamic-client audience mismatch, host-derived callback URLs, the MCP handshake, DNS-rebinding vs container hostnames, taint keying — plus the fail-closed catalogue. |
| [`07-testing-and-qa.md`](07-testing-and-qa.md) | The test & QA program: six-category pyramid, per-category normative requirements, the acceptance-criteria matrix (INV-001..015 + F-001/F-002), QA process, and reference commands. |

## How to use this as a PRD

Suggested implementation order — each layer is a chokepoint the next depends on:

1. **Identity / auth** (`01`) — establish who the caller is before anything trusts a request.
2. **Policy chokepoint** (`03`) — deny-by-default OPA on the single invoke path; nothing invokes without it.
3. **Credential broker** (`02`) — brokered, per-identity, envelope-encrypted secrets behind the policy.
4. **Audit / observability** (`04`) — synchronous audit-before-response wrapping every path.
5. **Detections** (`03` heuristics + `04` Wazuh) — layered on top of the audited, policed core.
6. **Portal** (UI) — last; it only exposes what the layers below already enforce.

Governing rule for every layer: **it lands with its tests per `07` and preserves every §10 invariant.**
A layer is not done until its blocking tests are in the suite, `make security-check` is green, and — for
isolation or portal work — the red-team / e2e gates are green (see `07` §4). Moving a control from
roadmap to enforced MUST update the README table in the same change.

## Conformance language

- Requirement keywords **MUST / MUST NOT / SHOULD / SHOULD NOT / MAY** are used per
  [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).
- **`(roadmap)`** marks a control described for completeness but **not yet wired**. A `(roadmap)` control
  MUST NOT be relied upon, asserted by a passing gate, or listed in the README "Enforced today" column
  until its backing code and test exist.
