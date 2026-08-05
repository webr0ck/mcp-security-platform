# OpenSpec - MCP Security Platform

Spec-driven development source of truth. These specs state *what must be true* for this
platform to be correct, in a form usable to build it from scratch on any stack. They name
properties and standards, never vendors.

## The two layers

Each capability directory holds two files, and the distinction is load-bearing.

| File | Status | What it does |
|---|---|---|
| `spec.md` | **Normative** | Numbered requirements and scenarios. States properties, never mechanisms or products. This is what conformance is measured against. |
| `guide.md` | Non-normative | How to actually build the requirement on the systems people really use - Keycloak, Entra ID, Okta, Vault, cloud KMS, OPA, Cedar, PostgreSQL, Compose, Kubernetes. Names products freely, because that is its job. |

A `guide.md` never adds an obligation. Where it and `spec.md` disagree, `spec.md` wins and the
guide is wrong. Each guide ends with a checklist whose every line names the requirement it
serves, so it is usable as a review sheet.

## Requirement identifiers

Every requirement has a stable ID, prefixed per capability:

| Prefix | Capability |
|---|---|
| `IDN` | `identity-authentication` |
| `NET` | `network-isolation` |
| `POL` | `policy-enforcement` |
| `ENT` | `authorization-entitlement` |
| `AUD` | `audit-observability` |
| `CRD` | `credential-broker` |
| `VET` | `server-vetting` |
| `ONB` | `server-onboarding` |

IDs are stable and never reused. A withdrawn requirement leaves its number retired rather than
reassigned, for the same reason `IDN-010` and `ONB-010` forbid identifier reuse: a stale
reference to a reused number silently points at something else.

Cross-references between capabilities cite the ID directly (`per POL-008`). A requirement that
cannot be stated without citing another capability's ID is a real dependency, and the citation
is the record of it.

## Relationship to `docs/`

| Where | What it is |
|---|---|
| `openspec/specs/*/spec.md` | Normative requirements and scenarios. Drives development. |
| `openspec/specs/*/guide.md` | Non-normative build guidance for specific products. |
| `openspec/traceability.md` | Spec ID to architecture invariant to enforcement site. |
| `docs/ARCHITECTURE.md` | How the reference implementation fits together. Explanatory. |
| `docs/spec/01-15` | Reference-implementation detail, incident history, code references. |
| `README.md` status table | What is enforced *in this build today* versus roadmap. |

A spec here that no code satisfies is a gap to close, not a lie - that is the point of a
spec. A claim in `docs/` with no backing code is a documentation bug.

## Prerequisites - what you must have before building

These are procurement decisions, not code:

1. **An authorization server you control client registrations of.** Not merely "we have
   SSO" - you must be able to register a confidential client, define a scope, and read the
   token you get back. Check for RFC 8693 token exchange and RFC 8707 resource indicators
   *before* you design around them; several major identity providers have neither, and their
   absence pushes every backend onto the stored-credential path in `credential-broker`.
   `identity-authentication/guide.md` §0 has the comparison.
2. **A place to root the credential key hierarchy, and a decision about its shape.** Either the
   platform reads a root secret and does its own crypto, or the root never leaves the store and
   the platform sends data to be wrapped. These disclose very different things when the platform
   is compromised, and `CRD-004` requires you to state which one you built. Read
   `credential-broker/guide.md` §0 before choosing. An environment variable is neither.
3. **A policy engine that denies by default and whose decisions you can distribute as signed,
   versioned artifacts.** In-process evaluation, not a network call per decision.
4. **Storage whose write permissions are enforced by the storage system.** The append-only
   property in `audit-observability` must be enforced below the application, so that an
   application compromise cannot rewrite the record of it.
5. **A runtime that can run workloads with no inbound reachability and constrained egress.**
   `network-isolation` is unimplementable if every service must be published to reach it.

## Build order

Each layer is a chokepoint the next depends on. Building out of order produces a system that
cannot be retrofitted cheaply.

1. `identity-authentication` - resolve who is calling before anything trusts a request.
2. `network-isolation` - establish the topology now; retrofitting it means re-plumbing
   every service.
3. `policy-enforcement` - one deny-by-default chokepoint on every mediated operation, in both
   directions.
4. `authorization-entitlement` - who may see and call what.
5. `audit-observability` - must record before the effect from the first invocation, not added
   later.
6. `credential-broker` - the largest single lift, and the one that removes agent-held
   credentials. Start with stored credentials; add token exchange where the identity provider
   supports it.
7. `server-vetting` + `server-onboarding` - the supply-chain gate and its human workflow.

Items 1-5 are structural. 6 and 7 can be staged, but a platform without 6 has not yet
delivered its central property: the agent never holds a credential that opens more than one
door.

## Capabilities

| Capability | Property it buys |
|---|---|
| `identity-authentication` | One visible issuer; every request carries a validated, revocable, typed identity |
| `authorization-entitlement` | Deny-by-default at role and per-server level; discovery equals invoke |
| `policy-enforcement` | One chokepoint that fails closed; quarantine, injection screening, taint floor |
| `credential-broker` | The agent never holds a backend credential; each backend sees only its own |
| `server-vetting` | Nothing runs unscanned; nothing stays approved forever |
| `server-onboarding` | Quarantine on entry, dual-control approval, pinned build, verified release |
| `network-isolation` | A hostile backend gains nothing - no reachability, no egress, no lateral movement |
| `audit-observability` | Every decision reconstructable, without the trail becoming the leak |

## Conventions

- `SHALL` is normative. `MAY` marks a genuine implementation choice. `SHOULD` is avoided -
  if it matters, it is a `SHALL`; if it does not, it is not in the spec.
- Every requirement carries at least one scenario, including a failure scenario. A
  requirement whose only scenario is the happy path is incomplete.
- Normative text states properties, not mechanisms. Where a requirement names a mechanism, that
  is a defect to fix, not a precedent. The test is whether a reader on a different stack can
  satisfy it without adopting ours.
- Products, versions and configuration belong in `guide.md`. Nothing in a `spec.md` may depend
  on a product's behaviour.

## Validation

```bash
OPENSPEC_TELEMETRY=0 openspec validate --specs --strict --no-interactive
```

The CLI is `@fission-ai/openspec`. `guide.md` files sit alongside `spec.md` and are ignored by
the validator.
