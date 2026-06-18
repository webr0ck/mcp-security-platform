# Documentation index

Start with the root [`README.md`](../README.md) (thesis + threat model + the **Enforced-vs-Roadmap**
table that is the source of truth) and [`AGENTS.md`](../AGENTS.md) (repo map). This folder holds the
deeper design and reference docs.

## Design & architecture

| Doc | Purpose |
|---|---|
| [`ARCHITECTURE-v2.md`](ARCHITECTURE-v2.md) | **Canonical** as-built architecture, reality-annotated per component |
| [`ARCHITECTURE-delegated-auth.md`](ARCHITECTURE-delegated-auth.md) | Delegated downstream-auth subsystem (User → IdP → Gateway → Entra → Graph) |
| [`db.md`](db.md) | Database schema reference |
| [`RBAC.md`](RBAC.md) | Role model and permission matrix |
| [`API.md`](API.md) | HTTP API surface |

## Security

| Doc | Purpose |
|---|---|
| [`SECURITY_NONNEGATABLES.md`](SECURITY_NONNEGATABLES.md) | The security invariants CI enforces (INV-001…) |
| [`appsec-review.md`](appsec-review.md) | Full AppSec audit of the invariants (historical record) |
| [`../SECURITY.md`](../SECURITY.md) | Disclosure policy + tracked known-limitations |

## Operating & extending

| Doc | Purpose |
|---|---|
| [`MCP-SERVER-PUBLISHING.md`](MCP-SERVER-PUBLISHING.md) | How to build & onboard a new backend MCP server |
| [`LAB-HOWTO.md`](LAB-HOWTO.md) | Working in the self-contained Podman lab |
| [`runbook.md`](runbook.md) | Operational runbook |
| [`DEV-TEST-PROCESS.md`](DEV-TEST-PROCESS.md) · [`test-plan.md`](test-plan.md) · [`TEST-STRATEGY-v2.md`](TEST-STRATEGY-v2.md) | Dev/test process, test plan & strategy |

## Decision records

| Path | Purpose |
|---|---|
| [`ADR/`](ADR/) | Architecture Decision Records (language choices, enrollment model, consent gate) |
| [`rfc/`](rfc/) | RFCs (e.g. signed MCP trust envelope) |
| [`prd/`](prd/) · [`PRD-delegated-downstream-auth.md`](PRD-delegated-downstream-auth.md) | Product requirement docs |
| [`waivers/`](waivers/) | Risk-acceptance waivers with expiry |
| [`ROADMAP.md`](ROADMAP.md) | Done vs next |

## Archive

[`archive/`](archive/) holds **superseded / point-in-time** documents kept for provenance only —
do not rely on them. See [`archive/README.md`](archive/README.md).
