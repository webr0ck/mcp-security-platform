# AGENTS.md — repo guide for AI coding agents (and new humans)

This file is the **map of the codebase**. It tells an AI agent (Claude Code, Cursor, Copilot, Aider, etc.)
or a new contributor where things live, how to build and test, and the rules that must not be broken.
It is intentionally short and factual. For the *why* (the thesis and threat model) read [`README.md`](README.md);
for the *as-built* design read [`docs/ARCHITECTURE-v2.md`](docs/ARCHITECTURE-v2.md).

> **Prime directive:** this is a **reference implementation held to an honesty rule** — every claim in
> the docs is matched to code, and the [Enforced today vs Roadmap](README.md#enforced-today-vs-roadmap)
> table is the source of truth. **If you wire, change, or remove a control, update that table in the
> same change.** Over-claiming is treated as a bug.

---

## What this project is

A runtime security gateway for [MCP](https://modelcontextprotocol.io/) tool calls. Every tool call from
an AI agent passes through **identity → RBAC → quarantine → OPA policy → credential injection → audit**,
with backend MCP servers network-isolated by default. The design choice is **mediate every call at
runtime**, not statically classify servers as safe/unsafe.

## Languages & runtime

- **Python 3.12** everywhere (proxy, SDK, sample servers, scripts). FastAPI + Pydantic v2.
- **Rego** (OPA) for policy. **Bash** for ops/glue. **HTML/JS** for the static design page and a small UI.
- Containers: **Docker Compose** for the production-shaped tiers, **Podman** for the self-contained lab.

## Top-level layout

| Path | What it is | Start here when… |
|---|---|---|
| `proxy/` | **The core.** FastAPI security proxy — all enforcement logic. 228 files. | changing enforcement, auth, credentials, audit |
| `policies/` | OPA/Rego policy (`policies/rego/authz.rego` is the deny-by-default core) + Semgrep rules | changing authorization or policy gates |
| `gateway/` | Nginx + ModSecurity/OWASP-CRS edge (mTLS, WAF, rate limit) | changing the network edge |
| `sdk/mcphub-sdk/` | Python SDK + `create-mcp-server` scaffolder for building compliant backend MCP servers | adding/integrating a new MCP server |
| `observability/` | Audit logger (SHA-256, redaction), Loki/Grafana, Alertmanager, MinIO | changing audit or telemetry |
| `sandbox/tests/red_team/` | Containerized adversarial harness (cred-exfil, isolation, priv-esc, seccomp, tool-poisoning) | adding a security regression test |
| `infra/` | DB migrations (`infra/db/migrations/V0xx__*.sql`), secrets scaffolding, IaC | schema changes, infra |
| `deployments/` | Per-tier env templates (`engine`/`standard`/`poc`) | deployment config |
| `lab/` | Self-contained Podman lab: bundled Keycloak, Dex, Wazuh, sample MCP servers | local end-to-end testing |
| `detections/` | Sigma-style detection rules for the platform's own telemetry | detection content |
| `scripts/` | Operational scripts (see below) | running a verifiable demo / onboarding a server |
| `ui/` | Small admin/portal frontend | UI work |
| `docs/` | Architecture, API, RBAC, ADRs, RFCs, security invariants | understanding design decisions |
| `helm/`, `ci/` | K8s template stubs (roadmap), CI helpers | (mostly roadmap) |

## The core: `proxy/app/`

```
proxy/app/
  main.py                 # FastAPI app wiring + startup (credential broker wired here, fail-closed)
  core/                   # config, database (asyncpg), redis, security, hardening, public_url
  middleware/             # auth.py (identity) · rbac.py · audit.py (synchronous emit)
  routers/                # HTTP surface — one file per area:
                          #   auth, oauth, oauth_metadata, oidc_browser   (identity / OAuth 2.1 PKCE)
                          #   tools, mcp_server, catalog, entitlements      (tool invoke + discovery)
                          #   server_registry, admin_grants, admin_credentials, admin_limits (admin)
                          #   policy, anomaly, audit, compliance, health, portal, profiles
  services/               # business logic — the important ones:
                          #   invocation.py     ← single choke point for BOTH REST and /mcp tool calls
                          #   policy.py         ← OPA evaluation (deny-by-default, fail-closed)
                          #   opa_data_sync.py  ← pushes grants/roles to OPA (fail-closed)
                          #   entitlement.py    ← discovery==invoke enforcement
                          #   sbom.py           ← CycloneDX per tool
                          #   trust_verifier.py / trust_labeler.py / jcs.py ← signed trust-envelope POC
                          #   taint_floor.py / taint_store.py ← taint tracking
  credential_broker/      # AES-256-GCM + HKDF KEK credential store, Vault KMS, injection adapters
  models/                 # Pydantic models (tool, audit_event, anomaly, api_key, compliance)
  tests/                  # unit/ · integration/ · security/  (142 test files total in the repo)
```

**If you only read one file to understand enforcement, read `proxy/app/services/invocation.py`** — both the
REST path (`/api/v1/tools/{id}/invoke`) and the `/mcp` path funnel through it.

## Build / run / test

```bash
# Lab (self-contained, Podman) — easiest full stack to develop against
cp .env.lab.example .env.lab          # then set OIDC_ISSUER_URL (see LAB.md)
make -f Makefile.lab lab-up           # build + start + seed
make -f Makefile.lab lab-smoke        # all checks should be green

# Dev loop (needs a stack up)
make dev-up                           # hot reload + debug ports
make test                             # unit + integration
make lint                             # ruff

# Gates you MUST pass before proposing a change is "done"
make security-check                   # secret scan + rego lint + OPA deny-default + F-001 isolation
make ship-check                       # docs-honesty + secret scan + compose smoke (pre-publish gate)

# A verifiable control demo (no full stack needed)
python scripts/check_network_isolation.py   # statically proves backends can't reach the proxy
```

Production-shaped tiers run on Docker — see [`INSTALL.md`](INSTALL.md). The lab runs on Podman — see [`LAB.md`](LAB.md).

## Adding / integrating a new MCP server

This is the most common extension task. Use the SDK scaffolder rather than hand-rolling:

```bash
make sdk-base                                  # build the digest-pinned mcphub-sdk:base image (once)
python -m mcphub_sdk.scaffold <server-name>    # generates server.py / Dockerfile / requirements / compose snippet
```

Then register it (`scripts/onboard_server.py` or `POST /api/v1/servers`). Full walkthrough:
[`docs/MCP-SERVER-PUBLISHING.md`](docs/MCP-SERVER-PUBLISHING.md). The `lab/mcp-servers/` dir has working examples.

## Conventions (follow these)

- **Conventional commits:** `feat(scope): …`, `fix(sec): …`, `docs: …`, `chore: …`, `refactor: …`.
- **Fail-closed by default.** Never introduce a fail-open path. Deny-by-default in OPA; if a dependency
  (Vault, OPA, Redis) is unreachable, the request is denied, not allowed. Tests assert this.
- **No secrets in commits.** Only `*.example` env files are tracked; real `.env*` are gitignored.
- **One logical change per PR**, with tests (unit `proxy/tests/unit`, integration `proxy/tests/integration`,
  isolation/red-team `sandbox/tests`) and docs updated in the same change.
- **Keep the Enforced-vs-Roadmap table true.** A control is only "Enforced today" if there is code *and*
  a test for it.

## Canonical docs (don't trust the rest blindly)

| Doc | Status |
|---|---|
| [`README.md`](README.md) | thesis, threat model, **Enforced-vs-Roadmap table = source of truth** |
| [`docs/ARCHITECTURE-v2.md`](docs/ARCHITECTURE-v2.md) | architecture **design narrative** (supersedes v1). For *current* control status trust the README table + ROADMAP, not this doc's per-section annotations (see its banner) |
| [`docs/API.md`](docs/API.md) · [`docs/RBAC.md`](docs/RBAC.md) | API surface · role model |
| [`docs/SECURITY_NONNEGATABLES.md`](docs/SECURITY_NONNEGATABLES.md) | the security invariants CI enforces |
| [`docs/ROADMAP.md`](docs/ROADMAP.md) | done vs next |
| [`SECURITY.md`](SECURITY.md) | disclosure policy + tracked known-limitations |
| [`docs/archive/`](docs/archive/) | superseded/historical docs — **do not rely on these** |

> `docs/archive/ARCHITECTURE-v1.md` (v1) is **superseded**; prefer `ARCHITECTURE-v2.md`.
