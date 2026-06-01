# MCP Security Platform

An **open-source reference implementation (work in progress)** exploring how to secure
[Model Context Protocol](https://modelcontextprotocol.io/) (MCP) tool calls at runtime — by
*mediating* every call through identity, policy, and audit rather than trying to statically
classify MCP servers as safe.

> **Honesty notice (2026-05-31).** This is a learning/reference build, not a production security
> gateway, and I keep the docs matched to the code. The **Enforced today vs Roadmap** table below is
> the source of truth. A full Claude+Codex dual-review of this repo is in
> `Brain/Vault/00_AI/__dual_review__/2026-05-30_mcp-security-platform.md` (architecture, claimed-vs-actual,
> security). If a claim isn't in the "Enforced today" column, treat it as roadmap.

## Enforced today vs Roadmap

| Area | Enforced today (verified in code) | Roadmap / not yet wired |
|---|---|---|
| **Policy (OPA/Rego)** | Evaluated on the REST invocation path `/api/v1/tools/{id}/invoke` | `/mcp` built-in tools currently bypass OPA/audit; **signed OPA bundles are an opt-in overlay** (`docker-compose.opa-signed.yml`), not the default |
| **Identity** | Gateway terminates mTLS and sets client identity; proxy uses it (server-side nonce + PKCE on credential enrollment) | App still trusts the gateway-set `X-Client-Cert-CN` header — safe only when nginx is the sole path (defense-in-depth gap) |
| **OIDC login** | **Keycloak browser login, PKCE S256, session JWT, Grafana SSO** — full flow implemented (`/api/v1/auth/oidc/*`); KC tokens stored server-side only; HttpOnly session cookie | External Keycloak access token passed directly as Bearer still validated against KC JWKS (as a fallback); session revocation check not yet enforced on every request |
| **Credential broker** | Crypto hardened — session identity (CB-001), HKDF-SHA256 KEK (CB-007), Vault HTTPS-only (CB-002), PKCE (CB-011), synchronous enrollment audit (CB-004), DB grants (CB-005) | **Broker is not wired into the request path at startup** (`broker_instance` is `None`); injection dispatcher logic exists (`credential_broker/dispatcher.py`) but actual injection is not active |
| **Credential injection modes** | Dispatcher wired — `injection_mode` column on `tool_registry` (none/service/user/service_account/oauth_user_token); admin credentials UI to upload/rotate/revoke credentials; V010–V012 DB migrations applied | `broker_instance` is `None` at startup — dispatcher resolves the mode but cannot inject until broker is wired |
| **Admin credentials UI** | `GET /admin/credentials` (htmx HTML) + REST API (`/admin/credentials/api`, `PUT`, `DELETE`, `/injection-mode`); requires admin role; credentials AES-256-GCM encrypted; audit events emitted | — |
| **Network isolation** | **F-001 proven on the lab** — a non-dialed sidecar cannot reach `proxy:8000`; regression-gated in `make security-check` | — |
| **Audit / observability** | Synchronous audit on REST invocation + credential enrollment; SHA-256 per-event; credential redaction; Loki/Grafana | Quarantine/error audit paths fail open; MinIO uses GOVERNANCE retention (not tamper-proof WORM); compliance checker is advisory |
| **Gateway** | mTLS, structured logs, rate limiting by client-CN / source-IP | `conf.d/default.conf` template needs cleanup (TLS-1.3-only not guaranteed); **per-tool** rate limiting not built |
| **SBOM** | CycloneDX per tool | SPDX **not implemented** (route should not be relied on for SPDX) |
| **Not built** | — | Helm/K8s (template stubs) · learned/statistical anomaly baseline (hardcoded sliding-window rules today) · outbound Jira (inbound webhook only) · broker wired into request path |

**Verified findings remediated:** the security findings in `docs/REVIEW-2026-05-16.md` (CB-001…CB-011)
are fixed in the current code (that review doc is now historical). The remaining gaps above are
*coverage/wiring* gaps, tracked honestly rather than papered over.

## What it's exploring

The thesis (see the companion blog): you can't reliably decide *in advance* whether an MCP server is
safe (static scanning misses semantic capability — e.g. a server that wraps a C2 framework). So instead
of classifying servers, **mediate every tool call** at runtime through identity → policy → audit, with
the backend servers network-isolated by default. This repo is where I'm building that, in the open.

## Layers

- **Layer 1 — Nginx gateway:** TLS termination, mTLS client-cert enforcement, structured logs, CN/IP rate limiting.
- **Layer 2 — FastAPI security proxy:** identity resolution, OPA/Rego policy eval (REST path), LLM-assisted tool-manifest auditing (Ollama, advisory), CycloneDX SBOM per tool, sliding-window anomaly heuristics, audit emission.
- **Layer 3 — Observability:** audit logger (SHA-256, redaction), Loki + Grafana, Alertmanager, MinIO archival, daily compliance checks.

## Quick Start

```bash
git clone https://github.com/purplehootie/mcp-security-platform
cd mcp-security-platform
cp .env.example .env            # fill required secrets (see comments)
make up                         # start services
make pull-model                 # Ollama model for risk scoring
make health                     # verify
make security-check             # secret scan + rego lint + OPA deny-default + F-001 isolation gate
```
Proxy API: `https://localhost/api/v1` · Grafana: `http://localhost:3000` (dev) · API docs: `https://localhost/docs` (dev only).

> A reproducible demo of the verified **network-isolation** control: `python scripts/check_network_isolation.py`.

## Development

```bash
make dev-up         # hot reload + debug ports
make test           # tests
make lint
make security-check # CI security-invariant gate
make ship-check     # docs-honesty gate + secret scan + compose smoke + isolation demo (pre-publish)
```

## Docs

- [`docs/ARCHITECTURE-v2.md`](docs/ARCHITECTURE-v2.md) — reality-annotated architecture (supersedes `ARCHITECTURE.md` v1)
- [`docs/ROADMAP.md`](docs/ROADMAP.md) — status: done vs next
- [`docs/REVIEW-2026-05-16.md`](docs/REVIEW-2026-05-16.md) — historical security findings (CB-001…011, now fixed)
- [`docs/SHIP-v0.1.md`](docs/SHIP-v0.1.md) — release checklist
- [`docs/API.md`](docs/API.md) · [`docs/RBAC.md`](docs/RBAC.md) · [`docs/SECURITY_NONNEGATABLES.md`](docs/SECURITY_NONNEGATABLES.md)

## Security: Enforced vs Roadmap

### Enforced (shipped)
- **ZK-at-rest storage custody** (Plans 4–5): SUK = HKDF(session_secret, server_nonce, principal‖server_id). Ciphertext + KEK id stored in Vault KV; session_secret never persisted. Storage-only attacker (Vault KV + Postgres + MinIO + any snapshot) obtains no plaintext.
  - **Operator/active-session caveat stated plainly:** An ops/SRE operator who can read live proxy memory during an active session CAN derive SUKs. This is the irreducible ZK-in-use limit of any injection gateway. Mitigated (not eliminated) by mlock + no-core-dump + session TTL ≤ 60s.
- **Three-tier RBAC v3** (Plan 4): platform_admin / server_owner+manager / user+agent. Typed principal namespace. /mcp no longer exempt.
- **OPA policy on all paths** (Plan 2): every tool call policy-evaluated + audited.
- **Revocation SLA ≤ 60s** (G7): role cache TTL 60s, session/entitlement epoch check.
- **SSRF allowlist** (Plan 7): private IP, link-local, IPv6, cloud metadata endpoints blocked at registration + call time.
- **Owner-consent tokens** (Plan 7): mode/credential changes require signed, single-use, bound consent.
- **Process hardening** (Plan 7): mlock + no-core-dump + production log-level enforcement.

### Roadmap (not yet implemented)
- **True ZK-in-use**: TEE / confidential computing (SGX / SEV-SNP) + remote attestation. Closes the operator/active-session gap.
- **Injection sidecar** (deferred per DD3): under the current token-derived SUK model it buys no ZK-in-use benefit; worth revisiting only with a TEE.
- **HSMAgentCustodian**: Vault transit API integration for agent secrets (stub in place).
- **org-OAuth RFC 8693**: full token exchange with `sub` preservation + scope-down (schema in place, exchange not wired).

## Background reading

- *MCP Attack Surface: what 30+ public servers reveal* — the static-analysis research that motivated this platform *(coming soon — purplehootie.com)*.

## Technology stack

| Component | Technology |
|---|---|
| Gateway | Nginx + ModSecurity (OWASP CRS) |
| Internal CA | Smallstep step-ca |
| Proxy | Python 3.12, FastAPI, Pydantic v2 |
| Policy engine | OPA (sidecar) |
| Local LLM | Ollama (advisory risk scoring) |
| Database | PostgreSQL 16 |
| Cache / sessions | Redis 7 |
| Identity provider | Keycloak 24 (primary, PKCE S256, Grafana SSO) · Dex (legacy) |
| SBOM | CycloneDX (SPDX not implemented) |
| Logs | Loki + Promtail · Grafana · Alertmanager · MinIO archival |

## License

Apache 2.0. See [LICENSE](LICENSE).
