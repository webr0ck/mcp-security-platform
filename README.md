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
| **Policy (OPA/Rego)** | OPA-evaluated + audited on **both** the REST path (`/api/v1/tools/{id}/invoke`) and the `/mcp` invoke path (both call `services/invocation.py`) | Built-in `/mcp` **meta-tools** still evaluate OPA under a placeholder `platform_admin` identity, not the real caller; the **discovery==invoke** invariant is enforced on the catalog but **not** on `/mcp` invoke (an admin role can invoke any tool by name — see `mcp_server.py`); **signed OPA bundles are an opt-in overlay** (`docker-compose.opa-signed.yml`), not the default |
| **Identity** | Gateway terminates mTLS and sets client identity; proxy uses it (server-side nonce + PKCE on credential enrollment) | App still trusts the gateway-set `X-Client-Cert-CN` header — safe only when nginx is the sole path (defense-in-depth gap); the **production** gateway (`gateway/nginx/conf.d/mcp-proxy.conf`) does **not** route `/mcp`, `/.well-known/*`, or `/oauth/register` — the zero-credential MCP/OIDC flow is currently reachable only via the **lab** gateway |
| **OIDC login** | **Keycloak browser login, PKCE S256, session JWT, Grafana SSO** — full flow (`/api/v1/auth/oidc/*`); KC tokens stored server-side only; HttpOnly session cookie; **session JTI revocation IS enforced on every request**; external Bearer path now validates **`iss`** and (in production) **`aud`** | External Keycloak access token passed as Bearer is accepted as a fallback; in dev/lab `aud` validation is off when `OIDC_AUDIENCE` is unset (production startup is blocked unless it is set) |
| **Credential broker** | **Wired into the request path at startup** (`main.py` lifespan → `inv_svc.broker_instance`); disabled (and **fail-closed** at call time) only when `VAULT_TOKEN` is empty. Crypto hardened — HKDF-SHA256 KEK, AES-256-GCM + AAD row-binding, Vault HTTPS-only (prod), PKCE, synchronous enrollment audit | KMS master-secret format mismatch (seeders write hex, `kms.py` base64-decodes it) reduces effective IKM — fix before relying on key strength; approach-B service adapters (`gitea/grafana/netbox`) are orphaned (live service/user path uses approach-A `credential_store` crypto, not those adapters) |
| **Credential injection modes** | `injection_mode` on `tool_registry`; **`service` / `user` active and fail-closed** (decrypt from `credential_store` → inject header, raise on missing/failed creds); `service_account` (KC client-credentials) active; admin credentials UI to upload/rotate/revoke; V010–V022 migrations | **`oauth_user_token` (RFC 8693) is fail-closed but NOT functional** — the caller's KC access token is not yet threaded into `invoke_tool` (P1); **`passthrough`** and **`entra_user_token`** (delegated MS Graph) are wired in code but **not settable via the registry/admin API** (the valid-mode sets in `server_registry.py`/`admin_credentials.py` omit them), so unexercised end-to-end; **`entra_client_credentials`** is unreachable (missing from the DB enum); **`basic_auth`** credential type is stored but not base64-encoded on injection |
| **Admin credentials UI** | `GET /admin/credentials` (htmx HTML) + REST API (`PUT`, `DELETE`, `/injection-mode`); **admin role only**; credentials AES-256-GCM encrypted; audit events emitted | No **user** self-service (per-user token upload routes are admin-gated) and no **server-owner** scoping (`server_owner` is not in the admin RBAC allow-lists); the standalone **React SPA is not mounted by any tier** — the htmx portal is the served UI |
| **Network isolation** | **F-001 proven on the lab** — a non-dialed sidecar cannot reach `proxy:8000`; regression-gated in `make security-check` | The F-001 gate scans only `docker-compose.yml`, not the tier composes users actually deploy; `compose.poc.yml` (demo tier) ships **no** gateway/WAF/TLS/mTLS |
| **Audit / observability** | Synchronous audit on REST + `/mcp` invocation + credential enrollment; SHA-256 per-event; raw tool args never persisted (hashes only); Loki/Grafana | Quarantine/error and `/mcp` meta-tool audit paths fail open (best-effort); MinIO uses GOVERNANCE retention (not tamper-proof WORM); compliance checker is advisory |
| **Gateway** | mTLS, structured logs, rate limiting by client-CN / source-IP | `conf.d/default.conf` template needs cleanup (TLS-1.3-only not guaranteed); **per-tool** rate limiting not built; production tier does not expose the MCP/OAuth endpoints (see Identity row) |
| **SBOM** | CycloneDX per tool | SPDX **not implemented** (route should not be relied on for SPDX) |
| **Anomaly detection** | Per-call static heuristics (keyword/tool-name rules) feed an OPA input score | Advertised **behavioral baseline is decorative** — `update_baseline_async` writes a per-client baseline that the scorer never reads; trivially evaded by renaming a tool. Learned/statistical baseline = roadmap |
| **Not built** | — | Helm/K8s (template stubs) · admin-UI IDP configuration (no backend route) · outbound Jira (inbound webhook only) · learned anomaly baseline |

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
- **Credential injection (service/user) fail-closed** (Plan 7): broker wired at startup; `service`/`user`/`entra_user_token`/`service_account` modes inject per-tool credentials and **raise rather than forward uncredentialed** on any failure. At-rest crypto: AES-256-GCM + AAD row-binding, HKDF-SHA256 KEK.
- **Session JTI revocation ≤ 60s** (G7): proxy-issued session JWTs are revocation-checked on **every** request; role cache TTL 60s.
- **OPA policy on the invoke paths** (Plan 2): REST and `/mcp` tool invocations are policy-evaluated + audited via `services/invocation.py`; deny-by-default; **fail-closed when OPA is unreachable** (INV-004).
- **SSRF allowlist** (Plan 7): private IP, link-local, IPv6, cloud-metadata endpoints blocked at registration + call time.
- **Process hardening** (Plan 7): mlock + no-core-dump + production log-level enforcement (best-effort; degrades with a warning if the platform/permissions disallow it).

### Implemented but NOT active / partial (do not rely on yet)
- **ZK-at-rest storage custody** (Plans 4–5): SUK = HKDF(session_secret, server_nonce, principal‖server_id) is implemented, but the custody path is **not wired into the live request flow** — treat as design, not an enforced control. (Operator/active-session caveat still applies once wired: an operator reading live proxy memory during an active session can derive SUKs — the irreducible ZK-in-use limit, mitigated not eliminated by mlock + short TTL.)
- **Three-tier RBAC v3** (Plan 4): the principal model exists, but `server_owner`/`manager` are **absent from `authz.rego`**, `platform_admin` is accepted inconsistently across admin routers, and `/mcp` built-in meta-tools evaluate OPA under a placeholder admin identity. RBAC is not yet uniform across all surfaces.
- **Owner-consent tokens** (Plan 7): the signed/single-use/bound consent primitive exists but **`verify_consent_token` has no non-test callers** — mode/credential changes do not currently require consent.
- **Server entitlements / discovery==invoke**: blocked by a schema bug (the `entitlement` table has no `role` column the query selects) — entitlement checks throw-and-swallow; not enforced on `/mcp` invoke.

### Roadmap (not yet implemented)
- **org-OAuth RFC 8693 (`oauth_user_token`)**: token exchange with `sub` preservation + scope-down — currently **fail-closed and non-functional** (caller KC token not threaded into the invoke path; exchange targets the same IdP, not a second IdP).
- **`passthrough` / `entra_client_credentials`**: implemented or stubbed but not settable via the registry/admin API (DB-only) / missing from the DB enum.
- **True ZK-in-use**: TEE / confidential computing (SGX / SEV-SNP) + remote attestation. Closes the operator/active-session gap.
- **HSMAgentCustodian**: Vault transit API integration for agent secrets (stub in place).

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
