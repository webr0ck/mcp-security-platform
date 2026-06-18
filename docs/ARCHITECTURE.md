# Architecture

**Version:** 3.0 · **Status:** Canonical, current as of code at HEAD.

This document describes the MCP Security Platform **as it is built today**. It is held to the same
rule as the rest of the repo: every claim is matched to code, and where something is roadmap it is
labelled **(roadmap)** rather than implied as shipped. The
**[README Enforced-vs-Roadmap table](../README.md#enforced-today-vs-roadmap)** and
**[ROADMAP.md](ROADMAP.md)** remain the authoritative per-control status; this doc explains *how the
pieces fit together*. For the design history (the pre-hardening defect review) see
[`archive/`](archive/).

---

## 1. Thesis & scope

You can't reliably decide *in advance* whether an MCP server is safe, so this platform **mediates
every tool call at runtime** — identity → RBAC → quarantine → policy → credential injection → audit —
and keeps backend MCP servers **network-isolated** by default. The adversary in scope is a malicious
or compromised backend MCP server (or a prompt-injected agent driving it). The platform's job: even a
fully hostile backend never sees a raw credential, can't be invoked outside policy, can't reach the
proxy or other backends over the network, and can't act without an audit record.

It is a **reference implementation**, not a hardened product.

---

## 2. Layered architecture

Three enforcement layers sit in front of network-isolated backends.

```
 AI agent / MCP client ──TLS 1.3 (mTLS on /api/v1/tools/*)──┐
                                                            ▼
┌──────────────────── LAYER 1 — GATEWAY (Nginx + ModSecurity) ───────────────────┐
│ TLS 1.3 termination · mTLS client-cert enforcement · OWASP-CRS WAF              │
│ rate limit per client-CN + per source-IP · structured JSON access log          │
│ X-Client-Cert-CN set for the proxy; blanked outside /api/v1/tools/*             │
└───────────────────────────────────┬────────────────────────────────────────────┘
                                     ▼  (proxy honours the CN header only from trusted-proxy IPs)
┌──────────────────── LAYER 2 — SECURITY PROXY (FastAPI / Python 3.12) ───────────┐
│ ① Identity        AuthMiddleware: mTLS CN (post-verify) / OIDC session / API key │
│ ② RBAC            role check from role_assignments                               │
│ ③ Quarantine      pre-policy gate (INV-005) on tool quarantine state             │
│ ④ Policy          OPA eval — deny-by-default, fail-closed 503                    │
│ ⑤ Credentials     broker resolves & injects per-identity; client never sees it   │
│ ⑥ Audit           synchronous SHA-256 event (HMAC-signed in production)          │
│ Registration-time: CycloneDX SBOM · OPA-static + Ollama LLM manifest audit       │
└───────────────────────────────────┬────────────────────────────────────────────┘
        ┌──────────────┬─────────────┼──────────────┬──────────────┐
        ▼              ▼             ▼              ▼              ▼
   OPA sidecar     PostgreSQL 16   Redis 7       Ollama        Vault (KMS)
   deny-default,   registry +      sessions,     advisory      per-identity
   signed bundle   audit idx +     rate limits   risk score    master secret
   default         credential_store
                                     │ structured audit events (append-only)
                                     ▼
┌──────────────────── LAYER 3 — OBSERVABILITY ────────────────────────────────────┐
│ mcp-audit-logger: SHA-256/event · redaction (tested) → Loki/Promtail · Grafana   │
│ Alertmanager · MinIO archival (Object-Lock GOVERNANCE) · daily compliance check   │
└──────────────────────────────────────────────────────────────────────────────────┘
```

Backend MCP servers are **not** on this diagram's trust plane: they sit behind the proxy with no
inbound route to it (see §4).

---

## 3. Service catalogue

| Service | Container | Tech | Role |
|---|---|---|---|
| Gateway | `gateway` | Nginx 1.25 + ModSecurity 3 (OWASP CRS) | TLS/mTLS edge, WAF, rate limit |
| Internal CA | `step-ca` | Smallstep step-ca | issues mTLS certs (lab/dev) |
| Proxy | `proxy` | Python 3.12 / FastAPI / Pydantic v2 | all enforcement logic |
| Policy | `opa` | Open Policy Agent (sidecar) | deny-by-default authorization |
| Local LLM | `ollama` | Ollama | advisory tool-manifest risk score |
| Database | `db` | PostgreSQL 16 | server/tool registry, audit index, `credential_store` |
| Cache | `redis` | Redis 7 | sessions, rate limits, enrollment nonces |
| Secrets/KMS | `vault` | HashiCorp Vault | credential-broker master secret |
| Identity | `keycloak` (+ `dex` in lab) | Keycloak 24 | OIDC, PKCE S256, Grafana SSO |
| Observability | `loki`/`promtail`/`grafana`/`alertmanager`/`minio` | — | audit pipeline + archival |
| Compliance | `compliance-checker` | Python (cron) | daily sampled audit-integrity check |

---

## 4. Trust boundaries & network isolation

The proxy is **off** any flat shared mesh. Each backend shares exactly **one** dedicated network with
the proxy, so a compromised backend cannot traverse a shared network to reach the proxy or a peer.

```
PUBLIC ──TLS / mTLS──▶ gateway
gateway ──gateway-net──▶ proxy            (only ingress path to the proxy)
proxy ──proxy-opa-net──▶ opa              ┐
proxy ──proxy-redis-net──▶ redis          │ pairwise egress — one network per backend
proxy ──proxy-db-net──▶ db                │
proxy ──vault-net──▶ vault                ┘
backend MCP servers: no inbound route to proxy:8000 (no shared network)
```

This topology is enforced as a regression gate: `scripts/check_network_isolation.py` statically
resolves the compose topology and asserts the proxy is not on a shared backend network and that
backend/sidecar services share no network with it. It runs in `make security-check` across **all five
compose tiers** (`docker-compose.yml`, the lab, POC, `engine`, `standard`). It is a *topology
membership* proof (daemon-free); **runtime** unreachability is exercised separately by the red-team
harness (`sandbox/tests/red_team/`).

The proxy honours the gateway-set `X-Client-Cert-CN` header **only from trusted-proxy source-IPs**
(`proxy/app/middleware/auth.py`); this remains a defense-in-depth item (see [`../SECURITY.md`](../SECURITY.md) F-001).

---

## 5. Core data flows

### 5.1 Tool invocation

Both the REST path (`POST /api/v1/tools/{id}/invoke`) and the MCP path (`/mcp`) funnel through the
single chokepoint `proxy/app/services/invocation.py`:

```
mTLS / OIDC session / API key
  → gateway (TLS, WAF, per-CN rate limit, JSON log)
  → AuthMiddleware (identity = request.state.client_id)
  → RBAC → quarantine gate (INV-005) → anomaly heuristic (advisory)
  → OPA evaluate(identity × tool × params)        ── deny-by-default; OPA unreachable ⇒ 503
  → if tool needs a credential: broker resolves & injects (client never sees it)
  → invoke isolated backend MCP server
  → synchronous audit event (SHA-256, redacted; HMAC-signed in production)
  → response
```

### 5.2 Credential enrollment (zero raw credentials to the client)

```
authenticated user → /auth/enroll/{service}
  → server-side single-use nonce in Redis (TTL 5m, bound to the authenticated identity)
  → redirect to IdP (Keycloak / M365 / Bitbucket / Dex) with PKCE
  → /auth/callback/{service}: nonce verified & consumed (identity recovered from the nonce, not a header)
  → refresh token envelope-encrypted (AES-256-GCM, KEK = HKDF(master, authenticated user_sub))
  → credential_store upsert keyed by the authenticated identity
  → synchronous CREDENTIAL_ENROLLED audit event
```

### 5.3 Credential broker resolution

Triggered by `invoke_tool()` when a tool's `injection_mode != none`. Crypto, per
`proxy/app/credential_broker/`:

- **Master secret** fetched from Vault over HTTPS (`VAULT_ADDR` defaults `https://`; `http://` is
  rejected outside development — `core/config.py`). Decoded by `kms.py` with an enforced **256-bit
  entropy floor** (fails closed on a weak/misconfigured value).
- **Per-identity KEK**: `HKDF-SHA256(master, salt=per-blob, info="…kek…:{user_sub}")` — different
  identity ⇒ different key, no reuse.
- **AES-256-GCM** decryption with **AAD row-binding** `(user_sub, service, tool_id, owner_type)` —
  prevents credential-swap attacks; KEK bytearray is zeroed after use.
- **Injection modes** (`dispatcher.py`): `service`, `user`, `service_account`, `kc_token_exchange`
  (alias `oauth_user_token`, RFC 8693), `entra_client_credentials` active; `passthrough` /
  `entra_user_token` exist in code but aren't settable via the admin API **(roadmap)**. An unknown
  mode **fails closed**.
- Resolved token is injected as `Authorization: Bearer …` and **never logged** (redacted).

### 5.4 Tool-manifest audit (registration time only)

On tool registration the proxy combines a static OPA score with an Ollama LLM score. If Ollama is
unreachable the score falls back to **1.0 × static** (no silent downgrade), and in production
`REQUIRE_LLM_AUDIT=true` makes registration return 503 rather than run fail-open. **Invocations are
not affected** — the LLM auditor only runs at registration.

---

## 6. Policy & authorization (OPA)

- **Deny-by-default**: `policies/rego/authz.rego` (`default allow = false`), gated by INV-003.
- **Signed bundles are the default**: `docker-compose.yml` runs OPA with `--verification-key`; `make up`
  auto-signs; `make security-check` enforces it via `scripts/check_signed_default.sh`.
- **Grants are DB-authoritative**: `client_grants` are pushed to OPA's data API on every mutation
  (fail-closed — 503 if the push fails), with a 60s reconcile loop and a startup push
  (`services/opa_data_sync.py`, `routers/admin_grants.py`). RBAC `role_assignments` is a separate
  table consumed by middleware, not pushed to OPA.
- **Discovery == invoke**: server-linked tools are entitlement-checked on invoke
  (`enforce_tool_entitlement`), with no admin exception.

---

## 7. Observability & audit

- `mcp-audit-logger` emits one **SHA-256-hashed** event per invocation; raw tool arguments are never
  persisted (hashes only); redaction is unit-tested (`test_redaction.py`). In **production** events are
  additionally **HMAC-signed** (`AUDIT_LOG_HMAC_KEY` forced at startup).
- Events flow stdout → Promtail → Loki → Grafana; Alertmanager for alerting; MinIO for archival
  (Object-Lock **GOVERNANCE** retention — note: not tamper-proof WORM, see ROADMAP).
- A daily `compliance-checker` samples the audit trail for integrity.

---

## 8. Threat model (summary)

Full invariants: [`SECURITY_NONNEGATABLES.md`](SECURITY_NONNEGATABLES.md). Disclosed residual risks:
[`../SECURITY.md`](../SECURITY.md). Headline properties and how they're met:

| Goal | Mechanism |
|---|---|
| Hostile backend never sees a raw credential | broker injects per-identity tokens; client/backend never receive stored secrets; tokens redacted in logs |
| No invocation outside policy | deny-by-default OPA on the single `invocation.py` chokepoint; fail-closed 503 |
| Backend can't reach the proxy/peers | pairwise networks; isolation gate across all tiers; red-team runtime harness |
| Master key not network-sniffable | Vault HTTPS enforced outside dev; 256-bit entropy floor |
| Credential-swap resistance | AES-256-GCM with AAD row-binding |
| Tamper-evident trail | synchronous SHA-256 audit; HMAC-signed in production |

**Known residual items** (tracked openly): MinIO GOVERNANCE ≠ MFA-WORM; the `X-Client-Cert-CN` trust
is IP-gated defense-in-depth; the anomaly detector is an advisory heuristic, not a learned model;
per-server network isolation and per-tool rate limiting are **(roadmap)**.

---

## 9. Status & roadmap

Current per-control status is the [README Enforced-vs-Roadmap table](../README.md#enforced-today-vs-roadmap);
forward plan and current test counts are in [ROADMAP.md](ROADMAP.md). Notable **(roadmap)** items:
SPDX SBOM, outbound Jira, Helm/K8s, learned anomaly baseline, server-owner onboarding wizard,
per-server network isolation.

> Keep this document matched to code. If you change a control, update this doc, the README table, and
> ROADMAP in the same change — a claim without backing code is treated as a bug.
