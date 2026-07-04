# Architecture

**Version:** 3.0 · **Status:** Canonical, current as of code at HEAD.

This document is the **canonical, reusable specification** of the MCP Security Platform: enough to
re-implement the service from scratch. It describes the platform **as it is built today** — every
claim is matched to code, and anything not yet built is labelled **(roadmap)** rather than implied as
shipped. The **[README Enforced-vs-Roadmap table](../README.md#enforced-today-vs-roadmap)** is the
authoritative per-control status; this doc explains *how the pieces fit together*, and §10 lists the
security invariants any faithful re-implementation must preserve.

For the full language-agnostic re-implementation spec — authentication, credential broker,
policy & detections, audit, integrations, implementation lessons, and the test/QA program — see
**[`docs/spec/`](spec/README.md)**. This document stays the overview; the spec set carries the
normative detail.

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

**Adding a new MCP server?** See [`mcp-server-onboarding.md`](mcp-server-onboarding.md)
for the registry-granularity, entitlement, ingress-allowlist, and OAuth-discovery
checklist — derived from a full-functionality audit that found six onboarding
gaps the hard way.

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

### 6.5 RBAC roles

Two layers, not one — conflating them is the usual source of confusion:

1. **KC realm roles** — what Keycloak issues in the token (`admin`, `agent`, `auditor`,
   `security_reviewer`, `readonly`, ...).
2. **Platform RBAC roles** — what `middleware/rbac.py` actually checks against
   (`admin`/`platform_admin`, `manager`, `server_owner`, `user`, `auditor`, `agent`, `readonly`).

The KC role is translated into a platform role via an explicit allowlist
(`routers/oidc_browser.py::_ROLE_MAP`). A KC role missing from that dict is silently dropped —
fail-closed by design, so an IdP-side role can never grant platform access without an explicit
code change on this side.

**Role table** (`middleware/rbac.py::ROLE_LEVELS`, `services/entitlement.py::ROLE_LEVELS`):

| Role | Level | Grants |
|---|---|---|
| `admin` / `platform_admin` | 4 (max) | **Same role, two names — with one deliberate exception.** `admin` is the legacy/KC-facing name, `platform_admin` the "v3" canonical one; almost every RBAC check treats them as synonyms (admin UI, credential store, server-registry admin, grants/OPA policy editing, anomaly review, submission approve/reject). **Exception**: `routers/profiles.py::_CROSS_PROFILE_WRITE_ROLES` requires specifically `platform_admin` (not plain `admin`) to mutate *another principal's* profile — a past IDOR-005 fix deliberately narrowed trust for that one cross-user write, since KC only ever issues `admin` in this lab, no KC-mapped human held `platform_admin` until it was granted directly via the RBAC panel (§6.6). |
| `security_reviewer` | — | Narrow, single-purpose: approve/reject/request-changes on server **submissions only**, nothing else in the admin surface — and never on a submission the reviewer themself owns (`submission.py::_require_not_self_review`), even if they also hold `admin`. |
| `auditor` | 3 | Read-only: audit logs, anomaly alerts, compliance, policy rules, submission review queue. No mutation rights anywhere. |
| `server_owner` | 2 | Conceptual "owns a specific server" tier. Ownership itself is **not** granted by this RBAC role — it's enforced per-row via `owner_sub` checks in the handler (e.g. maintainers/debug-mode toggles). Self-service submitters actually hold `agent`/`user`, not `server_owner`; this role exists mainly for future multi-server-owner accounts. |
| `manager` | 1 | Can manage entitlements for servers alongside `server_owner`/`admin` — an ops tier above a plain user, below owning/reviewing. Not assigned to any lab user today. |
| `user` / `agent` / `readonly` | 0 | Base tier: invoke tools, submit/see only your own server drafts and submissions. `agent` and `readonly` are legacy aliases at the same level — `agent` historically meant a programmatic/service-client identity, `readonly` a human view-only identity. |

**Lab mapping** (`lab/keycloak/realm-mcp.json`):

| User | KC realm roles | Effective platform role | Can do |
|---|---|---|---|
| alice | `admin` (KC) + `platform_admin` (granted directly via the RBAC panel §6.6, since KC never issues it) | `admin` + `platform_admin` | Everything admin, **including** cross-principal profile writes (needs `platform_admin` specifically — see the IDOR-005 exception above). Before the `platform_admin` grant, she could view but not toggle another user's profile. |
| bob | `agent` | `agent` (level 0) | Invoke registered tools, submit his own server for review, see only his own submissions/servers. RBAC returns 403 on `/api/v1/admin/*` (covered by `AC-07` in the acceptance suite). |
| carol | `auditor` + `security_reviewer` | `auditor` (read-only everywhere) + submission-review mutate rights | Views audit/anomaly/compliance read-only, **and** can approve/reject/request-changes on submissions she didn't file — but cannot touch credentials, grants, or server-registry admin. |

**Worked example**: `test123` was submitted *and* approved by alice — legal under the pre-fix
code (`approve_submission` only checked for an admin role, never who owned the submission). Now,
alice hitting `/approve` on her own submission gets `403 cannot review your own submission`;
carol, holding the narrow `security_reviewer` role rather than full admin, approves/rejects it
instead — a real segregation-of-duties boundary, not just a UI convention.

### 6.6 RBAC management panel (in-platform, admin-only)

`role_assignments` is **append-only** — `V009__role_assignments_grants.sql` explicitly revokes
`UPDATE`/`DELETE` on the table from the app's own DB role (INV-011: single-writer, no hard
delete), so neither the panel nor anything else in the app can literally overwrite or delete a
row. `V050__role_assignments_append_only_revoke.sql` builds grant/revoke on top of that
constraint instead of around it:

- **Grant** = `INSERT` a new active event row (`revoked=false`).
- **Revoke** = `INSERT` a *tombstone* event row (`revoked=true`) for the same `(client_id, role)`
  — never an `UPDATE`/`DELETE` of the original grant.
- **Current state** is resolved at read time: the most recent row per `(client_id, role)` (by
  `created_at`) wins. `middleware/auth.py::_load_roles` and `routers/admin_grants.py`'s
  `_ACTIVE_ROLE_ASSIGNMENTS_SQL` both implement this "latest event wins" read, via
  `DISTINCT ON (client_id, role) ... ORDER BY created_at DESC`, filtering `revoked=false` and
  unexpired.
- The old `UNIQUE INDEX (client_id, role)` (V008) is dropped — it would have blocked ever
  re-granting a role after a revoke, or re-syncing the same role from Keycloak twice.

**KC-resync tension**: `oidc_browser.py`'s login flow inserts an active `granted_by='keycloak'`
row for every KC-derived role on every login (only when the latest event for that pair isn't
already an active keycloak grant, to avoid unbounded row growth). This means revoking a
KC-sourced role via the panel only sticks if the role is **also** removed in Keycloak — otherwise
the next login re-grants it. The panel surfaces this inline (`from_keycloak` flag → a visible
warning next to the revoke button) rather than hiding it.

**Endpoints** (`routers/admin_grants.py`, gated `admin`/`platform_admin` via `_require_admin`):
`GET/POST /api/v1/admin/roles`, `DELETE /api/v1/admin/roles/{client_id}/{role}`. Revoking
`admin`/`platform_admin` is blocked with `409` if it would zero out every admin grant on the
platform (counts active admin/platform_admin holders across all clients, excluding the one being
revoked) — a real lockout guard, not just a self-lockout check, verified live against the lab's
`bootstrap` service-account admin grant.

**UI**: a new "RBAC role assignments" table + grant form inside the existing Access tab
(`routers/portal.py::fragment_admin_access`) — no new nav tab, follows the existing
`fragment_admin_*` HTMX-fragment convention.

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

Full invariants are in §10 below. Disclosed residual risks: [`../SECURITY.md`](../SECURITY.md).
Headline properties and how they're met:

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

Current per-control status is the [README Enforced-vs-Roadmap table](../README.md#enforced-today-vs-roadmap).
Notable **(roadmap)** items: SPDX SBOM, outbound Jira, Helm/K8s, learned anomaly baseline,
server-owner onboarding wizard, per-server network isolation.

> Keep this document matched to code. If you change a control, update this doc and the README table
> in the same change — a claim without backing code is treated as a bug.

---

## 10. Security invariants

These are hard constraints; a faithful re-implementation must preserve every one. Machine-verifiable
ones are gated by `make security-check`; the rest are enforced by design and reviewed by hand.

| # | Invariant | Enforced by |
|---|---|---|
| INV-001 | Every tool invocation **and** auth-layer rejection (401/403) produces a synchronous audit event *before* the response; emission failure ⇒ 500 (no un-audited execution) | `middleware/audit.py`, `services/invocation.py` |
| INV-002 | Logs never contain raw payloads/secrets — credential & PII patterns auto-redacted (`[REDACTED:<cat>]`) | `mcp-audit-logger` redaction (unit-tested) |
| INV-003 | OPA is **deny-by-default** — `default allow = false`, no wildcard allow, no fallthrough | `policies/rego/authz.rego` |
| INV-004 | OPA unreachable ⇒ **fail closed** (503 `OPA_UNAVAILABLE`); `null`/missing result normalised to deny | `services/policy.py` |
| INV-005 | Quarantined tools cannot be invoked by any role (incl. admin), denied pre-OPA | `services/invocation.py` |
| INV-006 | Every registered tool has an HMAC-signed SBOM; no `active` status without a valid signature | `services/sbom.py`, DB constraint |
| INV-007 | Audit archive bucket has Object-Lock (≥GOVERNANCE, 90d); no app/API/Make path may delete it | `compliance-checker/checker.py`, `setup-minio.sh` |
| INV-008 | No secret value in any git-tracked file (`.env.example` placeholders only) | trufflehog in CI / `make security-check` |
| INV-009 | `/tools/{id}/invoke` requires mTLS cert or API key or OIDC JWT; unauthenticated ⇒ 401 before app logic | gateway `ssl_verify_client` + auth middleware |
| INV-010 | mTLS client certs have ≤24h TTL | step-ca provisioner config |
| INV-011 | Only the `proxy_app` DB role may write registry/audit/credential tables; only `compliance_checker` writes `compliance_reports` | PostgreSQL grants (`V003`/`V009`) |
| INV-012 | Signed OPA bundles in staging/production (HS256 `--verification-key`); **signed is the default** | `docker-compose.yml`, `check_signed_default.sh` |
| INV-013 | Every brokered credential is AES-256-GCM envelope-encrypted under a per-user HKDF-SHA256 KEK (≥256-bit master), keyed on the **authenticated** identity, with a synchronous lifecycle audit | `credential_broker/{kms,approaches/approach_a}.py` |
| INV-014 | Session-JTI revocation **fails closed** — any Redis/DB error ⇒ deny (never allow a revoked token) | `middleware/auth.py::_is_session_jti_revoked` |
| INV-015 | MCP-profile lookup **fails closed** — DB error + cache miss ⇒ 503, never an empty (unrestricted) profile | `services/invocation.py::_lookup_profile_with_cache` |

Identity anti-spoofing (P1-1): an OIDC email is only used as the identity key when the IdP asserts it
**verified** (`verified_oidc_identity`); with realm `verifyEmail=true`, a changed email is unverified
until re-proven, so a user cannot rename their email to a privileged identity. Machine
(client_credentials) tokens cannot perform human-only self-service profile mutation (P1-2).
