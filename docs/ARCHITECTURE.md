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

### 1.1 Security-critical design — read this first ⚠️

If you re-implement only a few things correctly, make it these. Each is a place where a subtle
mistake silently removes a security guarantee (the hard-won failure modes are in §6 of the spec set,
[`06-implementation-lessons.md`](spec/06-implementation-lessons.md)).

| # | Load-bearing invariant | Why it's dangerous to get wrong | Where |
|---|---|---|---|
| 🔑 **KEK never on disk** | Broker master secret lives only inside Vault's encrypted barrier; per-identity KEK is derived (HKDF) + zeroed after use, blob AAD-bound to `(user_sub, service, tool_id, owner_type)`. | A KEK on disk + a DB dump = **offline** decryption of every stored credential. The two-factor KMS boundary collapses to one. | §5.3, [`02-credential-broker.md`](spec/02-credential-broker.md) |
| 🚦 **Deny-by-default, fail-closed everywhere** | OPA `default allow = false`; OPA-unreachable ⇒ deny; unresolved principal ⇒ deny; missing session JTI ⇒ treated revoked; a credential mode with no handler ⇒ raise, never pass through. | Any fail-*open* path is a full auth bypass under the exact conditions an attacker induces (DoS the policy engine, strip a header). | §6, `invocation.py`, `dispatcher.py` |
| 🪪 **Trusted-proxy header gate** | `X-Client-Cert-CN` / `X-User-Sub` are honoured **only** when the caller proves the gateway shared secret (`hmac.compare_digest`); prod refuses to boot without it. | Without the gate, any client that can reach the proxy directly spoofs identity by setting a header. | §5.1, `middleware/auth.py`, `config.py` |
| 🔁 **Discovery == invoke** | The *same* entitlement resolver gates catalog visibility and invocation; there is **no** admin/role exception. | If discovery and invoke drift, a principal can invoke what they can't see (or an admin bypasses per-server entitlement). | §6, `services/entitlement.py` |
| 🧾 **Audit-before-response (synchronous)** | The audit event is emitted and durable **before** the tool result returns (emit-or-500). Responses re-enter the proxy for injection screening + ES256 trust-envelope signing — they are **not** a passthrough. | An async/after audit loses the record on crash; a passthrough response is an unscreened injection / unattributable action. | §5.1/§7, `invocation.py` |
| 🧬 **Network isolation** | Each backend shares exactly one pairwise net with the proxy and has **no inbound route** to `proxy:8000`; enforced by a CI runtime assertion, not just compose topology. | A backend that can call the proxy REST API is a confused-deputy / SSRF pivot into the control plane. | §4, `scripts/check_network_isolation.py` |
| ✍️ **Signed policy bundles** | OPA loads a signed bundle by default (HMAC/HS256 today); `make sign-policy-bundle` after any `.rego` edit — editing rego without re-signing is a silent no-op in prod. | An unsigned/were-not-resigned bundle means policy changes don't take effect, or a tampered bundle loads. | §6, `docker-compose.yml`, `scripts/sign_policy_bundle.sh` |
| 🎫 **One OAuth issuer identity (RFC 9207) + advertise only what clients consume** | `authorization_servers`, the AS-metadata `issuer`, and the callback `iss` are all the **same realm issuer URL** (proxy fronts *filtered* discovery at that issuer path, not its own origin). AND: `authorization_response_iss_parameter_supported` is advertised **false**. | Two-sided lesson. (1) A split issuer (proxy origin vs realm URL) is an RFC 9207 violation — a strict client (Codex) rightly rejects it, a lenient one (Claude Code) hides it; "works in Claude Code" ≠ compliant. (2) But strict ≠ correct: even with a consistent, present `iss`, rmcp/Codex 0.144.x's validator is broken and rejects it *when the AS advertises support* (openai/codex#31573) — so we stop advertising the optional flag (Keycloak still sends `iss`; PKCE+state still bind the flow). Verified: `codex mcp login` → OAuth success. | [`10-codex-oauth-issuer-consistency.md`](spec/10-codex-oauth-issuer-consistency.md) |

Everything below elaborates these. When a section describes one, it is marked with the same icon.

---

## 2. Layered architecture

Three enforcement layers sit in front of network-isolated backends.

```
 AI agent / MCP client ──TLS 1.3 (mTLS on /api/v1/tools/*)──┐
                                                            ▼
┌──────────────────── LAYER 1 — GATEWAY (Nginx + ModSecurity) ───────────────────┐
│ TLS 1.3 termination · mTLS client-cert enforcement · OWASP-CRS WAF             │
│ rate limit per client-CN + per source-IP · structured JSON access log          │
│ X-Client-Cert-CN set for the proxy; blanked outside /api/v1/tools/*            │
└───────────────────────────────────┬────────────────────────────────────────────┘
                                     ▼  (proxy honours the CN header only from trusted-proxy IPs)
┌──────────────────── LAYER 2 — SECURITY PROXY (FastAPI / Python 3.12) ────────────┐
│ ① Identity        AuthMiddleware: mTLS CN (post-verify) / OIDC session / API key │
│ ② RBAC            role check from role_assignments                               │
│ ③ Quarantine      pre-policy gate (INV-005) on tool quarantine state             │
│ ④ Policy          OPA eval — deny-by-default, fail-closed 503                    │
│ ⑤ Credentials     broker resolves & injects per-identity; client never sees it   │
│ ⑥ Audit           synchronous SHA-256 event (HMAC-signed in production)          │
│ Registration-time: CycloneDX SBOM · OPA-static + Ollama LLM manifest audit       │
└───────────────────────────────────┬──────────────────────────────────────────────┘
        ┌──────────────┬─────────────┼──────────────┬──────────────┐
        ▼              ▼             ▼              ▼              ▼
   OPA sidecar     PostgreSQL 16   Redis 7       Ollama        Vault (KMS)
   deny-default,   registry +      sessions,     advisory      per-identity
   signed bundle   audit idx +     rate limits   risk score    master secret
   default         credential_store
                                     │ structured audit events (append-only)
                                     ▼
┌──────────────────── LAYER 3 — OBSERVABILITY ──────────────────────────────────────┐
│ mcp-audit-logger: SHA-256/event · redaction (tested) → Loki/Promtail · Grafana    │
│ Alertmanager · MinIO archival (Object-Lock GOVERNANCE) · daily compliance check   │
└───────────────────────────────────────────────────────────────────────────────────┘
```

Backend MCP servers are **not** on this diagram's trust plane: they sit behind the proxy with no
inbound route to it (see §4).

**mTLS listener split (lab only, 2026-07-08).** `ssl_verify_client optional` is a TLS-handshake-time,
listener-wide setting — nginx cannot scope it to a location, so the single `:8443` listener sent an
optional client-certificate request on *every* connection, including `/mcp` traffic that never goes
near `/api/v1/tools/`. Windows Schannel-based MCP clients (observed: Codex) fail that handshake with
`SEC_E_ILLEGAL_MESSAGE` (`0x80090326`) before the request layer ever sees it — curl and OIDC/OAuth
flows are unaffected, which is why this only surfaced for one client. The lab config
(`lab/nginx/conf.d/mcp-proxy-lab.conf`) now runs two listeners: `:8443` with `ssl_verify_client off`
for all public/OAuth/MCP traffic, and a dedicated `:8445` (`GATEWAY_MTLS_PORT`) that keeps
`ssl_verify_client optional` and serves `/api/v1/tools/` only. **Production
(`gateway/nginx/conf.d/mcp-proxy.conf`) still has the single-listener design and has not been split**
— any Windows-Schannel MCP client hitting a production deployment's `:443` would hit the same failure.
Tracked as an open item, not yet fixed (production nginx changes need their own sign-off).

**`/api/v1/tools/` no longer requires a client cert on `:8443` (lab, 2026-07-11).** The path used
to hard-401 at nginx on `:8443` for every request regardless of credential, forcing any caller —
including OAuth-authenticated shell/CLI clients that structurally cannot present a client cert
(they're not the same client as the browser/TLS layer) — onto the `:8445` mTLS listener. It now
forwards like any other API path; the app's existing auth chain (session JWT / OIDC bearer / API
key) and RBAC (`admin`/`platform_admin`/`agent`/`user` are all already permitted on this route,
see `app/middleware/rbac.py`) gate it instead, so a no-cert **and** no-session request still 401s —
fail-closed is preserved, just enforced one layer up. Cert-based agent identity (`X-Client-Cert-CN`)
remains available only via the dedicated `:8445` listener, unchanged. Production's single-listener
`:443` config already only *optionally* requests a client cert per §2's INV-009 row below, so this
same OAuth-fallback behavior was already true there.

**OIDC token exchange hairpinned through the external TLS listener (lab, 2026-07-11 — PRD-0008
R-1).** Keycloak's discovery document advertises the **external** issuer URL
(`https://<LAB_HOST>:8443/...`) for every endpoint, including `token_endpoint`, regardless of
whether the document itself was fetched internally — `KC_HOSTNAME` fixes the advertised URLs
platform-wide. `oidc_browser.py`'s `/login` redirect already rewrote `auth_endpoint`
internal→external before sending the browser there; the server-to-server token exchange
(`oidc_callback`, and identically `token_refresh`) had no equivalent external→internal rewrite, so
the proxy container POSTed to its own external address and hairpinned back through nginx's TLS
listener — whose `mcp-step-ca`-issued cert the proxy's default trust store does not carry, so every
login failed closed with a 502 (`token_exchange_failed`). Fixed by rewriting `token_endpoint`
external→internal (mirroring the existing `auth_endpoint` rewrite) before both POSTs, so the
exchange goes directly to `lab-keycloak:8080` over the container network. No TLS trust or hairpin
question to solve — just don't hairpin.

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

**Single-tool-per-server registry wrappers didn't resolve to a real upstream tool name (lab,
2026-07-11 — PRD-0008 R-2).** The MCP path's direct `tools/call` dispatch (`_route_to_registry` in
`routers/mcp_server.py`) forwarded `tool_registry.name` (e.g. `"gitea-repos"`) verbatim as the
outgoing `params.name` — but the upstream MCP server's real per-function tool names are different
(e.g. `list_repos`, `get_repo`, ...), and no column stored the mapping, so every such wrapper bounced
"Unknown tool: gitea-repos". Fixed reactively rather than by an always-resolve-first rewrite (which
would have re-triggered discovery for already-correctly-routed individually-registered tools too):
on that specific upstream error signature, `_resolve_upstream_subtool_name` issues a `tools/list`
through the *same* `invoke_tool()` pipeline (identical entitlement/OPA/credential-injection
enforcement as any real call — this is not an authorization bypass) and retries once with the
resolved name, caching the result per `tool_id` for 300s.

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
  (alias `oauth_user_token`, RFC 8693), `entra_client_credentials`, `entra_user_token`,
  `external_oauth_client_credentials`, `external_oauth_user_token` active; `passthrough`
  exists in code but isn't settable via the admin API **(roadmap)**. An unknown mode **fails
  closed**.
  `kc_token_exchange`'s proxy-side audience allowlist (Codex review CR-03) is now two-layered
  (WP-A2, `services/oauth_policy.py`): the **enforced per-server value** is
  `server_registry.approved_token_audience`, set only by the admin `/approve` endpoint (never by
  the submitter); `KC_TOKEN_EXCHANGE_ALLOWED_AUDIENCES` (comma-separated env setting, default
  `lab-tickets`) remains as an outer/bootstrap ceiling — both must agree for a token exchange to
  proceed. `tool_registry.kc_token_audience` (the value the dispatcher actually reads) is written
  at tool-discovery time exclusively from `approved_token_audience`, never from the
  submitter-requested `upstream_idp_config`, so the runtime dispatch path structurally cannot see
  an unreviewed audience. Requested-vs-approved is surfaced via
  `GET /api/v1/submissions/{id}` (`upstream_idp_config` vs `approved_upstream_idp_config` /
  `approved_token_audience` / `approved_oauth_scopes`). **Open**: full exchanged-token
  actor/delegation claim verification remains **(roadmap)**.
- **OAuth/IdP policy engine (Codex review CR-13, WP-A2)**: `oauth_provider_policy` table
  (issuer+tenant → allowed/blocked scopes, redirect patterns, client-auth methods, risk ceiling)
  governs the scope-shaped dimension for `entra_client_credentials`/`entra_user_token` at
  approval time (`services/oauth_policy.validate_requested_config`); an unknown issuer or a
  scope outside the matching policy row's `allowed_scopes` (or explicitly `blocked_scopes`)
  fails closed (422) at `/approve`. High-risk scopes (`write`, `admin`, `mail`, `files`,
  `offline_access`) additionally require the reviewer to set `high_risk_scopes_approved=true`
  in the same request — recorded as `server_registry.high_risk_scopes_approved_by`/`_at`.
  `service_account` mode's `scope` field (e.g. `openid`) is validated by a **separate**
  scope-set allowlist (`SERVICE_ACCOUNT_ALLOWED_SCOPES`, default `openid,profile,email`) —
  deliberately not the `kc_token_exchange` audience allowlist above; an earlier attempt to
  reuse one mechanism for both was tried and rejected because it broke every existing
  service_account tool (lab-gitea, lab-grafana-mcp, lab-wazuh) on their default `openid` scope.
- **External IdP adapters, generic + Jira (Codex review CR-04 remainder, WP-A3)**:
  `credential_broker/adapters/generic_oauth.py::GenericOAuthAdapter` is a parameterized (not
  statically env-configured) approach-A adapter — onboarding a new external OAuth server (any
  IdP that isn't Keycloak or Entra) needs zero new Python module or env var, just a submission +
  reviewer approval. `adapters/dynamic_external_oauth.py::resolve_external_oauth_adapter` builds
  one per server at enrollment/refresh time from that server's `approved_upstream_idp_config`
  (never the requested `upstream_idp_config`) plus an admin-provisioned client_secret
  (`credential_store`, resolved the same way `entra_client_credentials` resolves its own —
  `tool_registry.credential_id`, no new admin endpoint). `routers/oauth.py::_get_adapter` and
  `broker.py::_resolve_a` both try the static registry first (m365/dex/bitbucket/jira, unchanged),
  then fall back to this dynamic resolver — fail-closed to `None`/"not enrolled" on any DB/Vault
  error, never a raw exception. New dispatcher branches
  `_inject_external_oauth_user_token`/`_inject_external_oauth_client_credentials` mirror the
  Entra ones exactly in shape, cleanly separated from `kc_token_exchange`. `GET
  /auth/status/{service}` is a new enrollment-status endpoint (existence-only check via the
  typed-principal dual-read, never decrypts) — applies to every approach-A adapter, not just the
  new mode. `credential_broker/adapters/jira.py` is the named D2 fast-follow: Atlassian Jira Cloud
  OAuth 2.0 3LO, statically registered like m365/dex/bitbucket (env vars
  `JIRA_OAUTH_CLIENT_ID`/`_SECRET`/`_REDIRECT_URI`/`_SCOPES`); a real Jira API call additionally
  needs a `cloudId` resolved via a separate Atlassian endpoint, which this adapter does NOT do —
  documented limitation, not silently dropped (see the adapter's module docstring).
- Resolved token is injected as `Authorization: Bearer …` and **never logged** (redacted).

### 5.4 Tool-manifest audit (registration time only)

On tool registration the proxy combines a static OPA score with an Ollama LLM score. If Ollama is
unreachable the score falls back to **1.0 × static** (no silent downgrade), and in production
`REQUIRE_LLM_AUDIT=true` makes registration return 503 rather than run fail-open. **Invocations are
not affected** — the LLM auditor only runs at registration. **Discovery uses the same fail-closed
rule (Codex review CR-09, fixed)**: `_run_tool_discovery` used to catch the auditor-unavailable
error and insert the tool anyway with a *fabricated* `risk_score=20`/`medium` — a made-up audit
record for a tool never actually analyzed, even though INV-005 quarantined it either way. It now
skips the tool (visible in the discovery response's `skipped_tools`) instead of inserting, matching
`register_tool`/`update_tool`. **Open**: discovery still has no `MAX_DISCOVERED_TOOLS` /
`MAX_TOOL_SCHEMA_BYTES` limits or a reserved-name denylist on the raw upstream `tools/list` response
— it is not yet validated with the same strictness as direct registration.

**Code-scan fusion (PRD-0006 R-1)**: the manifest scorer is blind to the *repo code*, so the
registration audit applies a **structural risk floor** from the tool's server's mcp_checker submission
scan: `combined_score = max(combined_score, floor)` (same monotonic shape as the injection escalation,
`auditor.py::_scan_risk_floor`). The floor fires only when the server-linked tool's `scan_status`
is `blocked` or its `scan_report` carries a block-tier finding — a benign-looking manifest can't mask
a repo the code scanner flagged malicious. A tool registered directly (`POST /tools`, no `server_id`)
has no scan → manifest-only, unchanged (fail-safe); lookup errors fail safe to no-floor. The floor is
one-directional (never lowers a score) and records the scan's `scanned_at`/`scan_commit` so a reviewer
can spot a stale flooring scan. *Reference: `auditor.py`, migration `V057`.*

**LLM provider is admin-configurable (PRD-0005 R-1)**: `services/llm_config.py` overlays env
defaults (`OLLAMA_*`) with the `llm_config` table (base_url/model/timeout/enabled; absent row = env),
editable via the **LLM Provider** admin tab. An optional API token is stored **encrypted** in
`platform_secrets` (KEK-wrapped AES-256-GCM via `approach_a` — a distinct non-user key-domain, NOT
the tool-bound `credential_store` path) and sent only as a `Bearer` header. **SI-6 (no silent
unauthenticated downgrade)**: a configured-but-unobtainable token (Vault down / decrypt failure) OR a
`401/403` from the endpoint is treated identically to "LLM unreachable" → `llm_unavailable`, which in
prod trips the `REQUIRE_LLM_AUDIT` 503. A no-token local ollama is unaffected. *Reference:
`services/auditor.py::run_llm_analysis`, `routers/admin_llm.py`, `services/platform_secrets.py`,
migration `V054`.*

### 5.5 Submission scan pipeline (self-service onboarding)

**2026-07 update (CR-14/WP-B1, CR-12/WP-B2): scanning moved out of the proxy process.** The
paragraphs below describing an in-proxy `services/submission_scanner.py` background task are
historical — that code path is now dead (unreferenced, kept only for its module docstring). The
live pipeline is a Postgres-backed job queue (`scan_jobs`, migration `V063`) consumed by a
separate, unprivileged `scanner-worker` service (`scanner_worker/`) that holds **no** proxy
secrets, DB-admin credentials, Vault token, or gateway shared secret — only its own narrow
`scanner_worker_app` DB role (INSERT-only on `scan_raw_results`, UPDATE limited to its own
claim/heartbeat columns on `scan_jobs`). This is a deliberate **execution/adjudication split**: the
worker clones the repo and runs every scanner below, emitting RAW findings only — it structurally
cannot write `scan_status`/`block`/any verdict. A trusted **evaluator** inside the proxy
(`services/scan_evaluator.py`, never touches attacker-controlled repo content — only the
structured JSON the worker already produced) reads `scan_raw_results` and drives
`server_registry.scan_status`/`submission_status`. A dead-lettered job (worker crashed before
producing a result) fails closed to `scan_status='error'`, never `passed`. Four scanners run:

The repo is cloned from a configured **git provider** (PRD-0005 R-2). GitHub and corporate
**Bitbucket** (Data Center `/scm/<proj>/<repo>.git` + `/<proj>/repos/<repo>`, and Cloud
`/<workspace>/<repo>`) are both supported — the provider is inferred from the URL host and must
match an **enabled, exact-host** row in `git_providers`. The service-account token lives encrypted
in `platform_secrets` (`git-<provider>`). **SSRF (the clone path does NOT traverse the egress proxy,
whose allowlist is M365/Graph only)**: the host is resolved and validated at write time and again
immediately before the clone — loopback/link-local/`169.254` cloud-metadata are **always** refused;
RFC1918/private ranges require an explicit `allow_private` admin acknowledgement (audited). Transport
hardening (https-only, option-injection `--` guard, shallow, tmpfs, read-only token) is unchanged.
*Reference: `services/git_providers.py`, `routers/admin_git.py`, migration `V055`.*

- **trufflehog** — verified secrets only (`--only-verified`); a live-confirmed secret blocks.
- **pip-audit** — Python-dependency CVEs, alongside **OSV-Scanner** (broad multi-ecosystem),
  **npm audit** (Node, lockfile-only, never `npm install`), and **govulncheck** (Go reachability) —
  CR-12/WP-B2. All four are RAW-finding scanners; policy (`services/dependency_policy.py`)
  alias-collapses findings across scanners and applies a severity threshold, never inferred from
  fix-version presence. A `review_required` verdict (distinct from `blocked`/`error`/`passed`) is
  forced — never a silent pass — for unknown-severity CVEs, a Node project with no lockfile, or a
  Go module that fails to load under govulncheck (a submitter could otherwise break their own
  `go.mod` to downgrade coverage and slip through). Reviewer-authorized, exact-match, expiring
  waivers (`scan_waivers` table) can clear a finding; waived findings stay visible, never deleted.
- **custom regex rules** — `scan-config.yaml` patterns (hardcoded IPs, credential logging, `eval`);
  advisory by default.
- **mcp_checker** — the vendored MCP-specific static engine (`proxy/vendor/mcp_checker/`, sourced
  from the `mcp-security-research` audit engine): malicious-code patterns, tool poisoning, per-OS
  attack patterns, SSRF/IMDS, crypto stealers, obfuscation, and an MCP-specific **semgrep** SAST
  rule pack. Runs semgrep in an isolated venv, fully offline.

**Gate semantics**: a FAIL in a `block_checks` check (deliberate-malice signals: `malicious_doc_ast`,
`*_attack_patterns`, `memory_poisoning`, `crypto_stealer`, `silent_exfil_pattern`, `obfuscation_scan`)
**blocks** the submission; any other FAIL is a **warning** routed to human review. A scanner binary
that cannot run fails **closed** (`scan_status='error'`, never `passed`). **The scan is a pre-filter
only** — a `passed` scan moves the submission to `awaiting_review`; it does not approve it. Human
review (§6.5 `security_reviewer`, with self-review forbidden) remains the authoritative gate.

**Post-approval state machine + deploy model — updated 2026-07 (CR-01/WP-B3).** Two paths now
exist side by side, sharing one verification implementation. **Self-hosted (original path,
unchanged):** `awaiting_review` → **approve** → `approved_pending_url`/`scaffold_ready` (DB fields
only) → submitter runs the server themselves → `POST .../provide-url` (SSRF-validated) → discovery
(quarantined, INV-005) → `active`. **Platform-managed (new, CR-01):** `POST
/api/v1/submissions/{id}/apply` pins the exact scanned+approved commit/content digest (never a
re-clone of branch HEAD — a submitter moving HEAD between approval and build must not swap in
unscanned code) and enqueues a `build_requested` job on the same `scan_jobs` queue WP-B1 built.
An **unprivileged build worker** (`build_worker/`, mirrors `scanner_worker/`'s isolation: no proxy
secrets, no container socket) builds the artifact, which passes back through the CR-12 scan layer;
a trusted **build evaluator** (`services/build_evaluator.py`) drives `deployment_status`
(`build_requested→building→built→deploy_requested→deploying→deployed→verify_requested→
verifying→verified→failed`, `infra/db/migrations/V068`). A separate, narrowly-scoped **launcher**
(`services/deploy_launcher.py`) is the *only* code path that shells out to `podman run` — it
re-reads `deployment_status='built'` fresh (never trusts a cached value) before launching, on a
per-server isolated network with the same hardening flags (`--read-only`, `no-new-privileges`,
resource limits) as every other lab MCP server. This permanently separates the SEC-05-trusted
components from the socket-capable one (resolves CR-18's "no env is both" contradiction
architecturally, not just by documenting it). **Verify is ONE shared code path for both flows**
(`services/deploy_verifier.py::run_verification_probes` — healthcheck → quarantined discovery →
invocation probe → CR-06 machine-testable contract check → `verification_report` write); deploy/
build success never auto-releases tools, release still requires the explicit evidence-gated
`POST /api/v1/tools/{id}/release` (CR-07). **Known limitation, not hidden:** no real `buildah`/
`kaniko` binary or container registry exists in the dev/lab sandbox this was built against — the
image-build step is a named, tested stub with a concrete upgrade path (mirror
`scanner_worker/Dockerfile`'s binary-install pattern); every other part of the pipeline (queue,
digest pinning, evaluator, launcher hardening, verify, contract check, API) is real and tested.

**Post-deployment lifecycle (WS-A, `ops-agent/`).** Day-2 operations on an
*already-deployed* server — read its logs, restart it, rebuild its image — are
handled by a second socket-capable component, the **`ops-agent`**, kept to the
same "only the socket-holder touches the socket" discipline as `deploy_launcher`.
It is a standalone service (its own container), the **sole holder of the
container-runtime socket for these ops**, with **no gateway ingress** — reachable
only by the proxy on the internal network, authenticated by a shared `X-Ops-Token`,
and refusing any container name outside the `mcp-`/`lab-mcp-` allowlist (fail-closed).
The proxy side (`routers/admin_ops.py`) never touches the socket: it authorizes,
derives the target container **server-side** from `server_registry.upstream_url`
(never from client input — see INV note on the confused-deputy review below),
and forwards. **restart/rebuild are platform_admin-only**; **logs** are
owner/maintainer + `debug_mode`-gated. Fail-closed: if the ops-agent is unset or
unreachable every endpoint returns 503, never a direct podman fallback. `rebuild`
today recreates the image from its existing build context; a per-server
`git pull`-of-latest is roadmap (needs a repo-path mapping per server). See
`docs/spec/11-server-lifecycle-and-hardening-batch.md`.

**End-to-end acceptance (PRD-0005 R-4)**: `lab/tests/submission_lifecycle_e2e.sh` drives the whole
lifecycle over the real gateway — submit (alice) → automated scan (mcp_checker findings + both SBOMs)
→ segregation-of-duties (submitter self-approve → 403) → approve (carol, `security_reviewer`) →
`approved_pending_url` → reviewer SBOM download (12 assertions, all passing). The Codex-driven
generation half (author a server from the wizard answers + push) is a documented manual runbook
(`lab/tests/README-r4-codex.md`) because `codex mcp login mcp-gateway` is an interactive PKCE flow.

**Legacy direct-registration bypass (Codex review CR-08, be honest).** `POST /api/v1/servers`
(`routers/server_registry.py::register_server_self_service`) is a **second, older** onboarding path
that goes straight to an admin-approvable `pending` row — it never touches the scan pipeline above at
all. Historically it was gated only on the `server_owner` RBAC role, which ordinary self-service users
can hold (§6.5 notes self-service submitters normally hold `agent`/`user`, but nothing technically
prevented granting `server_owner` to a non-admin). That made it a real bypass around scan/review for
anyone with that role. Fixed: the role gate now also requires `admin`/`platform_admin` unless
`ALLOW_DIRECT_SERVER_REGISTRATION_FOR_NON_ADMIN=true` (default `false`) explicitly opts a trusted
lab/environment back into plain `server_owner` self-registration. **Still open** (tracked in
`00_AI/mcp-security-platform/Codex_review/Claude_status.md`, CR-08): there is no
`registration_source` column distinguishing `submission`/`admin_direct`/`trusted_internal`, and
discovery is not yet denied for a direct-registered server lacking scan evidence or an explicit
admin waiver — the role gate closes the main hole but the fuller audit trail from the issue's
implementation sketch is not built.

**SBOM at submission (analyst context)**: during the scan the platform parses declared dependencies
from repo manifests (`parse_sbom_components`, bounded/soft-fail) into `server_registry.sbom_components`
and **surfaces them on the submission review card** so the reviewer has a component inventory
immediately — before the signed per-tool CycloneDX SBOM (INV-006), which is only generated at
approval time. It also generates a full **CycloneDX SBOM via syft** at scan time
(`generate_cyclonedx_sbom`, `server_registry.sbom_cyclonedx`), downloadable from the review card
(`GET /api/v1/admin/submissions/{id}/sbom`). Both are **soft-fail** (a syft failure / absent binary
leaves the declared-dep inventory as the fallback) and display-only — never a gate.

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
- **Public-to-authenticated servers (PRD-0005 R-3)**: a per-server opt-in flag
  `server_registry.public_to_authenticated` lets **any authenticated principal** invoke a server
  without an explicit grant — but **only** a read-only one. This is not a wildcard entitlement and
  not a role bypass: the `check_entitlement` resolver grants `role='user'`, `reason='public_server'`
  **iff** the caller is authenticated AND the server is `status='approved'` (quarantine/suspended
  are denied first) AND `public_to_authenticated=true` AND `has_write_ops=false`. Write-op safety is
  double-enforced — a DB `CHECK (NOT (public_to_authenticated AND has_write_ops))` (`V053`) makes the
  unsafe state unrepresentable, and the resolver re-checks. Discovery keeps parity
  (`list_entitled_servers` includes public read-only servers). Only `lab-self-service` is seeded
  public. Admin toggle: `POST /api/v1/admin/servers/{id}/public` (409 on a write-op server), audited.
  *Follow-on: thread `reason='public_server'` into the invoke audit event (today it is on the
  discovery/catalog response + an INFO log).*
- **Anomaly heuristic scoped too coarsely, `ping` unconditionally exempted (lab, 2026-07-11 —
  PRD-0008 R-3/R-4)**: the anomaly scorer's "rapid invocations" pattern counted total calls in a 5-min
  Redis sliding window with no distinction between `tools/list` (discovery, no side effects) and
  `tools/call`, and no per-tool distinction — a 9-call parallel discovery sweep tripped
  `anomaly_threshold_exceeded` and denied every subsequent tool-registry call for the rest of the
  session, including liveness checks, because every retried/polling call itself re-entered the same
  window before OPA was even evaluated (self-sustaining, no observed recovery). What looked like a
  separate entitlement bug on `self-service-mcp`/`plan_mcp_server`/`check_submission_status` (denied
  despite `enabled_for_your_profile: true`) turned out to be this same anomaly deny, not a distinct
  rule — verified via direct OPA eval that all three produce `allow:true` under the caller's real
  role/grant state once `anomaly_score` is not elevated. Fixed in `authz.rego`: `ping` (a pure
  liveness probe with no data-access or side effects) is now unconditionally exempt from the
  `anomaly_threshold_exceeded` deny — still subject to every other deny rule (quarantine, entitlement,
  grants, risk ceiling). The underlying scorer (`proxy/app/services/anomaly.py` — not distinguishing
  `tools/list` from `tools/call` in the window count) is **not yet fixed**; tracked as an open
  follow-on, not a roadmap item to lose track of.
- **On-behalf-of trust bridge for self-service submission ownership (lab, 2026-07-11 — T2)**:
  `lab-mcp-self-service`'s `submit_mcp_server` tool always calls the submissions API
  (`routers/submission.py`) with its own service credential (`client_id="lab-self-service"`,
  `auth_method=api_key`) — it never receives the real caller's session token, because
  `injection_mode=passthrough` only forwards a client-supplied `X-Downstream-Authorization` header
  (§5.3 / `docs/spec/02-credential-broker.md` §3.2), which no normal MCP client sends. Without a
  bridge, every self-service submission's `server_registry.owner_sub` was silently attributed to the
  service account instead of the submitting user. Fix: the submissions router accepts an explicit
  `X-On-Behalf-Of: <sub>` header, honoured **only** from a caller already authenticated via the
  normal HMAC-hashed API-key/OIDC/mTLS resolution in `middleware/auth.py` **and** holding the
  dedicated `submission_service` role — a small DB-backed allowlist (`role_assignments`) granted
  only to `lab-self-service` (`lab/seeder/seed.py`). This mirrors the identical cross-principal
  delegation `routers/profiles.py` already uses (`profile_service` role /
  `_assert_may_write`/`_assert_may_read`) for the same "proxy is the trust anchor, the downstream
  MCP server is not" problem — no new crypto primitive was introduced; the trust already comes from
  the platform's existing authenticated-identity + role-grant machinery. A caller presenting
  `X-On-Behalf-Of` **without** the role is rejected with 403 (fail closed), not silently ignored —
  see `routers/submission.py::_effective_owner`. This does **not** touch the `passthrough` mode or
  its documented security boundary; no other caller's behaviour changes. *Reference:
  `routers/submission.py::_effective_owner`, `lab/mcp-servers/self-service/server.py::_oauth_headers`,
  `lab/seeder/seed.py::seed_self_service_api_key`.*

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

### 6.7 Wizard Prompts panel (in-platform, admin-only)

The self-service submission wizard's per-mode design questions ("list every action…", "which
scopes…") default to code (`services/scaffold_generator.py` `_PROMPTS`/`_SHARED_PROMPTS`) but are
**admin-overridable at runtime**. `wizard_prompts` (`V052`) stores only overrides — an absent row
means "use the code default" (same NULL/absent-means-default convention as `client_limits`).
`services/prompt_store.py` overlays overrides on defaults at a single read choke point,
`prompts_for_mode()`, which both `GET /api/v1/submissions/{id}/prompts` and `GET /api/v1/design-assist`
call; a 30s cache bounds the DB read. **Endpoints** (`routers/admin_prompts.py`, gated
`admin`/`platform_admin`): `GET /api/v1/admin/prompts`, `PUT /api/v1/admin/prompts/{key}`,
`DELETE /api/v1/admin/prompts/{key}` (reset to default). **UI**: a new "Wizard Prompts" admin nav tab
(`portal.py::fragment_admin_prompts`), prompts grouped by auth mode with Save / Reset-to-default and
an "overridden" badge. Mutations flow through the HMAC-signed admin audit chain.

---

## 7. Observability & audit

- `mcp-audit-logger` emits one **SHA-256-hashed** event per invocation; raw tool arguments are never
  persisted (hashes only); redaction is unit-tested (`test_redaction.py`). In **production** events are
  additionally **HMAC-signed** (`AUDIT_LOG_HMAC_KEY` forced at startup).
- Events flow stdout → Promtail → Loki → Grafana; Alertmanager for alerting; MinIO for archival
  (Object-Lock **GOVERNANCE** retention — note: not tamper-proof WORM, see ROADMAP).
- A daily `compliance-checker` samples the audit trail for integrity.
- **2026-07 (CR-17/WP-D1): `/metrics`** (Prometheus format, `prometheus_client`) is exposed on the
  proxy, `scanner-worker`, and `build-worker` — authz allow/deny decisions, OPA/Vault reachability,
  credential-broker failures, audit-emit failures, scan-queue depth by status, dead-letter count,
  quarantine backlog, stale-scan count. A Prometheus instance (`observability/prometheus/`) scrapes
  all three over a dedicated read-only `metrics-net`; alert rules fire on hard invariants (OPA/Vault
  unreachable, audit-emit failure, scanner dead-letter, stale scans, rising deny rate) with
  thresholds explicitly labeled `initial_default: "true"` (no production reference environment
  exists yet to calibrate against — see D4 in the platform-finalisation PRD). Grafana dashboard
  `wp-d1-observability` (provisioned, `lab/grafana/provisioning/dashboards/`) covers the submission
  funnel, scan queue, quarantine backlog, invocation denies, and credential failures. A synthetic
  end-to-end probe (`lab/scripts/synthetic_probe.py`, `make -f Makefile.lab lab-probe`) runs
  login → low-risk invoke → audit-emission check. 9 runbooks live under `docs/runbooks/` (Vault
  init/unseal, OPA bundle signing, Keycloak client setup, git provider setup, private CIDR
  allowlisting, scanner failure, quarantine release, audit restore, incident triage), each verified
  against the live lab, not written from memory.
- **Stale DB gauges from a bind-parameter type mismatch (lab, 2026-07-11 — PRD-0008 R-8)**:
  `services/metrics.py::refresh_db_gauges` built its rescan-staleness interval with
  `(:hours || ' hours')::interval`, a string-concat that forces asyncpg to expect a `str` bind for
  `:hours` even though `settings.RESCAN_INTERVAL_HOURS` is an `int` — every scrape logged
  `asyncpg.exceptions.DataError` and left `mcp_stale_scan_count` etc. stale rather than updating.
  Fixed with `make_interval(hours => :hours)`, which takes the int directly.
- **`lab-mcp-grafana` unhealthy (no wget/curl in the image), and Promtail's catch-all job was
  blocking ALL Loki ingestion (lab, 2026-07-11 — PRD-0008 R-6/R-9)**: two independent observability
  bugs. (1) `podman-compose.lab.yml`'s `lab-mcp-grafana` healthcheck ran `wget -qO- http://localhost:8000/mcp`,
  but the `grafana/mcp-grafana:0.14.0` image ships neither `wget` nor `curl` — the probe exited 127
  every time, the container sat permanently `unhealthy`, and the proxy never registered its tools
  (`grafana-query` → "tool not found"), even though the MCP server itself was serving fine. Fixed by
  replacing the probe with a bash `/dev/tcp` HTTP GET that asserts a `200` response, no external
  binary required. (2) Promtail's `lab-other` catch-all job used relabel `action: drop` to exclude
  the per-service-labeled containers from double-scraping — but `docker_sd` keeps tailing dropped
  targets and ships them with **zero labels**, and Loki 400s an entire batch (all-or-nothing) the
  instant it contains even one label-less stream. That meant `promtail_sent_entries_total` was
  **flat at zero** — no log ingestion was reaching Loki at all, for any container, which is the real
  reason the five Loki-backed Grafana alert rules (`mcp-opa-unavailable`, `mcp-high-latency`,
  `mcp-high-deny-rate`, `mcp-compliance-failed`, `mcp-critical-tool-registered`) were stuck `NoData` —
  not a labeling gap on one stream, a total ingestion outage. Fixed by moving the exclusion from a
  relabel-stage drop (pre-label, produces empty streams) to a `pipeline_stages` `match`+`drop` on
  the log **entries** (post-relabel, so excluded containers' logs are dropped with their labels
  intact rather than shipped label-less) — verified `sent_entries` climbing from 0 to ~58k with real
  per-container line counts in Loki afterward. **Residual, deliberately not changed**: the five
  alert rules still read `NoData` in a quiet lab — each is a rare-event
  `count_over_time(...) > N` query with `noDataState: NoData` explicitly set
  (`observability/.../mcp-alerts.yml`), and `count_over_time` legitimately returns empty (not `0`)
  when the event hasn't occurred in-window. The Loki datasource itself is proven healthy (all five
  now query real data over HTTP 200); making them show "Normal" while quiet instead of "NoData"
  would need `or vector(0)` added to each query — that's an alert-rule authoring choice, not a
  data-pipeline bug, and is intentionally left to whoever owns alert-rule design.
- **`compliance-checker` couldn't verify its own audit-hash integrity, and its alert webhook was
  unreachable (lab, 2026-07-11 — PRD-0008 R-7)**: two independent bugs in the same container. (1)
  `docker-compose.yml` built it with `context: ./observability/compliance-checker`, so its Dockerfile
  could never `COPY` the sibling `observability/mcp-audit-logger` package (outside the build
  context) that `checker.py`'s `verify_hash_integrity()` imports as the shared canonicalizer — fixed
  by building from the repo root instead (`context: .`), matching the `proxy` service's own pattern,
  and installing `mcp-audit-logger` into the image the same way. (2) `COMPLIANCE_ALERT_WEBHOOK` is
  injected as `${COMPLIANCE_ALERT_WEBHOOK:-}`; when unset in `.env.lab` this resolves to an
  **empty-but-present** env var, and `os.getenv(key, default)` only falls back to `default` when the
  key is *absent* — so the checker used `""` as the webhook URL and httpx rejected it at alert-send
  time. Fixed with a `_normalize_webhook_url()` validated at import time (collapses empty values to
  the documented default, adds a scheme to a bare `host:port`, raises loudly if still unusable) —
  fails at startup now, not silently when a real compliance failure needs to alert.
- **Lab tool-registry hygiene (2026-07-11 — PRD-0008 R-5 / Appendix)**: `lab-mcp-wazuh` crash-looped
  on every restart (`TypeError: issubclass() arg 1 must be a class`) because `server.py` carried
  `from __future__ import annotations` (PEP 563 — stringifies annotations at runtime), which the
  pinned `mcp==1.9.4` SDK doesn't resolve before doing `issubclass(param.annotation, Context)` at
  tool-registration time; removed the import (it was the only one of 11 lab MCP servers using it —
  confirmed an outlier, not a pattern others depend on). Its healthcheck also 404'd after the crash
  fix (`POST /mcp` 307-redirects to `/mcp/`, and `urllib.request` doesn't auto-follow 307/308 on
  POST) — fixed by adding the trailing slash in `compose.wazuh.yml`. Separately, `echo` and three
  `echo-superseded-*` `tool_registry` rows pointed at acceptance-test fixture containers
  (`at3`/`at4-clean-mcp-fixture`) that aren't part of the standing lab stack — leftover state from
  test runs whose teardown never cleaned up the registry, causing SSRF-blocked DNS failures on every
  call. Soft-deleted (`status='deprecated'`, `deleted_at`, audited) rather than standing up throwaway
  fixture containers, since the naming (`echo-superseded-<uuid>`) is clearly ephemeral-test in origin.

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
is IP-gated defense-in-depth; the anomaly detector is an advisory heuristic, not a learned model, and
(per §6's R-4 note) its rapid-invocation window still doesn't distinguish `tools/list` discovery from
`tools/call` invocation — `ping` is exempted at the OPA layer but the scorer itself isn't fixed yet;
per-tool rate limiting is **(roadmap)**. Per-server network isolation for the platform-managed
deploy path now exists (CR-01/WP-B3's `deploy_launcher.py`, one isolated network per launched
server) — the self-hosted `provide-url` path still relies on the submitter's own infrastructure
isolation, unchanged.

---

## 9. Status & roadmap

Current per-control status is the [README Enforced-vs-Roadmap table](../README.md#enforced-today-vs-roadmap).
Notable **(roadmap)** items: SPDX SBOM, outbound Jira, Helm/K8s (compose remains the only
supported production deployment target — D3), learned anomaly baseline, Jira Cloud `cloudId`
resolution (adapter exists, per-D2 fast-follow), real `buildah`/registry integration for the
CR-01 build pipeline (stubbed with a named upgrade path, see §5.5), per-tool rate limiting.
2026-07's platform-finalisation program closed CR-01 through CR-19 (see
`Codex_review/Claude_status.md`) — the server-owner onboarding wizard and per-server network
isolation items previously listed here are done, not roadmap.
`docs/prd/PRD-0008-gateway-functional-sweep-bugfixes.md` (2026-07-11) closed a full-gateway
functional sweep's R-1 through R-9 plus its Appendix (OIDC token exchange, tool-wrapper dispatch,
anomaly scoring, `lab-mcp-wazuh`, `lab-mcp-grafana`, Promtail/Loki ingestion, `compliance-checker`,
metrics gauges, stale fixture cleanup — each cross-referenced at its section above). All nine items
are fixed and verified live as of this update; see the PRD for the one deliberately-left-open item
(alert-rule `NoData`-vs-`vector(0)` design, noted in §7 above).

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
| INV-005 | Quarantined tools cannot be invoked by any role (incl. admin), denied pre-OPA | `services/invocation.py`, `routers/mcp_server.py::_handle_invoke_tool_real` |
| INV-005 (fixed bypass) | The `invoke_tool` meta-tool's `tools/call` sub-dispatch (`{tool_name: 'ping', method: 'tools/call', arguments: {name: 'slow_tool'}}`) used to resolve a quarantined sub-tool's missing-from-the-active-only-query row as "doesn't exist" and silently fall back to the OUTER active tool's identity for every gate (entitlement, OPA) — dispatching the quarantined tool's name to the upstream anyway while authorizing as the active one. Fixed (Codex review CR-18, commit `8d83346`): a quarantined/deprecated/disabled lookup_name row is now checked and denied explicitly, before the fallback logic can ever see it. | `routers/mcp_server.py::_handle_invoke_tool_real` |
| INV-006 | Every registered tool has an HMAC-signed SBOM; no `active` status without a valid signature. Releasing from `quarantined` (Codex review CR-07) additionally requires the parent `server_registry` row to be `status='approved'` with `scan_status` passed — a bare admin cannot release a tool whose server is still pending or whose scan failed/blocked, closing the "generic PATCH bypasses release evidence" gap. **Open**: no dedicated `POST .../release` endpoint, `released_by`/`released_at` columns, or distinct `TOOL_RELEASED` audit event yet — this is enforced inline in the existing PATCH path (`routers/tools.py::update_tool`). | `services/sbom.py`, `routers/tools.py::update_tool`, DB constraint |
| INV-007 | Audit archive bucket has Object-Lock (≥GOVERNANCE, 90d); no app/API/Make path may delete it | `compliance-checker/checker.py`, `setup-minio.sh` |
| INV-008 | No secret value in any git-tracked file (`.env.example` placeholders only) | trufflehog in CI / `make security-check` |
| INV-009 | `/tools/{id}/invoke` requires mTLS cert or API key or OIDC JWT; unauthenticated ⇒ 401 before app logic. Lab: `:8443` forwards to the app (no cert requested there) and the app's auth chain gates it; the dedicated `:8445` listener (see §2 mTLS listener split note) is the only path that still enforces a client cert at the gateway. Production: still one listener, `ssl_verify_client optional` scoped by the `$ssl_client_verify` check inside the location block — same "cert OR app-layer auth" behavior. | gateway `ssl_verify_client` + auth middleware |
| INV-010 | mTLS client certs have ≤24h TTL | step-ca provisioner config |
| INV-011 | Only the `proxy_app` DB role may write registry/audit/credential tables; only `compliance_checker` writes `compliance_reports` | PostgreSQL grants (`V003`/`V009`) |
| INV-012 | Signed OPA bundles in staging/production (HS256 `--verification-key`); **signed is the default**. No tier's OPA command may carry `--scope=write` — `opa build` (the repo's only signing tool) cannot embed a `scope` claim, so it always produces `scope=None` and OPA rejects the flag with "scope mismatch" (crashloop). `docker-compose.yml` had already dropped the flag; `compose.engine.yml` had drifted and still carried it (Codex review CR-15, fixed) — check any new compose tier's OPA command against this before adding it. | `docker-compose.yml`, `compose.engine.yml`, `check_signed_default.sh` |
| INV-013 | Every brokered credential is AES-256-GCM envelope-encrypted under a per-user HKDF-SHA256 KEK (≥256-bit master), keyed on the **authenticated** identity, with a synchronous lifecycle audit | `credential_broker/{kms,approaches/approach_a}.py` |
| INV-014 | Session-JTI revocation **fails closed** — any Redis/DB error ⇒ deny (never allow a revoked token) | `middleware/auth.py::_is_session_jti_revoked` |
| INV-015 | MCP-profile lookup **fails closed** — DB error + cache miss ⇒ 503, never an empty (unrestricted) profile | `services/invocation.py::_lookup_profile_with_cache` |
| INV-016 | A **named profile** (session-bound via `?profile=` at OIDC login — the access-*restriction* mechanism) is an **allowlist**: once it has *any* binding row, a tool with no explicit row is **denied** (`{"enabled": false}` synthesized → `mcp_disabled_for_profile`), not default-allowed. A profile with zero bindings still allows all (an unconfigured profile is not silently a deny-all). The "does this profile have any binding" check itself fails closed (DB error + no cache ⇒ 503). The legacy per-identity profile path (no `profile_uuid`) is unchanged — default-allow. | `services/invocation.py::_named_profile_has_any_binding` |
| INV-017 | The isolation gate (`scripts/check_network_isolation.py`, `make security-check`) **fails if OPA (`:8181`) or any MCP backend publishes a host port** under the default lab-up compose layering — a comment that removes a port cannot be trusted when a later merged file re-adds it, so the invariant is machine-checked, not documented. Preserves "no backend invocation bypasses the shared invocation path" against same-host loopback re-exposure. | `scripts/check_network_isolation.py` |

Identity anti-spoofing (P1-1): an OIDC email is only used as the identity key when the IdP asserts it
**verified** (`verified_oidc_identity`); with realm `verifyEmail=true`, a changed email is unverified
until re-proven, so a user cannot rename their email to a privileged identity. Machine
(client_credentials) tokens cannot perform human-only self-service profile mutation (P1-2).
