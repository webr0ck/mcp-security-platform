# External System Integrations Specification

**Status: matches code at HEAD (`4dfa7b5`).**

This document specifies every external system the MCP Security Platform integrates with, so the platform can be re-implemented in any language against equivalent components. For each system it states its **role**, **interface/protocol**, **required configuration**, **failure behaviour** (fail-open vs fail-closed and why), and **what a re-implementer must provide**. **MUST/SHOULD/MAY** are RFC 2119; `(roadmap)` marks items not yet enforced/wired per the [README Enforced-vs-Roadmap table](../../README.md#enforced-today-vs-roadmap); *Reference:* points at code.

---

## 1. Identity & policy plane

### 1.1 Keycloak 24 — primary OIDC IdP

- **Role:** issues user identity (browser PKCE login), realm roles, service-account tokens, and RFC 8693 token-exchange tokens; also the Grafana SSO IdP. *Reference: `routers/oidc_browser.py`, `credential_broker/keycloak_client.py`.*
- **Interface:** OpenID Connect. Browser login MUST use Authorization Code + **PKCE S256**; the proxy stores KC tokens **server-side only** and issues an HttpOnly session cookie with a session JTI. External callers MAY present a KC access token as `Authorization: Bearer` (fallback path) — the proxy MUST validate `iss` and (in production) `aud`. *Reference: README OIDC-login row; `middleware/auth.py`.*
- **Realm model:** a realm (`lab/keycloak/realm-mcp.json`) defines clients and realm roles (`admin`, `agent`, `auditor`, `security_reviewer`, `readonly`, …). KC realm roles MUST be translated to **platform** RBAC roles via an explicit allowlist (`oidc_browser.py::_ROLE_MAP`); an unmapped KC role MUST be silently dropped (fail-closed — an IdP role can never grant platform access without a code change). *Reference: ARCHITECTURE §6.5.*
- **DCR:** the platform MUST accept Dynamic Client Registration (`POST /oauth/register`) returning a public `client_id` (no secret) for zero-config MCP clients.
- **Token exchange:** service-account (`client_credentials`) and subject token-exchange (grant `urn:ietf:params:oauth:grant-type:token-exchange`) MUST be supported for `service_account`/`kc_token_exchange` injection. Tokens cached in Redis (`expires_in − 30s`). *Reference: `keycloak_client.py`.*
- **Failure:** JWKS fetch failure on an exchanged-token verify MUST fail closed (abort injection). Session-JTI revocation MUST fail closed (INV-014). A re-implementer MUST provide any OIDC IdP supporting PKCE S256, DCR, client_credentials, and RFC 8693.

### 1.2 Dex — secondary/mock IdP (lab)

- **Role:** second OIDC IdP in the lab, used both as a Keycloak alternative and as an Approach-A OAuth upstream (`dex-calendar` enrollment). *Reference: `credential_broker/adapters/dex.py`.*
- **Interface:** standard OIDC Authorization Code + PKCE S256. Auth URL uses the browser-facing issuer; token URL uses an internal issuer so the proxy container can reach Dex directly. `response_mode` MUST NOT be sent (MSAL/Entra extension, unsupported by Dex). `refresh_token` MUST be read with `.get()` (Dex omits it without `offline_access`).
- **Failure:** token-endpoint errors MUST raise `TokenExchangeError` (status only, no body). **Re-implementer:** any spec-compliant OIDC provider.

### 1.3 OPA (Open Policy Agent) — authorization sidecar

- **Role:** deny-by-default authorization for every tool invocation; also the static tool-manifest risk scorer (`tool_risk.rego`). *Reference: `services/policy.py`, `services/auditor.py`, `policies/rego/`.*
- **Interface:** HTTP to the OPA sidecar (`http://opa:8181`). Grants (`client_grants`) are **DB-authoritative** and MUST be pushed to OPA's **data API** on every mutation; `data.mcp_grants` evaluates per-tool allow-lists at invocation. *Reference: `services/opa_data_sync.py`, `routers/admin_grants.py`.*
- **Required config:** signed bundles are the **default** — `docker-compose.yml` runs OPA with `--verification-key` + `--verification-key-id` + a read-only `bundle.tar.gz`; `make security-check` gates it (INV-012). *Reference: `docker-compose.yml` lines ~324-342, `scripts/check_signed_default.sh`.*
- **Failure (fail-closed, WHY = no invocation may bypass policy):**
  - OPA unreachable ⇒ **503 `OPA_UNAVAILABLE`**; a `null`/missing result MUST normalize to deny (INV-004). *Reference: `services/policy.py`.*
  - A grants **push failure MUST fail closed** — the mutation returns 503 and rolls back rather than diverging DB from OPA. A 60s reconcile loop plus a startup push MUST run. *Reference: `opa_data_sync.py` (`push_grants` raises `PolicyEngineError`; `start_reconcile_loop`).* Residual: a ~1-reconcile-interval deny window after an OPA restart before the first push completes **(roadmap-tracked)**.
- **Re-implementer:** any policy engine with deny-by-default eval, a pushable data document, and signed-policy verification.

---

## 2. Data & secrets plane

### 2.1 HashiCorp Vault — KMS (master secret only)

- **Role in the live path:** **KMS only** — supplies the credential-broker master secret. It is **NOT** used as AppRole/dynamic-secrets in the live path (despite lab tooling elsewhere). *Reference: `credential_broker/kms.py`.*
- **Interface:** Vault KV v2 read at `BROKER_MASTER_SECRET_PATH` (default `secret/data/mcp/broker-master`), header `X-Vault-Token`. Value stored under `master_secret` or `value`, hex or base64.
- **Required config:** `VAULT_ADDR` (MUST be `https://` outside development — rejected at config load otherwise), `VAULT_TOKEN` (empty ⇒ broker disabled), optional `VAULT_CA_BUNDLE` (TLS verification never disabled, CB-009).
- **Failure (fail-closed):** unreachable ⇒ `KMSError` ⇒ credentialed tools fail closed. Decoded secret `< 32 bytes` ⇒ `KMSError` (256-bit entropy floor). **Re-implementer:** any KMS/secret store returning a ≥256-bit master over TLS.

### 2.2 PostgreSQL 16 — system of record

- **Role:** server/tool registry, audit-event index, `credential_store`, `client_grants`, `role_assignments`, SBOM records. *Reference: `infra/db/migrations/`.*
- **Interface:** SQL over asyncpg/SQLAlchemy. The `server_registry` table is the **single source of truth** for backends (mcps.yaml deprecated); `registry.py` reads `status='approved' AND deleted_at IS NULL` with 30s auto-refresh. *Reference: `credential_broker/registry.py`.*
- **Required config / invariants:**
  - **INV-011 single-writer:** only `proxy_app` writes registry/audit/credential tables; only `compliance_checker_app` writes `compliance_reports` (SELECT-only for `proxy_app`). Enforced by GRANTs. *Reference: `V003__db_roles.sql`.*
  - **Append-only grants/roles:** `role_assignments` MUST forbid `UPDATE`/`DELETE` from the app role (V009); grant = INSERT active row, revoke = INSERT tombstone row (`revoked=true`); current state = latest event per `(client_id, role)`. *Reference: `V050__role_assignments_append_only_revoke.sql`, ARCHITECTURE §6.6.*
  - `client_grants` (V034) is the OPA-pushed per-tool allow-list table.
- **Failure:** MCP-profile lookup MUST fail closed — DB error + cache miss ⇒ 503, never an empty (unrestricted) profile (INV-015). Passwords set at container start, never in migrations (INV-008). **Re-implementer:** any RDBMS supporting per-role table GRANTs and append-only semantics.

### 2.3 Redis 7 — ephemeral state

- **Role:** OIDC session store, rate-limit counters, **enrollment nonces** (`oauth_flow:`, `enroll_consent:` — single-use, TTL 300s), pending OAuth/PKCE flows, and injection-token caches (`kc:sa:`, `kc:ex:`, `entra:cc:`). *Reference: `routers/oauth.py`, `credential_broker/{keycloak_client,dispatcher}.py`.*
- **Interface:** Redis commands; atomic get-and-delete for nonce consumption (`core/redis_atomic.py`).
- **Failure (mixed, by design):**
  - Rate-limit / registration path MUST fail closed (429 on Redis error).
  - Session-JTI revocation MUST fail closed (INV-014).
  - **Token caches MUST fail *open to a fresh fetch*** — Redis down ⇒ skip cache, fetch a new token (auth still works, just uncached). *Reference: `dispatcher.py::_inject_entra_client_credentials`, `keycloak_client.py`.* WHY: cache is a latency optimization, not an auth control; the token fetch itself is the control.
  - **Re-implementer:** any TTL KV store with atomic get-del.

### 2.4 Ollama — advisory LLM manifest scorer (registration-time only)

- **Role:** at **tool registration only**, produces a semantic risk score blended with the static OPA score. It MUST NOT run on invocations. *Reference: `services/auditor.py`.*
- **Interface:** HTTP `http://ollama:11434`, model `OLLAMA_MODEL` (default `llama3.2`), JSON risk output, timeout `OLLAMA_TIMEOUT_SECONDS` (30s).
- **Failure (advisory, no silent downgrade):** Ollama unreachable ⇒ `llm_unavailable=True` and the score re-weights to **1.0× static** (no silent fail-open). If `REQUIRE_LLM_AUDIT=true` (forced in production by config) the registration router MUST return **503** and insert no DB row. Invocations are unaffected. *Reference: `auditor.py::run_llm_analysis/run_audit`, `LLMAuditUnavailableError`.* **Re-implementer:** any LLM endpoint returning a 0-100 score, plus the fail-closed-in-prod gate.

---

## 3. Edge, transport & observability

### 3.1 step-ca — internal mTLS CA

- **Role:** issues short-lived mTLS certs for the gateway↔proxy trust plane (lab/dev). *Reference: `gateway/step-ca/`.*
- **Required config:** cert TTL MUST be ≤24h (INV-010), `STEP_CA_MAX_TLS_DURATION=24h`. *Reference: `docker-compose.yml` line ~202, `.env.example`.*
- **Failure:** cert issuance failure blocks the mTLS handshake at the gateway (fail-closed at edge). **Re-implementer:** any ACME/internal CA enforcing ≤24h TTL.

### 3.2 Wazuh — SIEM syslog sink (lab)

- **Role:** lab SIEM; the `wazuh` mock MCP server + syslog feed model a downstream SOC/detection consumer of audit events (e.g. the stolen-SA-token incident). *Reference: `lab/mcp-servers/wazuh/`, `lab/wazuh/`, `lab/incidents/`.*
- **Interface:** syslog/opensearch. **Failure:** best-effort (observability, not an enforcement control). **Re-implementer:** any SIEM ingesting the JSON audit stream.

### 3.3 Loki / Promtail / Grafana / Alertmanager / MinIO

- **Role:** audit pipeline + archival. Covered normatively in the logging/observability spec — **cross-reference only** here. Summary: audit events flow stdout → Promtail → Loki → Grafana; Alertmanager alerts; MinIO archives with Object-Lock GOVERNANCE (≥90d, INV-007; not tamper-proof WORM — roadmap). Grafana SSO is via Keycloak. *Reference: ARCHITECTURE §7.*

### 3.4 Jira — inbound webhook only

- **Role:** external approval signal — a Jira issue transition can activate a quarantined tool. **Inbound only; outbound Jira is (roadmap).** *Reference: `routers/integrations.py`.*
- **Interface:** `POST /api/v1/integrations/jira/webhook`, authenticated by the **`X-Jira-Webhook-Secret`** shared secret verified HMAC-style (`core/security.verify_jira_webhook`) — **not** RBAC. Payload: `issue.key` + `issue.fields.status.name`.
- **Behaviour (MUST):** disabled ⇒ 503 (`JIRA_ENABLED=false`); bad secret ⇒ 401; malformed ⇒ 422. On an approval status (`done|approved|resolved`) it activates the linked quarantined tool **only if a signed SBOM exists** (INV-006) and emits a synchronous `TOOL_STATUS_CHANGED` audit on a separate connection (INV-001; audit failure = hard error). **Re-implementer:** any webhook source with a shared-secret HMAC and the SBOM-gated activation check.

---

## 4. Backend MCP servers (the protected assets)

- **Source of truth:** the `server_registry` DB table (mcps.yaml deprecated). A server is reachable only at `status='approved'`; a `pending`/`draft`/`suspended` row silently yields no entitlement. *Reference: `registry.py`, `docs/mcp-server-onboarding.md` §3.*
- **Registry granularity (MUST pick one per server):** Pattern A = one `tool_registry` row per callable function (independent OPA/quarantine/risk); Pattern B = one row for the whole server, sub-tools discovered live via `tools/list` proxying and invoked as `tool_name=<server>, arguments.name=<subtool>`. Mixing them breaks discovery/entitlement. *Reference: onboarding §2.*
- **Onboarding pipeline (normative steps, summarizing `docs/mcp-server-onboarding.md`):**
  1. Create a `server_registry` row (self-service `POST /api/v1/servers` or admin path); status starts non-approved.
  0. **Wizard design prompts are admin-editable.** The self-service wizard's per-mode design questions ("list every action…", "which scopes…") default to `scaffold_generator._PROMPTS`/`_SHARED_PROMPTS` but may be overridden at runtime via the **Wizard Prompts** admin tab (`admin` / `platform_admin` only). Overrides persist in `wizard_prompts` (absent row = code default) and are applied at the single read choke point `prompt_store.prompts_for_mode()`, which both `GET /api/v1/submissions/{id}/prompts` and `GET /api/v1/design-assist` call. Edits take effect within a 30s cache TTL, no redeploy. *Reference: `services/prompt_store.py`, `routers/admin_prompts.py`, `portal.py::fragment_admin_prompts`, migration `V052`.*
  1a. **Automated submission scan — isolated worker + queue (CR-14 / WP-B1).** Untrusted clone + scanner execution runs OUT of the proxy container, in a separate unprivileged `scanner-worker` service, holding no proxy secret (no DB-admin creds, no Vault token, no gateway shared secret). The proxy only **enqueues** a `scan_jobs` row (`services/scan_queue.py`) on any submission carrying a GitHub repo URL and, separately, on the periodic rescan sweep (`services/rescan_scheduler.py`). `scanner-worker` (`scanner_worker/worker.py`, its own container/image) claims queued jobs (`SELECT … FOR UPDATE SKIP LOCKED`), clones the repo, and runs the scanners: **trufflehog** (verified secrets), **pip-audit** (Python-dep CVEs), **custom regex rules** (`scan-config.yaml`), and the vendored **mcp_checker** engine (malicious code patterns, tool poisoning, per-OS attack patterns, SSRF/IMDS, crypto stealers, obfuscation, MCP-specific semgrep SAST). It writes **RAW findings only** to `scan_raw_results` — it structurally cannot write a verdict: its DB role (`scanner_worker_app`) has no grant whatsoever on `server_registry` and is INSERT-only on `scan_raw_results` (no SELECT/UPDATE/DELETE), plus UPDATE limited to its own claim/heartbeat/attempt columns on `scan_jobs` (`infra/db/migrations/V063__scanner_worker_queue.sql`). A trusted **evaluator** running inside the proxy (`services/scan_evaluator.py`, a background loop that never touches attacker-controlled repo content — only the structured JSON the worker already produced) reads `scan_raw_results`, applies the UNCHANGED policy (a FAIL in a `block_checks` check blocks the submission; any other FAIL is a warning; a scanner binary/tool that could not run, a worker crash, or a dead-lettered job all fail **closed** to `scan_status='error'`, never `passed`), and drives `server_registry.scan_status`/`submission_status`. Failed jobs retry up to `max_attempts` (default 3) before landing in `status='dead_letter'` — visible via `scan_queue.dead_letter_jobs()`, never silently dropped; the evaluator maps a dead-lettered job with no raw result to `scan_status='error'` so a submission is never stuck in `scan_running` forever. Idempotent: re-enqueuing the same `(server_id, github_url)` while a job is queued/running returns the existing job unless `force=true` (DB-enforced via a partial unique index). Egress from `scanner-worker` is restricted to configured git-provider hosts + PyPI (the allowlisting squid proxy already used for `lab-mcp-m365`, extended — `lab/egress-proxy/squid.conf`); it has its own narrowly-scoped git clone token(s), never the proxy's `platform_secrets`/`credential_store`. The scan gate is a pre-filter only — a `passed` scan moves the submission to `awaiting_review`, it does **not** approve it; human review remains mandatory. *Reference: `scanner_worker/` (worker + scan engine + `README.md`), `services/scan_queue.py`, `services/scan_evaluator.py`, `infra/db/migrations/V063__scanner_worker_queue.sql`, `scan-config.yaml`, `proxy/vendor/mcp_checker/VENDORED.md`. Legacy in-proxy exec code remains in `submission_scanner.py` as dead code (unreferenced by any live path) — see its module docstring.*
  1b. **Multi-ecosystem dependency-CVE gate (CR-12 / WP-B2), built on top of 1a's execution/adjudication split.** Three more scanner layers run inside the same `scanner-worker` alongside pip-audit (`scanner_worker/dependency_scanners.py`): **OSV-Scanner** (broad Go/npm/PyPI/etc. coverage via `osv-scanner --format=json --recursive`), **npm audit** (Node, `npm audit --json --package-lock-only` — deliberately NEVER `npm install`, which would execute the submitted package's own preinstall/postinstall scripts inside the worker), and **govulncheck** (Go reachability analysis, `govulncheck -json ./...`). All three, like pip-audit, write RAW findings only — `block` is always `false` from the worker for every dependency-CVE finding; the worker cannot decide policy because a single scanner layer doesn't have the full picture (pip-audit's own JSON output carries no severity at all, only a vuln_id). The **normalized finding schema** (`scanner, ecosystem, package, version, vuln_id, aliases, severity, cvss_score, fix_versions, source, reachable, direct_dependency, block, waiver_id, message`) is shared across all four dependency scanners. Policy now lives entirely in `services/dependency_policy.py` (imported by `scan_evaluator._decide_status`), which: (a) **alias-collapses** findings whose `vuln_id`/`aliases` identifier sets overlap (a CVE reported by both pip-audit — unknown severity — and OSV-Scanner — known CVSS — for the same package collapses to one group and inherits the known severity, never double-counts); (b) applies a **severity threshold** (`scan-config.yaml`'s `dependency_audit.block_on`, default `high`) — severity is read from advisory data only, **never inferred from fix-version presence**; `severity=unknown` (no scanner layer had real advisory data) is a fourth, distinct verdict, **`review_required`**, never a silent pass; (c) applies **waivers** (below). Two **fail-closed structural signals**, forced to `review_required` regardless of alias-collapse: a Node project with `package.json` but no `package-lock.json`/`npm-shrinkwrap.json` (npm audit cannot run deterministically without one), and a Go module that fails to load/build under govulncheck (**the core security property of this package**: a submitter can deliberately break their own `go.mod` to trigger this exact downgrade path, so "incomplete but treated as passing" would be an attacker-controlled fail-open — OSV-Scanner's independent, manifest-only `go.mod` parse remains the coverage floor when this happens). `scan_status` precedence is now **`blocked` > `error` > `review_required` > `passed`**; `review_required` routes to the same `awaiting_review` submission-status queue as `passed` (the review UI distinguishes them via `scan_status`, not `submission_status`). **Waivers** (`scan_waivers` table, `infra/db/migrations/V066__scan_waivers.sql`, service `services/scan_waivers.py`) are expiring, reviewer-authorized risk acceptances matched on **exact** `package`+`version`+`vuln_id` (never fuzzy/prefix — a waiver for one version never suppresses a different version of the same package). Integrity is DB-role-enforced provenance, not a cryptographic signature (no key custody problem to invent): `scanner_worker_app` has **zero grant** on `scan_waivers` (it executes untrusted content and must never author or even read a waiver); only `proxy_app` may `INSERT`/`SELECT`, with `UPDATE` narrowed to the revocation columns only (`revoked_at`, `revoked_by_principal_id` — a waiver's identity is otherwise immutable once written). Every waiver records a **typed principal** (`waived_by_principal_id/_type/_issuer`, the CR-10/WP-A1 pattern — never a bare subject) and emits an audit event on creation via the existing HMAC-signed chain (`admin_audit.emit_admin_config_event`). Waived findings are **never deleted** — they remain visible in the SBOM/review UI with `waiver_id` set; a waiver only suppresses `block`/`review_required` in the evaluator's decision. *Reference: `scanner_worker/dependency_scanners.py`, `services/dependency_policy.py`, `services/scan_waivers.py`, `infra/db/migrations/V066__scan_waivers.sql`, `scan-config.yaml` (`osv_scanner`/`npm_audit`/`govulncheck`/`dependency_audit` sections), `lab/egress-proxy/squid.conf` (added `api.osv.dev`, `deps.dev`, `registry.npmjs.org`, `proxy.golang.org`, `sum.golang.org`). **Known gap:** `POST /api/v1/admin/submissions/{id}/approve`'s scan-status gate (`routers/submission.py`) still only allow-lists `('passed', 'not_applicable')` — a `review_required` submission cannot yet be approved through that endpoint. Deliberately left unpatched this session: `submission.py` was under concurrent edit by the WP-A2 (OAuth/IdP policy) session; fold this one-line allow-list extension into the next patch that touches that file.*
  2. Generate a **CycloneDX SBOM**; it MUST be HMAC-signed — no `active`/approved status without a valid signature (INV-006). SPDX is **(roadmap)**.
  3. Run the registration-time **manifest audit** (static OPA + advisory Ollama, §2.4); high risk quarantines the tool.
  4. Register tools + **discover/quarantine** on registration.
  5. Create `entitlement` / `server_role_grant` rows. `principal_id` format MUST match exactly: `human:{OIDC_ISSUER_ID}:{sub}` (OIDC), `human:apikey:{client_id}` (API key), `agent:{MTLS_CA_ID}:{cn}` (mTLS) — a wrong prefix silently never matches.
  6. Keep backends **network-isolated**: each backend shares exactly one pairwise network with the proxy; a backend MUST NOT have an inbound route to `proxy:8000`. A backend that must call back the proxy REST API MUST be added to `PROXY_INGRESS_TRUSTED_HOSTS` (narrow exception, SEC-05) and MUST authenticate every such call. *Reference: onboarding §4, `middleware/ingress.py`.*
  - **Absence of an `mcp_profiles` row is default-ALLOW** (documented), and any display surface MUST default absent rows to enabled to match. *Reference: onboarding §3.*
- **Test fixture set:** 11 lab mock MCP servers under `lab/mcp-servers/`: `echo`, `gitea`, `grafana`, `lab-tickets`, `m365`, `netbox`, `notes`, `rag-assistant`, `search`, `self-service`, `wazuh`.

---

## 5. Client integration (zero-credential, URL-only)

- **Pattern:** an MCP client configures **only a URL**, no API keys: `{"type": "http", "url": "https://<host>:8000/mcp"}`. `type` MUST be `http` (Streamable HTTP), not `sse`; `url` not `command`. *Reference: README "Connecting Claude Code".*
- **What a client MUST support:**
  1. **OAuth protected-resource discovery (RFC 9728):** on 401 read `WWW-Authenticate: Bearer resource_metadata="…/.well-known/oauth-protected-resource"`. The `resource` field MUST be the **exact** resource URL (`https://host/mcp`, not origin-only), and a path-suffixed metadata variant MUST exist. *Reference: onboarding §6, `routers/oauth_metadata.py`.*
  2. **Authorization-server metadata (RFC 8414)** discovery of the Keycloak endpoints.
  3. **DCR** (`POST /oauth/register`) → public `client_id`.
  4. **Authorization Code + PKCE** browser login; then present the KC access token as `Authorization: Bearer` on subsequent calls.
- **Re-implementer (server side):** serve the two `.well-known` documents publicly (200 JSON), emit the RFC 9728 `WWW-Authenticate` challenge on the protected path, and accept DCR.

---

## 6. Real-service integration patterns (three reusable shapes)

Generalized from the vault-documented patterns; a re-implementer maps each new upstream to one shape:

1. **Delegated OAuth (M365-style):** per-user authorization-code + refresh; enroll once (`/auth/enroll/{service}`), store the encrypted refresh token, mint a fresh delegated access token per call. Approach A. Use for services with a per-user OAuth IdP (Microsoft Graph, Bitbucket, Dex).
2. **Token-per-user (NetBox-style):** the platform holds an admin token and provisions a short-lived per-user token via the service's admin API on demand. Approach B. Use for token-API services (NetBox, Grafana service accounts).
3. **Service-account / shared (Grafana-/Gitea-style):** a single shared service credential (static token or KC client-credentials) injected for all callers. `service`/`service_account` modes. Use where per-user identity to the upstream is not required.

*(See `docs/spec/02-credential-broker.md` for the crypto and mode mechanics behind each shape, incl. the current orphaned/roadmap status of the Approach-B path.)*

---

## 7. Discrepancies found (docs ↔ code)

1. `mcps.yaml` is referenced as deprecated in `registry.py`/`dispatcher.py` docstrings but `server_registry` is the actual source of truth — no live YAML read remains.
2. Vault is described broadly as "secrets/KMS" in the stack table, but the **live broker path uses it as KMS only** (master secret); AppRole/dynamic-creds language elsewhere (agent-memory, other labs) does **not** apply to this repo's live path.
3. `entra_client_credentials` reads its secret from the Vault-backed `credential_store` via `services/credential_storage.py` (nonce-only envelope, row-context checked in app code) — a different crypto helper than the `approach_a` salt+AAD path used by other modes (see broker spec §2 discrepancies).
4. Jira: only the inbound webhook exists; ARCHITECTURE §8.2 / API.md §2.10 are referenced but outbound Jira ticket creation is roadmap.
