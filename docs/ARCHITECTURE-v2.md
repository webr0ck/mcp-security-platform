# MCP Security Platform — Architecture v2 (Reality-Based + Secure Target)

**Version:** 2.0.0
**Date:** 2026-05-16
**Status:** Canonical. Supersedes `docs/ARCHITECTURE.md` v1.0.0 (stale: omits the credential broker, Vault, `credential_store`, OAuth router).

This document describes the system **as it actually is** (verified at source) and the **secure target state** (what must change before production). Every component is annotated with its real implementation status so this document cannot drift back into aspiration.

Status legend: ✅ implemented & wired · 🟡 partial/overclaimed · 🔴 stub/missing · 🆕 exists in code, was undocumented · ⚠️ security defect (see REVIEW-2026-05-16.md)

---

## 0. Current security status (2026-05-16)

**Phase 0 (security unblock): ✅ COMPLETE.** All CRITICAL/HIGH findings from `REVIEW-2026-05-16.md` are fixed and tested (79 unit + 9 MCP-client tests). The two CRITICALs (CB-001 broker identity collapse, CB-002 plaintext Vault key) and the HIGHs (CB-003/004/005, F-001, F-002 mechanism) are closed. **F-001 was additionally proven at runtime on the live podman lab** — a non-dialed sidecar that previously reached `proxy:8000` is now refused, with the proxy still healthy.

**Phase 1–3 complete (2026-06-10):** Signed OPA bundles default (INV-012), dispatcher fail-closed, JTI deny-on-error; server_owner persona + OPA authz.rego; entitlement CRUD + consent wiring; self-service server onboarding (POST /api/v1/servers); DB-driven server registry (mcps.yaml retired — dispatcher reads server_registry, 30s refresh); 4 integration modes wired (oauth_user_token, entra_client_credentials, user, service_account); OPA grants sync — role_assignments pushed via data API on mutation + 60s reconcile.

**Not yet done** (tracked in `ROADMAP.md`): Phase 4 (named profiles, multi-session, IdP-group entitlements) → Phase 5 (SIEM: Sigma→Loki ruler) → Phase 6 (per-server network isolation) → Phase 7 (UI onboarding wizard).

The §4.2 "secure target" items below are annotated ✅ where now implemented; the rest remain the forward plan.

---

## 1. Scope

Full-stack security reference implementation for MCP: a hardened ingress gateway, a semantic security proxy, a credential broker, and a compliance-grade observability stack. The "92% insecure MCP" framing is removed pending a citable source.

---

## 2. Component Diagram (as-built)

```
 External AI Agents / MCP Clients ──(TLS 1.3; mTLS on /api/v1/tools/ only)──┐
                                                                            ▼
┌──────────────────────────────── LAYER 1: GATEWAY ─────────────────────────────┐
│ Nginx 1.25  ✅  TLS1.3-only ✅  mTLS(tools) ✅  ModSec+custom JSON-RPC rules 🟡 │
│ rate-limit: per-client-CN + per-IP ✅  (NOT per-tool 🟡)  JSON access log ✅    │
│ X-Client-Cert-CN sanitized via map for non-tools paths ✅ (F-001 partial ⚠️)   │
└───────────────────────────────────────┬───────────────────────────────────────┘
                                         │ internal HTTP  (⚠️ proxy also on internal-net — F-001)
                                         ▼
┌──────────────────────────────── LAYER 2: SECURITY PROXY (FastAPI) ─────────────┐
│ Auth mw (mTLS CN / API key) ✅   RBAC mw ✅   Audit mw (sync, fail=500) ✅      │
│ Tool Manifest Auditor: OPA-static + Ollama LLM ✅ (fail-closed: 1.0×static on outage; REQUIRE_LLM_AUDIT prod gate) │
│ SBOM: CycloneDX 1.5 + HMAC-SHA256 ✅   SPDX 🔴(dead constant only)              │
│ Anomaly detector: fixed-rule sliding window ✅  (learned baseline 🔴)            │
│ Invocation: quarantine-gate(INV-005) ✅ → OPA eval ✅ → fail-closed 503 ✅       │
│ 🆕 Credential Broker: Vault-KEK envelope-encrypt (AES-256-GCM) ⚠️CB-001/2/7/8  │
│ 🆕 OAuth enroll router /auth/* ⚠️ (no nginx route; identity from spoofable hdr) │
│ Integrations: Jira inbound webhook ✅  Jira outbound 🔴  Artifactory ✅(gated)  │
│ OIDC routes 🔴 (HTTP 501 stubs)                                                 │
└──────────────────────────────────────┬─────────────────────────────────────────┘
        ┌──────────────┬──────────────┬─┴────────────┬───────────────┐
        ▼              ▼              ▼               ▼               ▼
   OPA sidecar ✅   PostgreSQL ✅   Redis ✅      Ollama ✅      🆕 Vault ✅(dev)
   (deny-default,   (registry,     (rate/session)  (LLM risk)    (KMS master
    fail-closed)     audit idx,                                    secret) ⚠️CB-002
                     credential_store 🆕)
                                         │ structured audit events (append-only)
                                         ▼
┌──────────────────────────── LAYER 3: OBSERVABILITY ────────────────────────────┐
│ mcp-audit-logger: SHA-256/event ✅  10-category redaction ✅(tested)            │
│ Loki+Promtail ✅(cfg)  Grafana dash+alerts ✅(cfg)  Alertmanager ✅(cfg)        │
│ MinIO Object-Lock GOVERNANCE 90d ✅ (NOT MFA-WORM as T3 claimed 🟡)             │
│ Compliance checker: daily 1000-sample, 10 categories ✅  (startup lock-verify 🔴)│
└────────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Service Catalogue (corrected — adds Vault)

| Service | Container | Tech | Status |
|---|---|---|---|
| Gateway | `gateway` | Nginx 1.25 + ModSecurity 3 | ✅ config |
| step-ca | `step-ca` | Smallstep | ✅ script (24h TTL enforced, untested) |
| Proxy | `proxy` | Python 3.12 / FastAPI | ✅ |
| OPA | `opa` | OPA ≥0.63 sidecar | ✅ (bundle signing 🔴 F-002) |
| Ollama | `ollama` | Ollama | ✅ |
| PostgreSQL | `db` | PG 16 | ✅ |
| Redis | `redis` | Redis 7 | ✅ |
| **Vault** 🆕 | `vault` | HashiCorp Vault | ✅ dev mode — **was undocumented in v1.0.0** |
| Loki/Promtail/Grafana/Alertmanager/MinIO | — | observability | ✅ config |
| compliance-checker | `compliance-checker` | Python cron | ✅ |

---

## 4. Trust Boundaries — current vs SECURE TARGET

### 4.1 Current (defective)

```
PUBLIC ──TLS/mTLS──> [gateway] ──internal HTTP──> [proxy]
                                                     │  ⚠️ proxy ALSO on internal-net
INTERNAL-NET: proxy, opa, ollama, redis, db  ◄───────┘  any sidecar can POST proxy:8000
                                                        and forge X-Client-Cert-CN  (F-001 OPEN)
VAULT-NET: proxy ⇄ vault   ⚠️ default http:// → master secret in cleartext (CB-002)
```

### 4.2 Secure target (required before prod)

1. **Proxy ingress isolation (fixes F-001) — ✅ IMPLEMENTED:** proxy is off the flat `internal-net` mesh and off `observability-net`. Inbound only via `gateway-net` (gateway/grafana) + `step-ca-net` (cert issuance). Egress via dedicated pairwise `proxy-{opa,ollama,redis,db}-net` + `vault-net` — each backend shares exactly one network with proxy, so a compromised sidecar can no longer traverse a shared mesh, and compliance-checker shares no network with proxy. Audit ships stdout→Promtail (docker.sock), so proxy needs no observability network. `internal-net` retained for backend peering + the podman-lab external-net contract. nginx already blanks `X-Client-Cert-CN` outside `/api/v1/tools/` via `$client_cert_cn_safe`. Regression-gated by `scripts/check_network_isolation.py` in `make security-check`.
2. **Identity source of truth (fixes CB-001) — ✅ IMPLEMENTED:** `user_sub` for the broker derives from `request.state.client_id` (AuthMiddleware: mTLS CN post-verification / API key) — **never** a raw inbound header. `/auth/enroll/*` is authenticated; `/auth/callback/*` is public but identity is recovered from the single-use server-side nonce, not headers. Real nginx `location /auth/` added.
3. **Vault transport (fixes CB-002/CB-009) — ✅ IMPLEMENTED:** `VAULT_ADDR` defaults to `https://`; model-validator rejects `http://` outside `development`; `VAULT_CA_BUNDLE`; `kms.py` explicit `verify`.
4. **OPA bundle signing (fixes F-002) — 🟡 MECHANISM DONE, NOT YET ENFORCED IN A RUNNING ENV:** `scripts/sign_policy_bundle.sh` + `make sign-policy-bundle` + `docker-compose.opa-signed.yml` (HS256, `scope=write`) deliver real signature verification for staging/prod. Still to do (ROADMAP P2.8): bring a staging stack up with the overlay and prove OPA rejects an unsigned bundle at runtime.
5. **Credential lifecycle is audited (fixes CB-004/CB-012) — ✅ ENROLL DONE:** enrollment emits a synchronous `CREDENTIAL_ENROLLED` audit event (RuntimeError-propagation). *Still to do:* same for refresh/revoke/delete + an audit-before-delete DB trigger.
6. **DB least privilege (fixes CB-005, INV-011 scope) — ✅ IMPLEMENTED:** `V009` grants `proxy_app` `SELECT, INSERT` on `role_assignments` and `REVOKE UPDATE, DELETE`. *Still to do (P1.6):* add `credential_store`/`role_assignments` to the written INV-011 scope text.

---

## 5. Critical Data Flows (corrected)

### 5.1 Tool invocation (accurate)
mTLS/API-key → nginx (TLS, WAF, per-CN rate, JSON log, sanitized CN header) → proxy auth mw → RBAC → quarantine gate (INV-005, pre-OPA) → anomaly window → OPA `allow` (fail-closed 503) → **if a tool requires a brokered credential, broker resolves & injects it into the upstream call** (🆕 undocumented in v1 §5.1) → upstream MCP server → synchronous audit event (SHA-256, redacted, 500 on emit failure) → response.

### 5.2 Credential enrollment (🆕 — was entirely undocumented)
Authenticated user → `/auth/enroll/{service}` → server-side random nonce stored in Redis (TTL 5m, keyed to authenticated identity) → redirect to IdP (M365/Bitbucket/Dex) with PKCE → IdP → `/auth/callback/{service}` → nonce verified & consumed → token exchanged → refresh token envelope-encrypted (AES-256-GCM, KEK = HKDF(master, authenticated user_sub)) → `credential_store` upsert keyed by *authenticated* identity → **synchronous `CREDENTIAL_ENROLLED` audit event** → done. (Target state; current code violates the bolded/italic parts — see CB-001/3/4/7.)

### 5.3 Credential broker resolution (🆕 implementation details)
**Triggered by:** `invoke_tool()` when tool config has `injection_mode != "none"` and broker_instance is not None.

**Flow (dispatched in `proxy/app/credential_broker/broker.py:resolve()`):**

1. **Approach B (Session Cache)** — default:
   - Check Redis for `(session_id, service)` token with non-expired `expires_at`
   - Hit: return immediately
   - Miss: fetch adapter for service (Keycloak, M365, Bitbucket, Grafana, NetBox, Dex)
   - Adapter calls OAuth2 client_credentials or refresh_token endpoint
   - Save to Redis with TTL; return token

2. **Approach A (Persistent Encrypted Refresh Token)** — for service accounts:
   - Read `credential_store` row by `(user_sub, service)`
   - Decrypt `encrypted_ref` blob:
     - **KEK derivation** (`proxy/app/credential_broker/approaches/approach_a.py:_derive_kek()`):
       - Fetch `master_secret` from Vault via `VaultKMSClient` (kms.py:40-59)
       - Vault path: `/v1/secret/data/{BROKER_MASTER_SECRET_PATH}` (e.g., `secret/data/mcp/broker-master-secret`)
       - ⚠️ **CB-002 OPEN**: format mismatch — lab seeders write HEX, kms.py tries base64 first
       - Extract random salt from blob (first 32 bytes)
       - HKDF-SHA256: `info = b"mcp-credential-broker-kek-v2:{user_sub}"`, length=32
       - Derive per-user KEK
     - Extract nonce (next 12 bytes)
     - AES-256-GCM decrypt: ciphertext checked against AAD binding `(user_sub, service, tool_id, owner_type)`
     - ✅ **CB-F004**: KEK bytearray explicitly zeroed after decryption (proxy/app/credential_broker/approaches/approach_a.py:74-75)
   - Use decrypted refresh_token to call adapter OAuth2 token exchange
   - Return fresh access_token

3. **Credential injection** (back in `invocation.py`):
   - Resolved token injected into upstream MCP call as `Authorization: Bearer <token>`
   - Token is **never** logged (INV-002 redaction: `[REDACTED:credential_ref]`)

4. **Master secret lifecycle** (`broker.py:51-67`):
   - Fetched once per TTL (default: 300s, settable `BROKER_MASTER_SECRET_TTL_SECONDS`)
   - Stored as bytearray to allow explicit zeroing (CB-008)
   - Refreshed on every batch of invocations after TTL expires
   - On startup (lifespan): `test_lifespan_broker.py` confirms broker_instance wires correctly; on shutdown: master_secret.bytearray is zeroed

**Security properties:**
- ✅ Per-user KEK: different user → different decryption key (no key reuse across identities)
- ✅ Per-cred salt: blob format includes random salt; same credential encrypted twice → different ciphertexts (CB-F002)
- ✅ AAD binding: prevents credential-swap attacks (FIND-010); decrypt fails if user_sub/service/tool_id/owner_type don't match
- ✅ Fail-closed: if KEK derivation fails, CredentialInjectionError → AuditEmissionError → 500 aborts invocation
- ⚠️ **CB-002 OPEN**: Vault transport must be `https://` (enforced by model-validator in development mode, but can be overridden in prod)
- ⚠️ **CB-007 PARTIAL**: HKDF-SHA256 correct, but master_secret entropy reduced by format mismatch

**Tested by:**
- `proxy/tests/unit/test_invocation_broker.py` (13 unit tests: injection modes, failure cases, broker=None)
- `proxy/tests/unit/test_lifespan_broker.py` (broker wiring, master_secret zeroing)
- `proxy/tests/integration/test_mcp_server_chain.py` (E2E: resolve → inject → call upstream → audit)

### 5.3a Tool Manifest Auditor — fail-closed posture (DET-F1, Task 0.4)

The auditor pipeline (`proxy/app/services/auditor.py`) combines a static OPA score and an LLM (Ollama) score with a weighted average. Prior to this fix the LLM weight was 0.6 and the static weight was 0.4; when Ollama was unreachable the LLM score silently fell back to 0, reducing the combined score to `0.4 × static_score`. A tool flagged `description_prompt_injection` with static score 40 would score 16 — below every quarantine threshold — allowing a targeted Ollama DoS to bypass the quarantine gate (INV-005).

**Remediation applied (commit: fix(security): LLM auditor fail-closed posture):**

- When Ollama is unreachable, `run_llm_analysis` now returns `llm_unavailable: True` in its result dict.
- `run_audit` detects this flag and switches to a **1.0 × static_score** formula (no LLM contribution), ensuring the quarantine gate fires on static flags alone.
- `AuditResult.llm_unavailable: bool` is set so every downstream consumer (log, audit event, Jira, portal) can observe the degraded decision.
- New config setting `REQUIRE_LLM_AUDIT: bool = False` (dev/staging default). **In production this must be `true`** — the startup validator in `config.py:_reject_placeholders_in_production` blocks startup when it is false, preventing an operator from accidentally running a production node in fail-open mode.

**Operational consequence (production `REQUIRE_LLM_AUDIT=true`):** tool *registration* returns HTTP 503 for the duration of any Ollama outage. **Tool invocations are not affected** — the LLM auditor only runs at registration time. Runbook: restore Ollama, then retry the registration. The Sigma rule `mcp-tool-lifecycle-event` fires on quarantine-state changes; the `mcp-quarantined-tool-access` rule fires on any blocked invocation attempt against a quarantined tool.

**Dev/staging (`REQUIRE_LLM_AUDIT=false`):** registration continues with a full-weight static score; `llm_unavailable=true` is recorded in the audit trail so the degraded run is traceable. The risk score is the same value that would have been produced if static alone were used — no silent downgrade.

Files: `proxy/app/services/auditor.py` (classes `LLMAuditRequiredError`, `AuditResult.llm_unavailable`, `run_audit` score logic), `proxy/app/core/config.py` (field `REQUIRE_LLM_AUDIT`, validator `_reject_placeholders_in_production`), `proxy/app/routers/tools.py` (503 path for `LLMAuditRequiredError`). Tested by: `proxy/tests/unit/test_auditor_unavailable.py` (6 unit tests, all passing).

### 5.4 SBOM / registration, 5.5 compliance, 5.6 auth — as in v1 §5.2/§5.3/§5.4, with: SPDX removed (not built), outbound Jira removed (not built), OIDC marked stub.

---

## 6. Threat Model — additions

v1 §7 stands, with these added/corrected entries:

| Threat | Status |
|---|---|
| **T7 — Broker identity collapse** (CB-001): attacker enrolls under collapsed `"unknown"` identity, overwrites victim refresh tokens, shares KEK. | **Active critical defect.** Mitigation = §4.2 item 2. |
| **T8 — Master-key network sniff** (CB-002): cleartext Vault transport exposes the master that decrypts all stored credentials. | **Active critical defect.** Mitigation = §4.2 item 3. |
| T3 (audit log tampering) overstated | MinIO GOVERNANCE mode is bypassable with a privileged key; it is **not** MFA-WORM. Either move to COMPLIANCE mode or correct the claim. |
| T5 (policy bypass) | F-002 OPEN — no runtime bundle-signature verification anywhere. |

---

## 6.1 Evidence: Credential Broker Flow Trace (graphified knowledge graph)

A knowledge graph analysis (June 2026) of the entire codebase extracted the credential broker's actual operational flow. Key traced paths and gaps:

**Service Account Injection → Vault/KMS → Decryption Path:**
- `invoke_tool()` (invocation.py:87) → `broker.resolve(user_sub, service, session_id, approach)` → Approach A reads encrypted_ref from credential_store
- KEK derivation: `_derive_kek()` (approach_a.py:22-37) fetches master_secret via `VaultKMSClient.get_master_secret()` (kms.py:40-59)
- Vault transport: `GET /v1/{BROKER_MASTER_SECRET_PATH}` with `X-Vault-Token` header over **current default: `http://`** ⚠️ CB-002
- Master secret format: Lab seeder writes HEX; kms.py._decode_master_secret() (line 16-28) tries base64 first, reducing effective entropy
- HKDF: `HKDF(SHA256, salt=extracted_from_blob, info=b"mcp-credential-broker-kek-v2:{user_sub}", length=32)` ✅ correct
- AES-256-GCM: decrypt with nonce (next 12 bytes after salt), ciphertext verified against AAD = `f"{user_sub}|{service}|{tool_id}|{owner_type}"` ✅ prevents blob-swapping
- KEK zeroing: explicit loop to overwrite bytearray before drop ✅ CB-F004

**Audit cascade:**
- Every resolved token is injected as `Authorization: Bearer <token>` into upstream MCP call ✅
- Token **never** logged (INV-002: `[REDACTED:credential_ref]`) ✅
- Synchronous audit event emitted before response ⚠️ **except** on refresh/revoke/delete (CB-004, CB-012)

**Identified gaps requiring Phase 2+ fixes:**
1. CB-002: Vault `http://` default → master secret in plaintext (network-sniffable) — **CRITICAL**
2. CB-001 residual: identity from header (fixed in code, §4.2.2) — **CLOSED** but retrofit needed for old enrollments
3. CB-007: single-round `HMAC(master, user_sub)` now fixed to HKDF (§3, service_account line 2) — **UPGRADED**
4. CB-008: master_secret cached forever (no TTL re-fetch); add `BROKER_MASTER_SECRET_TTL_SECONDS` → **IN PROGRESS**
5. CB-004/CB-012: no audit on refresh/revoke/delete; need audit-before-delete DB trigger — **ROADMAP P2**
6. CS-001 (consent two-session gap): `consume_consent_token()` and server approval commit run in separate DB sessions (`proxy/app/services/consent.py`). A crash between the two commits leaves the token consumed but approval not applied — owner must re-issue the consent token. Fail-closed by design; accepted gap (Phase 2.3).

**Test coverage:**
- `test_invocation_broker.py` (13 unit tests: modes, failures, broker=None) ✅
- `test_lifespan_broker.py` (startup wiring, master_secret zeroing) ✅
- `test_mcp_server_chain.py` (E2E: resolve → inject → call → audit) ✅
- `test_vault_tls_enforcement.py` (no `http://` outside dev) ✅
- `test_approach_a.py` (HKDF KEK derivation) ✅

---

## 7. Secrets Management (corrected)

All secrets via env/Vault. **Add to `.env.example`:** every broker variable (`VAULT_ADDR`, `VAULT_TOKEN`, `BROKER_MASTER_SECRET_PATH`, `OAUTH_STATE_SECRET`, `DEX_*`, `ENTRA_*`, `BITBUCKET_*`, `GRAFANA_*`, `NETBOX_*`). Lab key material must be generated by `make lab-init` at setup, not shipped as `devpassword` constants. `.env.lab` confirmed never committed (git history clean) — keep it that way; add a pre-commit secret-scan hook (currently absent — INV-008 gap).

---

## 8. What is NOT real (must be deleted from docs or built)

SPDX SBOM 🔴 · outbound Jira issue creation 🔴 · Helm/K8s deployment (empty templates) 🔴 · OIDC (501) 🔴 · per-tool rate limiting 🟡 · learned anomaly baseline 🔴 · "92%/20%" stat & competitor table (unsourced). Until built, the v1 architecture's claims about these are hallucinations and must be removed (see ROADMAP P1).

---

*End — Architecture v2. Keep status annotations accurate on every change; a claim without verified file:line is a defect.*
