# MCP Security Platform — Architecture v2 (Reality-Based + Secure Target)

**Version:** 2.0.0
**Date:** 2026-05-16
**Status:** Canonical. Supersedes `docs/ARCHITECTURE.md` v1.0.0 (stale: omits the credential broker, Vault, `credential_store`, OAuth router).

This document describes the system **as it actually is** (verified at source) and the **secure target state** (what must change before production). Every component is annotated with its real implementation status so this document cannot drift back into aspiration.

Status legend: ✅ implemented & wired · 🟡 partial/overclaimed · 🔴 stub/missing · 🆕 exists in code, was undocumented · ⚠️ security defect (see REVIEW-2026-05-16.md)

---

## 0. Current security status (2026-05-16)

**Phase 0 (security unblock): ✅ COMPLETE.** All CRITICAL/HIGH findings from `REVIEW-2026-05-16.md` are fixed and tested (79 unit + 9 MCP-client tests). The two CRITICALs (CB-001 broker identity collapse, CB-002 plaintext Vault key) and the HIGHs (CB-003/004/005, F-001, F-002 mechanism) are closed. **F-001 was additionally proven at runtime on the live podman lab** — a non-dialed sidecar that previously reached `proxy:8000` is now refused, with the proxy still healthy.

**Not yet done** (tracked in `ROADMAP.md`): Phase 1 truth reconciliation (this doc replacing v1; killing/relabelling not-built features; fixing broken CI refs; documenting the broker in API/RBAC/SECURITY) → Phase 2 hardening (CB-008, INV-007 startup verify, pre-commit secret hook, F-002 enforced in a running staging deploy) → Phase 3 features.

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
│ Tool Manifest Auditor: OPA-static + Ollama LLM ✅ (advisory, fails-open to 0)   │
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

### 5.3 SBOM / registration, 5.4 compliance, 5.5 auth — as in v1 §5.2/§5.3/§5.4, with: SPDX removed (not built), outbound Jira removed (not built), OIDC marked stub.

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

## 7. Secrets Management (corrected)

All secrets via env/Vault. **Add to `.env.example`:** every broker variable (`VAULT_ADDR`, `VAULT_TOKEN`, `BROKER_MASTER_SECRET_PATH`, `OAUTH_STATE_SECRET`, `DEX_*`, `ENTRA_*`, `BITBUCKET_*`, `GRAFANA_*`, `NETBOX_*`). Lab key material must be generated by `make lab-init` at setup, not shipped as `devpassword` constants. `.env.lab` confirmed never committed (git history clean) — keep it that way; add a pre-commit secret-scan hook (currently absent — INV-008 gap).

---

## 8. What is NOT real (must be deleted from docs or built)

SPDX SBOM 🔴 · outbound Jira issue creation 🔴 · Helm/K8s deployment (empty templates) 🔴 · OIDC (501) 🔴 · per-tool rate limiting 🟡 · learned anomaly baseline 🔴 · "92%/20%" stat & competitor table (unsourced). Until built, the v1 architecture's claims about these are hallucinations and must be removed (see ROADMAP P1).

---

*End — Architecture v2. Keep status annotations accurate on every change; a claim without verified file:line is a defect.*
