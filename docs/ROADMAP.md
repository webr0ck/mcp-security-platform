# MCP Security Platform — Roadmap & Challenges

**Date:** 2026-05-16 · Driven by `REVIEW-2026-05-16.md` and `ARCHITECTURE-v2.md`.

Principle: **no new features until the platform is honest and not exploitable.** A security platform that is itself insecure or oversold is worse than none — it manufactures false confidence (the exact failure mode INV-001 was written to prevent).

---

## STATUS DASHBOARD (as of 2026-06-01)

| Phase | State | Summary |
|---|---|---|
| **P0 — Security unblock** | ✅ **DONE** | All 2 CRITICAL + 4 HIGH + supporting MEDIUM findings fixed, unit-tested, F-001 **runtime-proven on the live Podman lab**. |
| **P1 — Truth reconciliation** | ✅ **DONE** | Docs reconciled to code; credential broker fully documented; enforcement table honest (enforced vs roadmap split). |
| **P2 — Hardening** | ✅ **DONE** | HKDF KEK, master-secret TTL + zero, adapters raise typed errors, pre-commit gate, `.pre-commit-config.yaml` fails closed. CB-008/INV-007 partial (see notes). |
| **P3 — Feature completion** | 🟡 **PARTIAL** | OIDC browser login + KC session JWT + Grafana SSO ✅. Learned anomaly baseline, real Helm, outbound Jira, per-tool rate-limit still roadmap. |
| **P4 — Self-service MCP** | ✅ **DONE** | `self-service-mcp` (port 8108) live: 7 tools, `mcp_profiles` + `mcp_profile_events` tables (V020), OPA profile enforcement, 57 lab tests pass. |
| **P5 — OAuth API + scripts** | ⏳ **DEFERRED** | Thin OAuth2-authenticated REST + Python CLI scripts. Non-security; sequence after P6. |
| **P6 — Runtime-enforcement closure** | 🟢 **CORE DONE** (2026-06-06) | 6.1 meta-tool OPA identity ✅, 6.2 discovery==invoke enforcement ✅, 6.3 oauth_user_token RFC 8693 ✅, 6.4 anomaly dead-code removed ✅. Carried-forward hardening (6.5 INV-007 object-lock, 6.6 F-002 signed-bundle staging, 6.7 lab key material) still open. See Phase 6. |

**Test coverage (2026-06-01):** 440 tests (383 proxy + 57 lab). Stress test: 2000 VUs (800 ROPC + 200 SA + 200 per-user + 1400 API-key), 50+ MCP requests/VU, p95 latency <500ms with token caching.

---

## Phase 0 — UNBLOCK (security-critical) — ✅ COMPLETE

Exit criteria met: every P0 finding fixed, each with a passing regression test; F-001 additionally proven at runtime.

| # | Fix | Findings | Status / evidence |
|---|---|---|---|
| 0.1 | Broker/RBAC identity from `request.state.client_id` (never raw `X-Client-Cert-CN`); real nginx `location /auth/`; CN blanked outside `/api/v1/tools/`; OAuth callback public, identity recovered from server-side nonce. | CB-001, F-001 | ✅ `proxy/app/routers/oauth.py`, `middleware/auth.py`, `gateway/nginx/conf.d/mcp-proxy.conf` · tests: `test_oauth_router.py` (identity-from-store, spoof-ignored) |
| 0.2 | `VAULT_ADDR` default `https://`; model-validator rejects `http://` outside dev; `VAULT_CA_BUNDLE`; `kms.py` explicit TLS verify. | CB-002, CB-009 | ✅ `core/config.py`, `credential_broker/kms.py` · tests: `test_vault_tls_enforcement.py`, `test_config_broker.py` |
| 0.3 | Proxy off the flat `internal-net` + `observability-net`; pairwise `proxy-{opa,ollama,redis,db}-net` + `vault-net`; inbound only `gateway-net`. **Apply via full `compose up -d` (recreate) — not live `network disconnect`, not `--no-deps` without `--alias` on manually-connected backends.** | F-001 | ✅ `docker-compose.yml` · gate `scripts/check_network_isolation.py` in `make security-check` · **runtime-proven**: `mcp-netbox`→proxy:8000 REACHABLE→REFUSED, proxy healthy |
| 0.4 | Real OPA signed-bundle mechanism: `scripts/sign_policy_bundle.sh` + `make sign-policy-bundle` + `docker-compose.opa-signed.yml` overlay (HS256, `scope=write`). Dev keeps directory mount (INV-012 permits). | F-002 | ✅ mechanism delivered & overlay validates. **NOT yet enforced in a running staging deploy → see P2.8** |
| 0.5 | Server-side random nonce in Redis (single-use, TTL 300s, atomic consume); PKCE S256 added to m365/bitbucket/dex. | CB-003, CB-011 | ✅ `oauth.py`, adapters · tests: `test_oauth_router.py` (nonce/PKCE, replay→400) |
| 0.6 | Synchronous `CREDENTIAL_ENROLLED` audit event, RuntimeError-propagation (INV-001 pattern). | CB-004, CB-012 | ✅ `oauth.py::_emit_credential_audit` |
| 0.7 | Migration `V009`: `GRANT SELECT, INSERT ON role_assignments TO proxy_app; REVOKE UPDATE, DELETE`. | CB-005, INV-011 | ✅ `infra/db/migrations/V009__role_assignments_grants.sql` |
| 0.8 | KEK via HKDF-SHA256 (RFC 5869), not single-round HMAC. | CB-007 | ✅ `approaches/approach_a.py` · test: `test_approach_a.py` (HKDF, ≠ legacy) |
| 0.9 | OAuth token adapters raise `TokenExchangeError` (status only, never IdP body). | CB-010 | ✅ `adapters/{m365,bitbucket,dex}.py`, `adapters/base.py` |
| 0.10 | In-process MCP-client contract tests (no Docker): auth/role/JSON-RPC/quarantine/OPA/audit. | coverage | ✅ `proxy/tests/unit/test_mcp_client.py` (9 tests) |

**Not yet done in P0 scope (carried forward):** the *regression tests for some fixes are unit-level, not the integration tests the original plan named* — integration coverage (real DB/OPA) is folded into P1.4 (the integration CI job is currently broken by missing fixtures and must be repaired first).

---

## Phase 1 — TRUTH RECONCILIATION (documentation integrity)

Exit criteria: every claim in every doc maps to verified file:line, or is deleted, or moved to "Planned (not built)".

- 1.1 Replace `ARCHITECTURE.md` with `ARCHITECTURE-v2.md` content (or redirect it); never let a doc call itself "single source of truth" while omitting a shipped subsystem again.
- 1.2 Remove or implement: SPDX SBOM, outbound Jira, Helm/K8s, OIDC, per-tool rate limiting, learned anomaly baseline. Default action = **remove the claim**; reintroduce only when built (Phase 3).
- 1.3 Remove unsourced "92% / 20%" stat and the competitor differentiator table, or cite a verifiable public source.
- 1.4 Fix every broken cross-reference: `ci/test-jobs/security.yml` (missing), `tests/fixtures/integration_seed.sql` (missing), `test_audit_completeness_opa_down.py` (missing), INV-001's wrong test path. Either create the files or fix the references — the integration CI job currently fails at the seed step.
- 1.5 Rewrite each INV "Enforcement:" clause to state what is *actually* automated vs human-review vs aspirational (table in REVIEW §2). Correct T3: GOVERNANCE mode is not MFA-WORM.
- 1.6 Document the credential broker fully in architecture, API.md, RBAC.md (roles that may enroll), and SECURITY_NONNEGATABLES (a new INV for credential-at-rest + credential lifecycle audit).

---

## Phase 2 — HARDENING (not started; sequence after P1)

- 2.1 ✅ DONE in P0.8 — KEK via HKDF (RFC 5869) (CB-007).
- 2.2 ✅ DONE — master secret held in a bytearray, re-fetched after `BROKER_MASTER_SECRET_TTL_SECONDS` (default 300s, honours Vault rotation), old copy explicitly zeroed (CB-008). Test: `test_master_secret_ttl.py`.
- 2.3 ✅ DONE in P0.9 — adapters raise typed `TokenExchangeError`, status only (CB-010). *Still pending:* add IdP-error redaction patterns to `mcp-audit-logger` (INV-002 depth).
- 2.4 ⏳ Real INV-007 startup Object-Lock verification in compliance-checker; decide GOVERNANCE vs COMPLIANCE mode and align the doc.
- 2.5 ✅ DONE — `.pre-commit-config.yaml` (trufflehog + F-001 gate + rego deny-by-default); `make security-check` now **fails closed** when trufflehog/opa absent (was skip-with-warn).
- 2.6 ✅ DONE via P1.4 — integration CI Phase-2 step sets `OPA_DOWN_TEST_MODE=1` and runs the opa_down split; the `--ignore` of the nonexistent file was removed. (Local `make test` still skips it by design — no OPA-down locally.)
- 2.7 🟡 PARTIAL — broker vars added to `.env.example` (CB-015 closed). *Still pending (deferred, lab-only, touches running lab setup):* `make lab-init` generating lab key material instead of `devpassword` constants (CB-006).
- 2.8 ⏳ **Wire F-002 into a real staging deploy**: bring the stack up with `-f docker-compose.opa-signed.yml`, prove OPA refuses an unsigned/tampered bundle at runtime (the mechanism exists from P0.4 but has only been validated statically, not enforced in a running env).

---

## Phase 3 — FEATURE COMPLETION — 🟡 PARTIAL

✅ Keycloak browser login, PKCE S256, session JWT, Grafana SSO — full flow implemented.
✅ Lab environment: Keycloak, Dex, 4 lab MCP servers (echo, notes, search, self-service), stress test infrastructure.

Still roadmap: learned/statistical anomaly baseline (hardcoded sliding-window today) · SPDX (if a real consumer needs it) · outbound Jira issue creation on critical risk · real Helm chart + `helm template` CI lint · per-tool rate limiting · browser UI (catalog/submission/scan-status/reviewer actions — none exists; spec before building).

---

## Phase 4 — SELF-SERVICE MCP — ✅ DONE (2026-06-01)

**Delivered:** `lab/mcp-servers/self-service/server.py` — FastMCP server on port 8108.
**Tools:** `list_available_mcps`, `enable_mcp`, `disable_mcp`, `get_profile`, `list_functions`, `enable_function`, `disable_function`.
**Storage:** `mcp_profiles` + `mcp_profile_events` (V020 migration). Identity from proxy-injected `X-User-Sub`. OPA profile enforcement wired into invocation path (Python layer); Rego integration is Phase 5 work.
**Test coverage:** 57 lab tests (20 self-service + 37 functional).

### Original Design (archived below for reference)

**Goal (original):** expose platform management capabilities *as an MCP server* so agents and automated pipelines can discover, enable, and configure MCP servers programmatically.

## Phase 4 — SELF-SERVICE MCP (original spec, now implemented)

**Goal:** expose platform management capabilities *as an MCP server* so agents and automated pipelines can discover, enable, and configure MCP servers programmatically — the platform eating its own dogfood.

### Design principles
- **JSON only, no bloat.** Every response is a tight JSON object. No HTML, no XML, no extra wrapper envelopes. Schema-minimal: only fields a consumer will actually use.
- **One MCP server, one responsibility.** The self-service MCP is a single FastMCP server (`self-service-mcp`) running alongside the proxy. It talks to the proxy DB and RBAC layer directly (same container network). It does NOT re-implement auth — the proxy's auth middleware sits in front of it like any other upstream.

### Tools (minimum viable set)

| Tool | Description | Auth required |
|---|---|---|
| `list_available_mcps` | List all MCP servers visible to the caller's account. Returns `[{name, description, status, enabled_for_account}]`. Filters by RBAC — agents only see MCPs they are entitled to. | agent / auditor |
| `enable_mcp` | Enable an MCP server for the caller's account (or a named profile). Idempotent. Emits `MCP_ENABLED` audit event. | agent (self) / admin (others) |
| `disable_mcp` | Disable an MCP server for the caller's account (or profile). Emits `MCP_DISABLED` audit event. | agent (self) / admin (others) |
| `list_functions` | List all tools exposed by a specific MCP server visible to the caller. Returns `[{function_name, description, enabled}]`. | agent |
| `enable_function` | Enable a specific function on an MCP server for a profile. Profile defaults to the caller's identity. Emits audit event. | agent (self-profile) / admin |
| `disable_function` | Disable a specific function on an MCP server for a profile. Emits audit event. | agent (self-profile) / admin |
| `get_profile` | Get the complete permission profile for an account: which MCPs enabled, which functions active per MCP. | agent (self) / admin / auditor |

### Profile model

A **profile** is a named permission set (maps 1:1 to a KC role or user sub). Profiles answer: "which MCP servers can this identity call, and which functions on each?"

```json
{
  "profile_id": "alice@lab.local",
  "mcps": [
    {
      "name": "search-kb",
      "enabled": true,
      "functions": ["search", "get_document", "list_categories"]
    },
    {
      "name": "notes-store",
      "enabled": true,
      "functions": ["create_note", "list_notes"]
    },
    {
      "name": "grafana-query",
      "enabled": false,
      "functions": []
    }
  ]
}
```

### Implementation sketch

- **Backend storage:** new `mcp_profiles` table: `(profile_id, mcp_name, enabled, allowed_functions jsonb, updated_at)`. Seeded with defaults from tool_registry.
- **MCP server:** `lab/mcp-servers/self-service/server.py` using FastMCP. Talks to DB directly (read own profile) and via proxy admin API (admin operations).
- **OPA integration:** proxy checks `mcp_profiles` at tool-call time: if `enabled=false` for the caller's profile → deny even if the tool is globally active.
- **Audit trail:** every enable/disable emits to `audit_events` — immutable, same pipeline as all other events.

### Non-goals for P4
- No UI. The self-service MCP IS the interface; a human-facing UI is a Phase 5+ concern.
- No cross-tenant profile sharing. Each profile is scoped to a single identity.
- No bulk import. Changes are per-MCP, per-function, per-profile.

---

---

## Phase 5 — OAuth API + Python CLI (NEXT)

**Goal:** thin OAuth2-authenticated REST API + Python script layer for MCP management without MCP context overhead. Answers the question: "how do I manage MCP servers from a simple script without the self-service MCP bloating the LLM context?"

### Design

- **Auth:** Keycloak `client_credentials` (for automation) or ROPC (for dev scripts). Same KC realm already in place.
- **API surface:** reuse existing proxy REST endpoints + add `PUT /api/v1/credentials/me/{tool_id}` for per-user credential self-service.
- **Scripts** (`scripts/mcp_admin.py`):
  - `--list` — list all registered MCPs with status
  - `--enable <mcp>` / `--disable <mcp>` — toggle for calling identity
  - `--profile <mcp>` — show allowed functions
  - `--set-secret <mcp>` — upload personal credential (user injection mode)
  - Auth: `httpx` + KC token, ~150 lines total, zero MCP dependency
- **No new infrastructure.** All endpoints already exist or are a 1-endpoint addition to the proxy.

### Non-goals
- No new UI beyond the admin panel already built.
- No new auth mechanism — KC tokens already work.

---

## Phase 6 — RUNTIME-ENFORCEMENT CLOSURE — 🔴 NEXT (added 2026-06-06)

**Driver:** `GRAPHIFY-FINDINGS-2026-06-06.md` + a verified source audit of the `/mcp` path. P0–P2 hardened the **REST** invoke path and the credential broker's *crypto*; this phase closes the gaps that remain on the **`/mcp` protocol path** and in the advisory/telemetry layers. CB-002 (KMS hex/base64) and the entitlement query bug are now **FIXED** (commit `ee47c2c`) and are NOT in this phase.

Sequencing rule (unchanged from the top of this doc): **the two authorization bypasses (6.1, 6.2) ship before the feature-completion items (6.3, 6.4).** A privileged-caller authz bypass on the headline `/mcp` surface is a P0-class defect, not polish.

### 6.1 — `/mcp` meta-tools evaluate OPA as `platform_admin`, not the real caller — ✅ DONE (2026-06-06)
- **Was:** `mcp_server.py` built `opa_input` for inline platform meta-tools with hardcoded `"client_id": "platform_internal"`, `"client_roles": ["platform_admin"]`. OPA authorized every meta-tool as `platform_admin` regardless of caller, and the audit identity was corrupted.
- **Fix shipped:**
  - `proxy/app/routers/mcp_server.py` — `opa_input` now carries the real `client_id` / `roles` from `request.state`.
  - `policies/rego/authz.rego` — new `platform_meta_tool_roles` map (mirrors `_TOOLS._roles`), `is_platform_meta_tool` / `caller_may_use_meta_tool` helpers, a role-based `client_has_invoke_permission` clause and a `risk_level_within_threshold` clause for meta-tools (no per-client grant required), plus an explicit `deny["meta_tool_role_not_authorized"]` reason. Deny rules (quarantine, prompt-injection) still apply via `count(deny)==0`.
- **Tests (TDD, red→green):**
  - `policies/rego/meta_tools_test.rego` — 8 tests: viewer→platform_info/enrollment_status allow (no grant), viewer→security_pulse deny, analyst→security_pulse/list_registered_tools allow, prompt-injection deny on a meta-tool, no-roles deny, and a non-meta registry tool still denied without a grant (no accidental widening). `opa test`: **14/14**.
  - `proxy/tests/unit/test_mcp_opa_audit.py` — new `test_dispatch_meta_tool_opa_uses_real_caller_identity`; **eliminated drift**: the prior `test_dispatch_tools_call_platform_info_emits_audit` asserted `client_id == "platform_internal"` (locking in the bug) — now asserts the real `alice`/`["analyst"]`. **7/7**.
- **AppSec review (self-conducted; appsec-reviewer agent was rate-limited):** found a real privilege-escalation vector in the first cut — the meta-tool Rego rules keyed on `input.tool_name` alone, so a registry tool *registered* with a reserved name (e.g. `platform_info`) would, on the registry invoke path (`services/invocation.py`), inherit the meta-tool risk-gate + grant bypass. **Closed** by requiring an explicit `is_platform_meta=true` marker that only the inline `/mcp` meta dispatch sets; `is_platform_meta_tool` now requires both the marker and a known name. Two bypass-regression tests added (`test_registry_tool_named_like_meta_no_marker_denied`, `test_registry_tool_named_like_meta_risk_gate_applies`). `default allow = false` unchanged (INV-003 intact).
- **Docs:** README enforced-vs-roadmap (Policy + RBAC rows) updated. **INV-003.** opa check --strict clean; `opa test` 16/16; pytest 7/7.

### 6.2 — discovery≠invoke: server entitlement not enforced on the invoke path — ✅ DONE (2026-06-06)
- **Was:** `check_entitlement()` was never called before invoke; `mcp_server.py` admitted an admin/platform_admin could invoke any tool by name regardless of server grants. The call was blocked on a missing `tool_registry.server_id` FK.
- **Fix shipped:**
  - `infra/db/migrations/V023__tool_server_fk.sql` — adds nullable `tool_registry.server_id` FK → `server_registry(server_id)` `ON DELETE SET NULL` + partial index; re-asserts `proxy_app` SELECT only (INV-011: no new write privilege).
  - `proxy/app/services/entitlement.py` — new `NotEntitledError` + `enforce_tool_entitlement(tool_record, principal_id, principal_type)`. Uses the **same** `check_entitlement` resolver the catalog uses for discovery (so the two can't drift), **no role exception** (identity-based — admin can't bypass), **fail-closed** on unresolved principal. Unlinked tools (`server_id` NULL) are a no-op (OPA still governs them).
  - `proxy/app/services/invocation.py` — `invoke_tool()` gains `principal_id`/`principal_type` params and calls `enforce_tool_entitlement` at **Step 1.5** (pre-OPA, like the INV-005 quarantine gate). Emits a **synchronous deny audit at the chokepoint** (INV-001) before the exception propagates, so REST + both `/mcp` paths record the deny uniformly.
  - Callers threaded: `routers/tools.py` (REST, +server_id in SELECT), `routers/mcp_server.py` `_route_to_registry` and `_handle_invoke_tool_real` — all pass `request.state.principal_id/principal_type` and map `NotEntitledError` → 403 / JSON-RPC deny **without leaking** `server_id`/reason.
- **Tests (TDD, red→green):** `proxy/tests/unit/test_entitlement_enforcement.py` — 6 tests: unlinked no-op, entitled passes, not-entitled raises, **admin not-entitled still raises** (no role exception), unresolved principal fails closed, and a wiring regression proving `invoke_tool` enforces **before OPA** and **audits the deny**. Fixture drift fixed in `test_mcp_client.py` (added `server_id`). Full unit suite: **275 passed, 1 xfailed**.
- **AppSec review (self-conducted):** moved the deny audit from the REST handler into the `invoke_tool` chokepoint so the `/mcp` deny paths are no longer a silent INV-001 gap. Accepted nit: invoke returns 403 (confirms tool exists) while server *discovery* returns 404 — consistent with the existing quarantine path; tool-name enumeration is already bounded by grant-filtered `tools/list`.
- **Docs:** README Policy row → discovery==invoke enforced. **INV-011 + discovery==invoke invariant.**

### 6.3 — `oauth_user_token` (RFC 8693) injection mode: thread the caller's KC token — ✅ DONE (2026-06-06)
- **Was:** fail-closed stub — `invocation.py` hardcoded `user_kc_token=None`, so the dispatcher always raised. The token-exchange machinery existed but was unreachable. Users could not use on-behalf-of without holding a secret.
- **Fix shipped (no secrets on the user side — pure OAuth on-behalf-of):**
  - `proxy/app/middleware/auth.py` — the direct-OIDC path (3b) stashes the raw KC access token on `request.state.user_kc_token` (it IS a valid RFC 8693 subject token there). All other auth methods default it to `None`. In-memory for the request only; never logged (INV-002).
  - `proxy/app/services/invocation.py` — `invoke_tool()` gains `user_kc_token` and forwards it to `dispatch_credential_injection` (was `None`).
  - Callers threaded: REST (`tools.py`) + both `/mcp` paths (`mcp_server.py`) pass `request.state.user_kc_token`.
  - The dispatcher (`_inject_oauth_user_token` → `keycloak_client.exchange_token`, `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`) was already correct; it now receives the subject token.
- **Tests (TDD, red→green):** `proxy/tests/unit/test_oauth_user_token_threading.py` — 4 tests: `invoke_tool` forwards the token to the dispatcher; dispatcher uses it as the RFC 8693 `subject_token` for the configured audience; **fails closed without a token**; and the auth middleware stashes the token **only** for direct-OIDC callers (None for API-key). Full unit suite: **279 passed, 1 xfailed**.
- **Limitation (documented):** internal-session / browser-portal callers still fail closed for this mode — their bearer is a session JWT, not a KC subject token (decrypting the stored KC token is a follow-up).
- **AppSec (self-conducted):** token never logged (INV-002); non-OIDC callers fail closed (verified by test); only the 3b path stashes. **INV-002.**
- **Docs:** README credential-modes row, CLAUDE.md known-gap #1.

### 6.4 — Behavioral anomaly baseline: relabel honestly — ✅ DONE (2026-06-06, option B)
- **Was:** `update_baseline_async` wrote `anomaly_baselines` but had **zero callers**; the scorer read only the Redis window + hardcoded rules and never queried the baseline — write-only dead code implying a learned model that did not exist.
- **Fix shipped (option B — honest heuristic beats dead code):**
  - `proxy/app/services/anomaly.py` — removed `update_baseline_async`; rewrote the module docstring to label the scorer an **advisory heuristic** (static keyword/window matching, evadable by tool rename, no statistical baseline). The `anomaly_baselines` table is kept (admin read-only view + future learned baseline) and is intentionally unpopulated.
- **Tests (TDD, red→green):** `proxy/tests/unit/test_anomaly_no_dead_baseline.py` — 3 drift guards: the write-only writer is gone, `detect`/`evaluate_anomaly` remain the entry point, and the docstring makes no learned-baseline claim. Existing `test_anomaly_detector.py` unchanged & green. Full unit suite: **282 passed, 1 xfailed**.
- **Decision deferred:** option (A) — a real learned/statistical per-client baseline — remains future work; do not build it until there is a consumer for the signal, and it must stay advisory (never silently enforcing).
- **INV touched:** none (advisory). **Docs:** README anomaly row, CLAUDE.md known-gap #2.

### Carried-forward hardening (still open from P2)
- **6.5 (=P2.4)** — INV-007 startup Object-Lock verification in compliance-checker; decide GOVERNANCE vs COMPLIANCE mode and align the doc. Today the "startup check" is aspirational.
- **6.6 (=P2.8)** — Wire F-002 signed bundles into a **running** staging deploy and prove OPA refuses an unsigned/tampered bundle at runtime (mechanism exists, only statically validated).
- **6.7 (=P2.7 tail)** — `make lab-init` generates lab key material instead of `devpassword` constants (CB-006, lab-only hygiene).

### Phase 6 exit criteria
6.1 and 6.2 merged with blocking regression tests + `appsec-reviewer` green; 6.3 merged or explicitly deferred with the stub's fail-closed behavior re-confirmed by test; 6.4 resolved by an explicit (A)/(B) decision (no lingering write-only code); README Enforced-vs-Roadmap table updated so `/mcp` built-ins move from "Roadmap / NOT yet" to "Enforced today" **only** for the parts actually wired. Update `ARCHITECTURE-v2.md` §5.3 status markers and `SECURITY_NONNEGATABLES.md` if a meta-tool/entitlement invariant is added.

---

## Challenges & Risks

1. **The doc/reality gap is structural, not a one-off.** The "canonical" doc drifted because nothing enforces doc↔code consistency. Mitigation: Phase 1.5 + the DEV-TEST-PROCESS doc-consistency gate; treat an unverifiable claim as a build defect.
2. **Credential broker is the highest-value attack target on the platform** — it holds keys to M365/Bitbucket/Grafana/Netbox/Dex. Its security bar must be the *highest*, yet it shipped with the *least* review (added after the appsec-review froze). Mitigation: mandatory `appsec-reviewer` sign-off on every broker change (DEV-TEST-PROCESS).
3. **Fail-open behaviors hide in "advisory" components.** Tool Manifest Auditor scores 0 if Ollama is down; anomaly uses fixed rules. These are defensible *if documented*; dangerous if presented as active controls. Mitigation: label advisory vs enforcing in architecture; alert when an advisory control is degraded.
4. **CI gives false assurance.** Several INV "Enforcement" tests `pytest.skip` unless env vars CI never sets, and `make security-check` skips tools when absent. Green CI ≠ invariants enforced. Mitigation: Phase 2.5/2.6; the gate must fail closed, like the system it protects.
5. **Crypto built by hand.** Per-user KEK, nonce handling, KDF were hand-rolled. Each is a CB-00x finding. Mitigation: standardize on `cryptography` HKDF/AESGCM primitives; no bespoke KDF/state derivation; crypto changes require appsec sign-off.
6. **No UI exists** despite reviewer/submission flows implied by the API. Don't let UI work start before P0–P2; a UI over an exploitable backend widens the attack surface.
7. **GOVERNANCE-mode WORM is not tamper-proof.** Compliance positioning depends on it. Decide COMPLIANCE mode (irreversible, operationally heavier) vs honest downgrade of the claim before any compliance marketing.

---

## Done Means

A phase is done only when: code merged, regression test in the **blocking** CI gate, docs updated to match (verified file:line), `make security-check` and `appsec-reviewer` both green, and no claim in any doc lacks a code referent. See `DEV-TEST-PROCESS.md`.
