# PRD — Delegated Downstream Auth for MCP Tools (User → Gateway → Entra → Microsoft Graph)

**Version:** 1.2.0 (draft — revised after two critic rounds)
**Date:** 2026-06-09
**Owner:** product-owner
**Companion design:** `docs/ARCHITECTURE-delegated-auth.md`
**Critic gate:** 2 × 3-critic runs 2026-06-09, both **needs_work** (unanimous). Round 1 fixes: R-2 downgraded P0→P1 + phantom-enforcement disclosed; R-3 split R-3a/R-3b; "safe to pass through an LLM" removed; R-4 scoped to RFC 8707 (PRM already served); R-5/R-6 marked not-implemented; R-7 document-only; §7 prerequisites added; OBO "impossible" softened. Round 2 fixes (code-verified): R-1 acceptance corrected to the real `-32010` error shape (no `enrollment_required=true` field); R-3b timing model fixed (two-phase link-token vs PKCE state) + diagnosis corrected (the gap is unauthenticated callback association, not URL leak); residual "LLM-safe" overclaim removed from ARCH §4; ARCH dangling `R-3` refs fixed; R-5 given a `scopes`-column mechanism + `__Host-` decision; R-6b reclassified as a design spike; §6 reality-check + P0 exit now disclose the Vault/broker conditional and the session-dependency security note; §7 adds env-var + `offline_access` + tenant-choice prerequisites; `service_name="m365"` `KeyError` invariant noted; WIF vs Entra External ID disambiguated; MCP spec date unpinned pending verification. **Open items remain (R-3b §8 Q-1 session model; R-5/R-6b design) — not yet a buildable P1 spec; P0 is buildable as a supervised demo.**

---

## 1. Problem & opportunity

A user authenticates to the MCP gateway with their corporate identity (Keycloak, OAuth 2.1 PKCE). They then ask the agent to *"read my last 5 emails"* or *"what's on my calendar."* The agent calls an MCP tool that must reach **Microsoft Graph as that specific user** — not as a shared app identity. Today this works end-to-end (`entra_user_token` mode) **only after** the user manually opens an enrollment URL and completes a second login to Entra. The enrollment step is discoverable but clumsy, the downstream audience binding is advisory rather than enforced, and per-tool Entra tenancy is not exercised.

**Goal:** make user-delegated downstream access (Graph first; the pattern generalizes to any OAuth API) **seamless, spec-compliant, and multi-tenant**, without weakening any security invariant.

### Non-goal / settled architecture decision

We will **not** attempt to exchange the Keycloak token directly at Entra via the standard OBO grant — Entra rejects a foreign-issuer (Keycloak-signed) assertion, and passthrough is also forbidden by the MCP spec. This is a topology constraint, not a literal impossibility: Workload Identity Federation / Entra External ID guest federation *could* make Entra accept an external identity, but only as turn-key for **application-level** access (user-delegated Graph scopes via federated foreign token is not turn-key) and only by changing tenant federation topology, which is out of scope. Given IdP #1 is fixed at Keycloak, the product uses **Pattern B**: independent per-user Entra enrollment + encrypted token vault. This decision is locked unless the org federates Keycloak into Entra; see design §1.

---

## 2. Users & stories

| As a… | I want… | so that… |
|---|---|---|
| End user (Alice) | the agent to open the Entra login automatically the first time a Graph tool is needed, then never again | I don't have to hunt for an enrollment URL |
| End user | to see exactly which Microsoft permissions are being requested before I consent | I'm not phished into over-broad scopes |
| Platform admin | to bind each MCP tool to its own Entra tenant/client/scopes | I can onboard tools from different tenants with least privilege |
| Auditor | every enrollment, token mint, and Graph call attributable to the real human | the audit trail is defensible (no app-identity blur) |
| Security reviewer | the gateway to prove a token was issued *for it* (audience), and to never forward a client token downstream | confused-deputy and passthrough classes are closed |

---

## 3. Requirements

Priority: **P0** = required for "seamless + safe" MVP · **P1** = hardening for production posture · **P2** = nice-to-have.

| ID | Pri | Requirement | Acceptance criteria (done = tested) |
|---|---|---|---|
| **R-1** | P0 | Delegated-tool call without a stored credential returns a structured, actionable enrollment signal. | Invoking m365-graph with no `credential_store` row returns a **JSON-RPC error (code `-32010`)** whose `data` object carries `service`, `enrollment_url`, `action`, and `instructions` (`mcp_server.py:361-376`) — there is **no** `enrollment_required=true` field; test the error shape, not a success result. A synchronous audit event is written (INV-001). *Mostly already wired via `CredentialEnrollmentRequiredError`.* **Caveat:** if Vault/broker is not initialized, the path raises `CredentialInjectionError` → generic `-32603`, **not** the enrollment error — so R-1 is only observable when the broker is up. **P0-exit met (supervised demo):** error shape, deny-audit (INV-001), and `enrollment_required` deny-reason split are all test-covered (`proxy/tests/unit/test_enrollment_link_delivery.py`). Session-dependency security note applies — see §6 P0 caveat. |
| **R-2** | P1 | Per-tool Entra binding. `tool_registry.entra_tenant_id/client_id/scope` are read first; `ENTRA_*` env is fallback only. | **Two parts, both required (the enforcement side does not exist today):** (a) migration seeds m365-graph row with explicit tenant/client/scope; (b) **refactor** so the adapter is selected/parameterized per invocation from `tool_record.entra_*` — thread the tool row through `dispatch_credential_injection` → `_inject_entra_user_token`, replacing the single startup-time `M365Adapter` built from `settings.ENTRA_*` (`oauth.py:33-38`). Unit test proves env is NOT consulted when the row is populated; two tools at two tenants both work. *Downgraded from P0: it is hardening, not the user's seamless-access goal, and the migration alone is a false green.* **Related invariant:** `broker._resolve_a` does `self._approach_a_adapters[service]` (`broker.py:127`) — a fixed `"m365"` key — so until R-2 lands, `entra_user_token` raises `KeyError` for any tool whose `service_name` ≠ `"m365"`. P0 acceptance tests must use `service_name = "m365"` exactly. |
| **R-3a** | P0 | Seamless enrollment hand-off — **link delivery**. The unenrolled-tool result surfaces a clickable enrollment link; `initialize` advertises pending enrollments. | Tool result + `initialize._meta` carry the enrollment URL; a capable client renders it clickable. Integration test asserts the shape. *(Builds on existing `CredentialEnrollmentRequiredError`, `mcp_server.py:353-372`.)* **Browser auto-open is NOT in scope** — it needs a client-side host capability most MCP clients lack; best-effort, tracked separately. Confirm whether the target MCP client honors `elicitation` before relying on it. **P0-exit met (supervised demo):** `initialize._meta.pending_enrollments` shape and all-enrolled absent-meta case are test-covered (`proxy/tests/unit/test_enrollment_link_delivery.py` Tasks 3). Client rendering of the link remains a manual verification step (Task 5 skipped — requires a human at the MCP client). Session-dependency security note applies — see §6 P0 caveat. |
| **R-3b** | P1 | Seamless enrollment hand-off — **secure deep-link**. The enrollment link is self-authenticating so a fresh browser (no proxy session) completes enrollment bound to the right caller. | **Diagnosis (precise):** today `client_id` is bound at enroll-time via `_authenticated_client_id(request)` (AuthMiddleware state — mTLS CN / OIDC sub / API key) and stored server-side in Redis under an unguessable nonce (`oauth.py:99-110`). The gap is **not** that `client_id` leaks in the URL — it is that the `enrollment_url` is unauthenticated, so a fresh browser opening it has no session and the callback cannot associate back to the original API caller (whoever logs in next gets the credential). **Design (two-phase token — resolve before writing tests):** an HMAC-signed, ≤300s, single-use **link-token** that embeds `client_id`, consumed at `/auth/enroll` (which then mints the normal PKCE `state` nonce that survives the Entra round-trip to callback). Do **not** specify "consumed at link-click" as the thing that survives to callback — that is self-contradictory and produces unrecoverable stuck-enrollments on any transient Entra failure. **Open decision (§8 Q-1):** does the link-token bypass `_authenticated_client_id` (a new unauthenticated grant surface) — yes, by design, which is why it must be single-use + short-TTL + replay-guarded. **Security gate:** bearer-equivalent; token not logged (INV-002); **no claim it is "safe to pass through an LLM"** — an agentic LLM with a browser tool can follow it unattended, and HITL confirmation at follow time is a policy the proxy cannot enforce. Acceptance tests deferred until the §8 Q-1 session model is decided. |
| **R-4** | P1 | Enforce RFC 8707 resource indicators on the inbound flow. **(PRM serving is already done.)** | *Already done (verify-only):* `/.well-known/oauth-protected-resource` is served (`oauth_metadata.py:239`) and `OIDC_AUDIENCE` is enforced in production (`config.py:407-413`), advisory in lab. *Remaining work:* inbound flow sends `resource=<canonical /mcp URI>` and the proxy **rejects tokens whose audience ≠ the gateway in lab too** (today advisory). **Keycloak-side dependency:** the client must add an audience mapper and emit `resource`. Test: wrong-`aud` token → 401 in lab; migration/grace window for existing dynamically-registered lab clients. |
| **R-5** | P1 | Per-client consent before downstream (Entra) redirect — the MCP confused-deputy MUST. **(No consent gate exists today. Design: `docs/ADR/003-enrollment-consent-gate.md`.)** | `consent.py` is explicitly **NOT ENFORCED** and governs mode-changes, not enrollment; `/auth/enroll/{svc}` redirects straight to Entra. Build: first enrollment for a given `(client_id, service, scopes)` shows a server-rendered page naming client + **exact scopes** + exact redirect; server-side state set *only after* consent; exact `redirect_uri` match; **scope recorded and re-checked on scope upgrade** — requires a schema change (the callback UPSERT at `oauth.py:154-163` has no scope comparison and `credential_store` has no `scopes` column): add `scopes TEXT NOT NULL`, store the consented scope set, and replace the unconditional UPSERT with compare-then-re-consent. **Cookie decision (not a note):** `__Host-` is origin-bound and the lab runs proxy and lab-nginx on different hosts — either (a) serve enrollment+consent from a single origin, or (b) document the weaker `Secure`+`SameSite=Lax` binding and its implications. Pick one in the design. Test: skipping consent, reusing state, or a silent scope upgrade is rejected. |
| **R-6** | P1 | Token-vault hardening — **4 separately-testable sub-requirements.** | **R-6a baseline scopes:** minimal default (e.g. `User.Read`); a config validator/test enforces the baseline. **R-6b step-up (design spike, blocks before build):** broader scopes via `WWW-Authenticate scope=`. This is a *prerequisite design task*, not a testable requirement — the interface contract (who issues the challenge, on which path, how the broker detects insufficient scope) must be defined and reconciled with R-5's consent flow **before** R-5 is built, or R-5 will be rebuilt. Do not mark R-6 "done" while R-6b is unspecified. **R-6c rotation:** refresh-token rotation on every mint — *already done* (`broker.py:130-136`); add regression test. **R-6d revocation:** a `DELETE /auth/enroll/{svc}` route deletes the `credential_store` row + emits audit — *route does not exist.* **Plus a Vault/KMS recovery runbook:** broker fails closed on Vault loss (done), but document what happens to vaulted blobs on master-secret rotation / Vault data loss (re-enrollment path), or mark explicitly out of scope. |
| **R-7** | P2 (document-only) | Generalize beyond m365: declarative downstream-provider registry. | **Largely already implemented** — `oauth.py:31-62` ships `m365`, `bitbucket`, `dex` adapters behind a `_get_adapter` factory; adding a provider is already a new adapter class + registry entry. Reframe as: *document the existing extension point and add a regression test for a second provider.* Do not build a new abstraction (gold-plating). |
| **R-8** | P2 | Admin visibility: list/revoke a user's enrolled downstream credentials in the portal. | Portal shows `(user, service, enrolled_at, last_used)` and a revoke action; revoke writes audit + removes the vault row. |

### Out of scope (this PRD)

- Keycloak→Graph OBO and Entra federation of Keycloak identities (topology change — see §1 non-goal).
- App-only Graph access (`entra_client_credentials`) — already exists, unchanged.
- Migrating IdP #1 from Keycloak to Entra (would enable OBO but is a different product decision).

---

## 4. Security non-negotiables (must hold)

- **INV-001** synchronous audit on enroll, mint, invoke, revoke. Audit failure = 500.
- **INV-002** no raw refresh/access tokens in logs — `[REDACTED:*]` only.
- **INV-003/004** OPA deny-default and fail-closed remain *upstream* of credential injection.
- **No token passthrough** (MCP spec): the Keycloak token is never forwarded to Graph; the Graph token is independently issued and vaulted.
- **No bespoke crypto**: `cryptography` AES-256-GCM + HKDF-SHA256 only.
- Every new table/column written by the proxy gets explicit `GRANT`/`REVOKE` (INV-011).

---

## 5. Success metrics

Each metric below needs an instrumentation plan, not just a target — none is measurable today as written.

- **Time-to-first-Graph-call** for a new user: from "manual: find URL, log in, retry" to **one click** with auto-retry. *Instrument:* a structured audit-event field stamping the interval between the first `enrollment_required` deny and the first successful Graph response; record the "before" baseline first.
- **Zero** delegated calls that reach Graph as the app identity when a user identity exists. *Instrument:* an alert query correlating `client_id` presence in `credential_store` with `injection_mode` used; no such query exists yet.
- **100%** of inbound tokens audience-validated. *Caveat:* not achievable until `OIDC_AUDIENCE` (or RFC 8707 `resource`) is **required in lab too** (today advisory in non-prod) and Keycloak emits the right `aud`. This is a P1 (R-4) exit criterion, not an MVP one.
- **0** confused-deputy findings in the next appsec review — contingent on R-5 being implemented (it is not today); not a standalone metric.

---

## 6. Phasing & handoff

| Phase | Scope | Exit |
|---|---|---|
| **P0 — Seamless MVP (the user's actual ask)** | R-1, R-3a | A user invokes a Graph tool, is handed a clickable enrollment link, completes the Entra login once, and the call succeeds on retry **in the same authenticated browser session** — all audited. **Security note:** today's `enrollment_url` is unsigned and session-dependent — opened in a fresh/incognito browser it binds the credential to whoever authenticates next (the R-3b gap). P0 is acceptable for a **supervised demo**, not unsupervised agentic use. Post-enrollment access is seamless **only when Vault + `ENTRA_*` are configured** (broker disabled → generic 500, not a Graph response). |
| **P1 — Spec & confused-deputy hardening** | R-2, R-3b, R-4, R-5, R-6 | Per-tool tenancy enforced; self-authenticating deep-link; resource indicators enforced; per-client consent gate; vault rotation/revocation/least-privilege/recovery proven. AppSec sign-off. |
| **P2 — Generalize & operate** | R-7 (document-only), R-8 | Existing multi-provider extension point documented + a second-provider regression test; admin revoke UI. |

> **Reality check (from critic review):** R-1 is essentially already wired (`CredentialEnrollmentRequiredError` returns an `enrollment_url` in a `-32010` error). So **P0 is small** — mostly confirming the link surfaces cleanly in the target client. **But "post-enrollment already works" is conditional:** it requires `VAULT_TOKEN` + broker initialized and `ENTRA_CLIENT_ID/SECRET/TENANT_ID` set; with Vault absent the broker is disabled and the invocation returns a generic 500, not a Graph response. The bulk of this PRD is P1 hardening the user did not explicitly ask for but which is needed to call the path production-grade. Be explicit with stakeholders that "seamless Graph access" (the dream) is largely deliverable in P0 **for a supervised demo**; the rest is safety.

**Architect handoff (before build):**
1. **R-3b** is the load-bearing design: resolve the session-reassociation problem (how a fresh browser with no proxy session completes enrollment bound to the right `client_id`) and the token-in-URL leak model **before** writing any acceptance test.
2. Confirm MCP client capabilities: which clients (Claude Code, etc.) honor `elicitation` vs. only render `_meta` text — drives R-3a fallback and whether auto-open is ever feasible.
3. **R-2** requires a dispatch/adapter refactor (thread `tool_record.entra_*`), not just a migration seed — confirm the per-tool adapter factory design.
4. **R-4** delta is RFC 8707 `resource` enforcement + a Keycloak audience-mapper change, **not** flipping `OIDC_AUDIENCE` (already enforced in prod). Plan a grace window for existing lab clients.

**TDD note (per `docs/DEV-TEST-PROCESS.md`):** each requirement starts with a failing test naming the INV it touches; credential-path changes are security-critical → dispatch `appsec-reviewer` before merge.

---

## 7. External prerequisites (Entra / Keycloak — not code, but blockers)

None of these are automatable by this PRD; all are required before any P0 acceptance test runs against a real tenant.

1. **Entra app registration** in the target tenant (an Azure-admin action). Choose **single-tenant** (`ENTRA_TENANT_ID` = the tenant GUID) vs **multi-tenant** (`common`) — this determines the authority URL and who can enroll.
2. **Redirect URI registration** — `ENTRA_REDIRECT_URI` must be registered on the app reg, or enrollment fails with `AADSTS50011`. It must exactly match what the proxy builds, which depends on `PROXY_BASE_URL` (or the derived `Host`) — a mismatch silently breaks enrollment.
3. **Delegated Graph permissions + admin consent** — `User.Read`, `Mail.Read`, `Calendars.Read`, etc. granted and admin-consented; non-`User.Read` scopes need a tenant admin.
4. **`offline_access` must be permitted** — the adapter always appends `offline_access` to the scope request (`m365.py:41`); if the app reg disallows it, Entra returns no refresh token, the broker stores a non-refreshable credential, and the *second* mint fails opaquely. Ensure the app permits `offline_access`.
5. **Client-secret lifecycle** — `ENTRA_CLIENT_SECRET` expires (1/2/24 mo); on rotation the broker fails closed for all users until the env is updated and the container restarted. Track expiry.
6. **Keycloak `mcp-audience` mapper** — required for the existing lab to emit `aud: mcp-proxy`, and a precondition for R-4.
7. **Proxy/broker env (not Azure, but required for any of this to work):** `VAULT_TOKEN` + `BROKER_MASTER_SECRET_PATH` (broker is disabled/fail-closed if unset), `ENTRA_CLIENT_ID`, `ENTRA_CLIENT_SECRET`, `ENTRA_TENANT_ID`, `ENTRA_REDIRECT_URI`, `ENTRA_SCOPES`, `PROXY_BASE_URL`.

## 8. Open questions

- **R-3b:** ~~does the self-authenticating link carry `client_id`…~~ **Decided in `docs/ADR/002-enrollment-deep-link-session-model.md` (Proposed):** signed, single-use, ≤300s, identity-bound link-token issued only to an authenticated caller, two-phase (link-token consumed at `/auth/enroll` → PKCE state survives to callback), no unattended LLM follow; **OAuth Device Authorization Grant (RFC 8628) is the recommended fallback** if AppSec rejects the bearer-in-URL residual risk. AppSec sign-off required before build.
- **R-3a:** do we even attempt browser auto-open, or only surface a clickable link? Recommendation: clickable link + `elicitation` where supported; auto-open is best-effort and likely out of reach for CLI clients.
- **R-4:** enforcing audience/`resource` in lab will break existing dynamically-registered clients lacking the `mcp-audience` mapper — confirm the migration/grace window.
- **R-7:** is a second downstream provider actually on the roadmap, or is m365 the only target? If m365-only, R-7 stays document-only (the extension point already exists) — do not build a new abstraction.
- **Vault recovery:** is a master-secret-rotation / Vault-data-loss recovery runbook in scope (R-6), or explicitly deferred? Today loss = all vaulted credentials unreadable, silent re-enrollment required.
