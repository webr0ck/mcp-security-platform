# ADR-003: Per-Client Enrollment Consent Gate (R-5)

Status: Accepted — conditions met (C4–C9 all closed; implemented 2026-06-09)
Date: 2026-06-09
Authors: System Architect
Deciders: Core team + AppSec

Relates to: `docs/PRD-delegated-downstream-auth.md` R-5; `docs/ADR/002-enrollment-deep-link-session-model.md` (R-3b lands the browser *on* this consent page); MCP Authorization spec — Security Best Practices, confused-deputy MUST.

---

## Context

Before the gateway redirects a user to Entra to authorize delegated Graph access, the MCP Authorization spec requires an explicit, per-client consent step. Verified current behavior (`proxy/app/routers/oauth.py`):

- `GET /auth/enroll/{service}` resolves the authenticated `client_id`, mints a PKCE pair + nonce, stores `{client_id, service, cv}` in Redis, and **immediately `302`s to Entra** (`oauth.py:97-115`). **There is no consent page, no scope display, no "state set only after consent."**
- `GET /auth/callback/{service}` exchanges the code and does an **unconditional, scope-blind UPSERT**: `ON CONFLICT (user_sub, service) DO UPDATE SET encrypted_blob=:blob` (`oauth.py:155-163`). A later enrollment with *broader* scopes silently replaces the credential with no re-consent.
- `credential_store` has **no `scopes` column** (V006) — there is nothing to compare a scope upgrade against.
- `consent.py` exists but is **NOT ENFORCED** and is shaped for `server_registry` mode-change transitions (`old_mode`/`new_mode`/`cred_ref`), **not** OAuth scope consent. Its HMAC-signed, single-use-`jti` *mechanism* is reusable; its *payload* is not.

### Why this matters (threat)

1. **Confused-deputy (the MCP MUST):** the proxy is an OAuth client to Entra using a static client registration. Without a consent step bound to the requesting MCP client + exact scopes + exact redirect, an attacker who can reach an authenticated `/auth/enroll` (or, post-R-3b, who steals a link-token) can drive an OAuth flow the user never knowingly approved.
2. **Silent scope escalation:** a tool's `entra_scope` is widened (or a malicious re-enrollment requests more), and the scope-blind UPSERT grants it with zero user awareness.
3. **No scope transparency:** the user is sent to Entra without the gateway ever telling them *which* client is asking for *what*. (Entra shows its own consent, but that is the downstream IdP's screen, not the gateway's attestation of the requesting MCP client.)

---

## Decision

**Insert a server-rendered consent interstitial into the enrollment flow, mint the PKCE `state` only after explicit consent, record the consented scope set, and require fresh consent on any scope upgrade.** Use server-side consent state (Redis) + a CSRF-protected form rather than depending on a `__Host-` cookie, so the design survives the lab's multi-host topology.

### D1 — Consent interstitial replaces the straight-to-Entra redirect

`GET /auth/enroll/{service}` no longer `302`s to Entra. Instead it renders a server-side HTML consent page that displays, from the resolved `tool_registry`/adapter config:

- the requesting **MCP client identity** (`client_id`),
- the **service** (e.g. `m365`) and target (Microsoft Graph),
- the **exact delegated scopes** being requested (from `tool_registry.entra_scope` once R-2 lands, else `ENTRA_SCOPES`), and on a scope upgrade, the **additions highlighted** vs. the stored set,
- the **exact `redirect_uri`** that will be used (adapter-owned, must match the Entra app registration).

A single **Approve** action `POST`s to `/auth/enroll/{service}/consent`.

### D2 — State set only after consent; server-side, CSRF-protected, single-use

This satisfies the spec's "single-use server-side `state` set only *after* consent."

- At **GET** time the proxy stores a pending-consent record in Redis (`enroll_consent:{csrf}` → `{client_id, service, requested_scopes, exp≤300s}`) and embeds an unguessable **CSRF token** in the form. **No PKCE `state` / `cv` is minted yet.**
- At **POST `/consent`** the proxy: validates the CSRF token against the Redis record (atomic get+del — single-use), re-confirms `client_id == request.state.client_id` (or, for the R-3b path, the link-token's bound `client_id`), **then** mints the PKCE pair + `state` nonce (the existing `{client_id, service, cv, scopes}` Redis record) and `302`s to Entra.
- **Rationale for Redis-state over `__Host-` cookie:** `__Host-` requires same-origin + `Secure` + no `Domain`; the lab runs the proxy (`:8000`) and lab-nginx (`:443`) on different origins, so a `__Host-` cookie set by one is unreadable by the other. Server-side consent state keyed by a form CSRF token has no origin-binding fragility. A `__Host-`/`SameSite=Strict` cookie MAY be added as defense-in-depth **only if** the whole enroll→consent→callback sequence is served from a single origin; it must not be load-bearing.

### D3 — Record consented scopes; re-consent on upgrade

- New migration adds `credential_store.scopes TEXT NOT NULL DEFAULT ''` (space-separated, sorted-canonical). Backfill existing rows to the current `ENTRA_SCOPES` value with a one-time note that they predate consent tracking.
- The callback UPSERT stores the **consented** scope set alongside the encrypted blob.
- On a fresh enrollment request, the proxy diffs `requested_scopes` against the stored row's `scopes`:
  - requested ⊆ stored → still show consent (first-class transparency) but flag "no new permissions";
  - requested ⊋ stored (upgrade) → consent page **highlights the additions** and approval is mandatory; the credential is replaced only after this consent.
- Replace the unconditional `DO UPDATE SET encrypted_blob` with a path that also sets `scopes` and only runs post-consent.

### D4 — Generalize `consent.py`, don't overload it

Refactor `consent.py` into a generic signed-consent core (HMAC-SHA256 over canonical JSON, single-use `jti`) with **two payload types**: the existing `ModeChangePayload` and a new `EnrollmentConsentPayload {client_id, service, scopes_hash, jti, iat, exp}`. Reuse the `jti`-burn table pattern for single-use. Do not stretch `old_mode/new_mode` to mean scopes. This keeps the proven mechanism and gives R-5 a payload that actually fits. (Server-side Redis consent state from D2 covers the in-flow CSRF/single-use need; the signed `EnrollmentConsentPayload` is the durable, auditable attestation recorded with the enrollment.)

### D5 — Composition with R-3b and audit

- **R-3b lands here:** the signed link-token (ADR-002) is consumed at `GET /auth/enroll`, which renders *this* consent page; the PKCE `state` is minted at `POST /consent` per D2 — so "state only after consent" and "link-token single-use at click" compose cleanly.
- **INV-001:** emit a synchronous audit event on **consent grant** (`event_type=CREDENTIAL_CONSENT`, includes `client_id`, `service`, `scopes_hash`, `jti`) *and* on enrollment completion (existing `_emit_credential_audit`). A consent POST that fails CSRF/expiry is audited as a deny.
- **INV-002:** never log scopes-bearing URLs or the refresh token; the consent record holds a `scopes_hash` for correlation, scopes in plain only on the rendered page.

---

## Alternatives considered

### A. `__Host-` cookie consent gate (as the PRD draft implied) — REJECTED as primary
Origin-bound; breaks in the lab's multi-host setup and any deployment where enroll and callback traverse different hosts. Retained only as optional single-origin defense-in-depth (D2).

### B. Rely on Entra's own consent screen, no gateway consent — REJECTED
Entra's screen attests the *downstream* grant, not *which MCP client* requested it, and does nothing about gateway-side confused-deputy or the scope-blind UPSERT. The MCP spec's MUST is specifically a *gateway/proxy* obligation.

### C. Skip the interstitial, add only scope-diff re-consent at callback — REJECTED
Too late: by callback the user has already authenticated at Entra and a token exists. Consent must gate the *redirect*, not the *storage*.

---

## Consequences

**Positive:** closes the confused-deputy MUST; gives scope transparency + an auditable consent attestation; kills silent scope escalation; composes cleanly with R-3b; survives multi-host (no `__Host-` dependency).

**Negative / obligations:**
- Adds a click to the flow (consent → Entra). Acceptable; it is the security feature.
- New migration + `credential_store` schema change (needs explicit `GRANT`/`REVOKE` review per INV-011 — the existing grant already covers `UPDATE`).
- `consent.py` refactor touches a security-critical primitive → `appsec-reviewer` sign-off; preserve the existing `ModeChangePayload` behavior and tests.
- Build order: **R-5 (this) before R-3b**, because R-3b's link-token lands on this page and ADR-002's residual-risk mitigation depends on the consent step existing.

**Acceptance (once Accepted):** skipping consent (POST without a valid Redis consent record) is rejected; CSRF token reuse is rejected; a scope upgrade without fresh consent is rejected; PKCE `state` does not exist in Redis until after a valid `POST /consent`; consent grant and denial both emit synchronous audit events (INV-001); no scopes/tokens in logs (INV-002); existing `ModeChangePayload` consent path unchanged.

---

## Open questions deferred to build

- Consent-page UI: standalone server-rendered HTML (matches the existing callback `HTMLResponse`) vs. the htmx portal. Lean: minimal standalone HTML, same origin as `/auth/enroll`.
- Scope-canonicalization rule (sort + lowercase? dedupe?) so the stored/requested diff is stable.
- Whether `auditor`/`readonly` principals may ever enroll, or only `agent`/owner roles (RBAC interaction — confirm against `docs/RBAC.md`).
- TTL alignment: consent Redis record (≤300s) vs. the existing `_PENDING_TTL_SECONDS` PKCE window — keep them independent (consent precedes PKCE).

---

## AppSec sign-off (2026-06-09) — blocking conditions before merge

Verdict: **APPROVED-WITH-CONDITIONS.** The Redis-state + CSRF-form model is the right choice for the multi-host topology and satisfies the confused-deputy "state only after consent" MUST. Binding conditions:

| # | Condition | Severity | Status | Proof |
|---|---|---|---|---|
| **C4** | `POST /auth/enroll/{service}/consent` MUST derive `client_id` **exclusively from the server-side Redis consent record** (keyed by the CSRF token). It MUST NOT accept `client_id` from any client-supplied param (body/query/header). | HIGH | **CLOSED** | `test_c4_client_id_from_redis_not_body` — `oauth.py:enroll_consent()` reads `client_id` only from `json.loads(raw)` where `raw = await get_and_delete(redis, consent_key)` |
| **C5** | CSRF-token validation at POST MUST use **atomic GET+DEL** — a non-atomic GET-then-DEL allows double-submit → two Entra redirects on one consent. | HIGH | **CLOSED** | `test_get_and_delete_uses_getdel_not_pipeline`, `test_c5_csrf_single_use_second_post_rejected` — `redis_atomic.get_and_delete()` uses `redis.getdel()` (Redis ≥6.2); `oauth.py:enroll_consent()` calls it |
| **C6** | The callback UPSERT MUST write `scopes` from the value stored in the Redis `oauth_flow:` record **at consent/mint time**, never re-read `tool_registry` at callback time. TOCTOU documented as known limitation. | MEDIUM | **CLOSED** | `test_c6_callback_stores_scopes_from_flow_record` — `oauth.py:callback()` reads `consented_scopes = flow.get("scopes", "")` and writes it to `credential_store.scopes` |
| **C7** | `EnrollmentConsentPayload` single-use MUST NOT reuse `consume_consent_token()`/`mode_change_consent`. Use **Redis GET+DEL**; signed payload is durable audit attestation only. Keep `ModeChangePayload` behavior-identical. | HIGH | **CLOSED** | `test_enrollment_payload_does_not_use_mode_change_consent_table` (AST-strips docstrings); `test_mode_change_*` regression guard (4 tests); `consent.py:issue_enrollment_consent_token` + `verify_enrollment_consent_token` have no DB interaction |
| **C8** | Unit test MUST assert a consent POST with invalid/expired CSRF emits a **synchronous `outcome=deny` / `CREDENTIAL_CONSENT_DENIED` audit before** the 4xx (INV-001). | MEDIUM | **CLOSED** | `test_c8_invalid_csrf_emits_deny_audit_before_4xx` — `_emit_consent_denied_audit` mock captured and verified called before HTTP response |
| **C9** | The migration adding `credential_store.scopes` MUST include an INV-011 comment confirming V006's existing `GRANT … TO proxy_app` covers the new column. | LOW (non-blocking) | **CLOSED** | `V024__credential_store_scopes.sql` — explicit comment cites V006 grant |

**Build order enforced: R-5 (this) before R-3b (ADR-002)** — merging R-3b without R-5 green would land the link-token on a blank Entra redirect with no consent/scope gate, a *worse* posture than today's unsigned URL.

### Implementation summary (2026-06-09)

- `proxy/app/core/redis_atomic.py` — `get_and_delete()` using `redis.getdel()` (C5)
- `proxy/app/services/consent.py` — `EnrollmentConsentPayload` + `issue_enrollment_consent_token` + `verify_enrollment_consent_token` added; `ModeChangePayload` path unchanged (C7)
- `proxy/app/routers/oauth.py` — `GET /auth/enroll/{svc}` renders consent HTML (D1); `POST /auth/enroll/{svc}/consent` is the new gate (C4/C5/C8/D2); callback UPSERT now scope-aware (C6); `_emit_consent_denied_audit` + `_emit_consent_grant_audit` added (C8/INV-001)
- `infra/db/migrations/V024__credential_store_scopes.sql` — adds `scopes TEXT NOT NULL DEFAULT ''` with INV-011 comment (C9)
- `proxy/requirements.txt` — `python-multipart==0.0.32` added (required for Form data)
- `proxy/tests/unit/test_enrollment_consent_gate.py` — 30 new tests, all green
- `proxy/tests/unit/test_oauth_router.py` — `test_enroll_mints_nonce_and_pkce` updated to `test_enroll_renders_consent_page` (reflects new D1/D2 behavior)
