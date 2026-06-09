# ADR-002: Enrollment Deep-Link Session Model (R-3b)

Status: Accepted with conditions (AppSec sign-off 2026-06-09 — C1, C2, C3 blocking before merge; RFC 8628 primary for `agent` principals)
Date: 2026-06-09
Authors: System Architect
Deciders: Core team + AppSec

Relates to: `docs/PRD-delegated-downstream-auth.md` R-3b / §8 Q-1; `docs/ARCHITECTURE-delegated-auth.md` §4.

---

## Context

A user authenticates to the MCP gateway via Keycloak (OAuth 2.1 PKCE) and invokes a delegated tool (`m365-graph`). If they have no vaulted Entra credential, the gateway returns a `-32010` error carrying an `enrollment_url` (`mcp_server.py:361-376`). The user must open that URL, complete an Entra login, and the proxy vaults the resulting refresh token bound to their identity.

**The problem (precise — corrects an earlier mis-diagnosis).** Today `client_id` is bound at `/auth/enroll/{svc}` from `_authenticated_client_id(request)` — i.e. from `request.state.client_id` set by `AuthMiddleware` (mTLS CN / OIDC sub / API key) — and stored server-side in Redis under an unguessable nonce (`oauth.py:99-110`). The callback reads `client_id` from Redis, not from the URL. So `client_id` does **not** leak via the URL. The actual gap is different:

> The `enrollment_url` is **unauthenticated**. When it is opened in a *fresh* browser (the normal case — the MCP client's browser is not the proxy's authenticated session), there is no proxy session, so `_authenticated_client_id` fails or resolves to **whoever authenticates next**. The callback cannot associate the browser back to the original API caller. Result: either enrollment is impossible (no session) or the credential is bound to the wrong identity.

This is the load-bearing P1 design decision: **how does a fresh, sessionless browser complete enrollment bound to the correct, already-authenticated MCP caller?**

### Forces

1. **Seamlessness (the user's stated goal):** "browser opens, user logs in once, done." Argues for a single clickable link.
2. **No bearer-in-URL leakage:** any auth-bearing token in a URL leaks to access logs, `Referer`, browser history, and LLM context windows (INV-002 spirit).
3. **Agentic-LLM hazard:** the calling agent has browser/fetch tools and could follow an enrollment link *unattended*, completing an OAuth flow with no human present.
4. **Confused-deputy:** if an attacker obtains an unconsumed link bound to victim `client_id`, they could complete the Entra step with **their own** Microsoft account, binding the attacker's refresh token into the victim's vault row → victim's Graph calls then act as the attacker. This is the dangerous case.
5. **Reference-build pragmatism:** this is a learning/reference implementation, not a production gateway; the bar is "demonstrably correct and honestly bounded," not "hardened for hostile internet."

---

## Decision

**Adopt a signed, single-use, short-TTL, identity-bound enrollment link-token, issued only to an already-authenticated MCP caller, with a two-phase token model. Explicitly forbid unattended (agentic) follow.** Record the OAuth 2.0 Device Authorization Grant as the recommended hardening alternative if AppSec rejects the bearer-in-URL residual risk.

### Mechanism

1. **Issuance (authenticated):** the link-token is minted **only** server-side at the moment the gateway raises enrollment-required — i.e. inside an already-authenticated MCP call. Payload: `{client_id, service, exp (≤300s), jti}`, HMAC-signed with a dedicated server key (derive from `PROXY_SECRET_KEY`, separate `info`). Issuance therefore *requires* a valid MCP authentication; an anonymous party cannot mint one.
2. **Two-phase token (resolves the R-3b timing contradiction):**
   - **Phase 1 — link-token, consumed at `/auth/enroll/{svc}`.** The GET validates the HMAC, checks `exp`, and **atomically consumes `jti`** from a Redis replay store (single-use *at link-click*). On success it reconstructs `client_id` **from the signed token**, bypassing `_authenticated_client_id` for this path *by design* (that is the whole point — the browser has no session).
   - **Phase 2 — PKCE `state` nonce.** Phase 1 then mints the normal PKCE `state` nonce (existing `oauth.py` flow) which is what survives the Entra round-trip to `/auth/callback/{svc}`. The link-token is **not** what must survive to callback — that was the self-contradiction in the draft requirement. A transient Entra failure leaves the link-token consumed but is recoverable by re-issuing a fresh link on the next tool call (issuance is cheap and authenticated).
3. **Bearer hygiene:** the link-token rides in the URL (unavoidable for a clickable link). Mitigate: (a) ≤300s TTL; (b) single-use `jti` so a *consumed* leaked link is inert; (c) scrub `/auth/enroll/*` query strings from Nginx + app access logs (INV-002); (d) bind `client_id` in the signature so the link cannot be retargeted to a different victim.
4. **No unattended follow:** the link is delivered to a human (the `-32010` `instructions`), never auto-followed. The proxy cannot *enforce* human-in-the-loop at follow time, so this is stated as a **policy + client-integration requirement**, not a system guarantee — and the docs must not claim the link is "safe to pass through an LLM."
5. **Consent binding (depends on R-5):** the Entra-side login should still be gated by the per-client consent page (R-5) showing the exact scopes; this is what reduces force-4 confused-deputy to "attacker must also win the race within 300s AND complete Entra login as the victim." Sequence R-5 design before R-3b build.

### Residual risk (must be signed off by AppSec)

A link-token stolen **before** consumption, within its ≤300s window, lets the thief reach the Entra consent screen bound to the victim's `client_id`. If the thief completes consent with their own Entra account, the victim's vault row is poisoned. Single-use + short-TTL + log-scrubbing + R-5 consent shrink but do not eliminate this. **If AppSec judges this unacceptable, fall back to the alternative below.**

---

## Alternatives considered

### A. Require an existing proxy session (no token, no bypass) — REJECTED
The enrollment link only works if opened in a browser that already holds the proxy's authenticated session. Eliminates the bearer-in-URL problem entirely. **Rejected** because the MCP client's browser is generally *not* the proxy session (CLI clients have no browser session at all), so it breaks the seamless goal in the common case and frequently makes enrollment impossible.

### B. OAuth 2.0 Device Authorization Grant (RFC 8628) — PRIMARY for `agent` principals (per AppSec 2026-06-09)
The gateway initiates a device-code flow: returns a `user_code` + `verification_uri`; the user opens `microsoft.com/devicelogin` (any browser, any device) and enters the code; the gateway polls for completion and binds the result to the **authenticated** MCP caller who started the flow. **No bearer token in any URL**, no fresh-browser association problem (the device code is entered by the human, the poll is bound to the API caller server-side), and unattended agentic completion is structurally harder (a code must be typed by a human). **Trade-off:** slightly less seamless than a clickable link ("type this code" vs. "click here"); requires Entra device-code flow to be enabled on the app registration.

> **AppSec ruling (2026-06-09):** implement **RFC 8628 as the PRIMARY enrollment mechanism for `principal_type == "agent"`** (headless/mTLS/API-key callers — exactly where the deep-link's pre-consumption-theft and agentic-follow risks are most exploitable). The signed deep-link (the chosen mechanism above) is retained **only for `principal_type == "human"`** (OIDC browser-session callers). Route by `principal_type` (already set in `auth.py:_build_principal_id`); **do not implement both for the same principal type.** Build the RFC 8628 path for `agent` before the deep-link for `human`.

### C. Bind the link-token to the original authentication via a server-set, short-TTL cookie at issuance — PARTIAL
Set a `__Host-` cookie on the MCP response and require it at `/auth/enroll`. Defeats the purpose: the MCP client (often a CLI) and the browser don't share a cookie jar, so this collapses back to alternative A in practice. Noted but not viable for cross-agent/browser flows.

---

## Consequences

**Positive:** delivers the seamless clickable-link UX; resolves the R-3b timing contradiction via the two-phase model; issuance requires authentication, so the surface is "leak of a short-lived single-use token," not "open enrollment endpoint."

**Negative / obligations:**
- Introduces a new (intentional) unauthenticated-by-token path at `/auth/enroll/{svc}` — must be implemented exactly: HMAC verify → `exp` check → atomic `jti` consume → only then proceed. Any deviation (e.g. non-atomic consume) reopens replay.
- Requires log-scrubbing for `/auth/enroll/*` query strings (Nginx + app).
- Carries a residual pre-consumption-theft risk that **must** be AppSec-signed-off, or fall back to B (device code).
- Depends on R-5 consent (`docs/ADR/003-enrollment-consent-gate.md`) for its strongest mitigation → R-5 design must precede R-3b build; the R-3b link-token lands on the R-5 consent page.
- "Safe to pass through an LLM" must never be claimed; human-click is a policy requirement the proxy cannot enforce.

**Testability (acceptance, once this ADR is Accepted):** token not present in any log line (INV-002); replay of a consumed `jti` is rejected; a token whose `client_id` is altered fails HMAC; expiry past `exp` is rejected; transient Entra failure followed by a fresh tool call yields a new working link; the Entra step is gated by R-5 consent.

---

## Open questions deferred to build

- Exact key separation: dedicated `ENROLLMENT_LINK_KEY` vs. HKDF-derived from `PROXY_SECRET_KEY`. (Lean: derive, to avoid another required secret.)
- Whether to promote alternative B (device code) to primary for the `agent` principal type (headless callers), keeping the link-token for `human` principals.
- Redis key schema + TTL for the `jti` replay store (reuse the existing `oauth_flow:` namespace pattern).

---

## AppSec sign-off (2026-06-09) — blocking conditions before merge

Verdict: **APPROVED-WITH-CONDITIONS.** The two-phase model is sound and the residual pre-consumption-theft risk is **accepted with disclosure for the reference build** (entry requires a prior authenticated MCP call; 300s single-use window; documented without overclaim). The following are binding:

| # | Condition | Severity |
|---|---|---|
| **C1** | The link-token `jti` replay store MUST use an **atomic GET+DEL** — Redis Lua `GET/DEL` script or `getdel()` (Redis ≥6.2). The existing `oauth.py` callback `pipe.get + pipe.delete` pipeline is **not** atomic and must not be copied for the jti store. | HIGH |
| **C2** | The link-token signing key MUST be **HKDF-SHA256-derived from `PROXY_SECRET_KEY` with a distinct `info`** (e.g. `b"enrollment-link-token-v1"`) — never signed with `PROXY_SECRET_KEY` directly (it already signs session JWTs + `consent.py`). Use `cryptography` HKDF (no bespoke crypto). | HIGH |
| **C3** | The `-32010` `instructions` field MUST carry an explicit **human-action-required marker**: "requires a human to open in a browser; do not forward or fetch automatically; expires in 300s, single-use." Wires the "never claim LLM-safe" stance into the emitted data. | MEDIUM |
| Rec | RFC 8628 is **primary for `agent` principals** (folded into Decision/Alt-B above). | — |

Residual risk explicitly accepted for the reference build; **if promoted to production, adopt RFC 8628 universally.** No merge of R-3b code until C1–C3 are closed and **R-5 (ADR-003) is green** (build order, below).
