# Architecture — Delegated Downstream Auth (User → IdP1 → Gateway → Entra → Microsoft Graph)

**Version:** 1.0.0
**Date:** 2026-06-09
**Status:** Canonical for the delegated-auth subsystem. Extends `docs/ARCHITECTURE-v2.md` §2/§3. Companion PRD: `docs/PRD-delegated-downstream-auth.md`.

Status legend: ✅ implemented & wired · 🟡 partial/overclaimed · 🔴 stub/missing · 🆕 exists in code, undocumented · ⚠️ security note.

---

## 0. The question this answers

> Can a user authenticate to the MCP gateway via **IdP #1 (Keycloak, OAuth 2.1 PKCE)**, and have the gateway then call **Microsoft Graph as that same user** (delegated, not app-only) — ideally with the Entra login opening automatically and seamless Graph access thereafter? Is there any MCP gateway that does this?

**Verdict: yes, it is possible — and this repo already implements the right architecture for a Keycloak-fronted gateway.** But not as a single token hand-off, and the architecture (token vault + per-user downstream enrollment) is a well-established pattern, not a novel one. The reason it can't be a single hand-off is an identity-provider constraint, explained below.

---

## 1. The load-bearing constraint: you cannot OBO a Keycloak token at Entra

There are two textbook patterns for "gateway calls a downstream API as the user":

| Pattern | How it works | Works here? |
|---|---|---|
| **A. Token Exchange / On-Behalf-Of** (RFC 8693 / Entra OBO) | Gateway presents the *inbound* user token to the downstream token endpoint and trades it for a downstream token. | 🔴 **Not via the standard OBO grant.** Entra's OBO grant requires the assertion to be an **Entra-issued** token (correct `iss`, signed with an Entra key) whose `aud` is the gateway's Entra app registration. A Keycloak token (`iss=keycloak`, `aud=mcp-proxy`, Keycloak-signed) does not qualify, so the standard OBO call fails. **This is a configuration/topology constraint, not a literal impossibility** — see the federation note below. |
| **B. Independent downstream enrollment + token vault** | Gateway is an OAuth **client** to Entra. On first use it runs a *separate* `authorization_code + PKCE` login against Entra (browser opens, user consents), stores the resulting **refresh token** per-user, and mints Graph access tokens on demand. | ✅ **Yes.** This is what the repo does via the `entra_user_token` injection mode. The user's Keycloak identity is the *vault key*; Entra issues the actual Graph credential. |

**Pattern B is the right choice whenever IdP #1 ≠ the downstream IdP and you are unwilling to change tenant federation topology.** It is also the pattern every comparable product uses for federated downstream access: Auth0 **Token Vault**, Cloudflare `workers-oauth-provider` (upstream OAuth, tokens stored in encrypted props), Azure APIM **Credential Manager**, WorkOS/Stytch **connected apps**.

> **Federation caveat (why "impossible" is too strong).** There *are* supported Microsoft paths to make Entra accept an external identity, but they are two distinct mechanisms — don't conflate them: **(a) Workload Identity Federation / federated identity credentials** (`urn:ietf:params:oauth:grant-type:jwt-bearer`) is for **workload/app-level** tokens (the GitHub-Actions/managed-identity pattern), *not* user sign-in; **(b) Entra External ID** OIDC/SAML federation is for **user sign-in** across IdPs (register Keycloak as an enterprise IdP). The catch for our use case: **user-delegated** Graph scopes via a federated foreign identity are not a turn-key scenario in either — they require tenant-admin topology changes that are out of scope. Given IdP #1 is fixed at Keycloak and we are not changing tenant federation, **Pattern B is the correct choice.** Pattern A becomes available only if the org later federates Keycloak users into Entra via (b).

> Pattern A (`oauth_user_token`, RFC 8693) **does** work in this repo — but only for **Keycloak→Keycloak** identity chaining (exchanging the caller's KC token for a *different KC audience*), never for Keycloak→Graph. The codebase is honest about this: non-OIDC and session/browser callers fail closed in that mode (`CLAUDE.md` known-gaps; `dispatcher.py`).

### MCP Authorization spec alignment

The MCP Authorization spec (Security Best Practices section) **forbids token passthrough**: *"The MCP server MUST NOT pass through the token it received from the MCP client… MUST NOT accept tokens not explicitly issued for the MCP server."* **Before citing this MUST in shipped docs, pin it to a verified source** — a specific `modelcontextprotocol.io` revision URL or spec commit hash (the exact revision date was not verified here, and the lab server currently advertises `protocolVersion: "2024-11-05"`). Pattern B is not just a workaround — it is the spec-compliant shape. The Graph token is independently issued and never the client's token, which preserves the audit trail (Graph logs show the real user), avoids the confused-deputy class, and satisfies RFC 8707 audience binding. Pattern A-passthrough (e.g. APIM "forward Authorization header to backend") is the anti-pattern the spec prohibits.

---

## 2. As-built flow (verified at source)

```
 [Claude Code / MCP client]
        │  ① OAuth 2.1 PKCE login to Keycloak  (IdP #1)
        │     → access token (iss=keycloak, aud=mcp-proxy)
        ▼
 ┌───────────────────────── Gateway / Security Proxy ─────────────────────────┐
 │ ② AuthMiddleware validates KC token (RS256 + iss + JWKS), sets             │
 │    request.state.client_id = <email|sub>;  user_kc_token stashed (path 3c)  │
 │      proxy/app/middleware/auth.py:225-237, 469-484                          │
 │ ③ invoke_tool → security pipeline:                                          │
 │    quarantine(INV-005) → entitlement(6.2) → anomaly → OPA(INV-003/004)      │
 │    → SSRF re-check        proxy/app/services/invocation.py:100-232          │
 │ ④ dispatch_credential_injection( injection_mode )                           │
 │    proxy/app/credential_broker/dispatcher.py:66-156                         │
 │      • entra_user_token →  _inject_entra_user_token()  (Pattern B) ✅        │
 │      • oauth_user_token →  KC RFC 8693 exchange  (Pattern A, KC→KC only) ✅  │
 │ ⑤ broker.resolve(approach="A", user_sub=client_id, service="m365")          │
 │    • master KEK from Vault (300s cache)   credential_broker/kms.py:16-28     │
 │    • SELECT encrypted_blob FROM credential_store WHERE user_sub,service      │
 │    • AES-256-GCM decrypt → Entra refresh_token                              │
 │    • M365Adapter.refresh() → fresh Graph access_token (delegated)           │
 │      adapters/m365.py:66-75                                                  │
 │    • re-encrypt rotated refresh_token, UPDATE row     broker.py:113-145      │
 │ ⑥ forward to leaf m365 MCP server with Authorization: Bearer <graph token>  │
 │    invocation.py:337-348                                                     │
 │ ⑦ synchronous audit event (INV-001), response injection filter              │
 └─────────────────────────────────────────────────────────────────────────────┘
        ▼
 [leaf m365 MCP server] → GET https://graph.microsoft.com/v1.0/me …  (as the user)
   lab/mcp-servers/m365/server.py:71-84

 ── one-time enrollment (Pattern B bootstrap) ──────────────────────────────────
 /auth/enroll/m365   → PKCE + state(nonce) in Redis → redirect to Entra authorize
 [user logs into Entra + consents]
 /auth/callback/m365 → code+verifier → M365Adapter.exchange_code()
                     → encrypt refresh_token → INSERT credential_store
                     → synchronous CREDENTIAL_ENROLLED audit
   proxy/app/routers/oauth.py:93-170
```

### What is wired vs. not

| Stage | Status | Evidence |
|---|---|---|
| ① PKCE login to Keycloak | ✅ | `oidc_browser.py`, `auth.py:168-237` |
| ② Token validation + identity | ✅ | `auth.py:225-237,469-484` |
| ③ Security pipeline (quarantine/entitlement/OPA/SSRF) | ✅ | `invocation.py:100-232` |
| ④–⑥ `entra_user_token` delegated injection (Pattern B) | ✅ | `dispatcher.py:381-436`, `broker.py:113-145`, `adapters/m365.py:66-75` |
| Enrollment `authorization_code`+refresh, vaulted, AES-256-GCM | ✅ | `oauth.py:93-170`, `credential_store` V006 |
| Refresh-token rotation on each mint | ✅ | `broker.py:130-136` |
| Synchronous audit on enroll + invoke (INV-001) | ✅ | `oauth.py:165`, `invocation.py:394-406` |
| **Enrollment-required signalled to client with clickable URL** | ✅ | `CredentialEnrollmentRequiredError` → `-32010` JSON-RPC error with `data.{service,enrollment_url,action,instructions}` + `initialize._meta.pending_enrollments`. `mcp_server.py:353-376,659-678`. Contract test-backed: `proxy/tests/unit/test_enrollment_link_delivery.py` (Tasks 1–3). Deny audit on this path verified (INV-001): `test_invoke_tool_audits_deny_before_reraising_enrollment_error`. |
| **Auto-open browser on enrollment-required** | 🔴 | Client receives a URL string; nothing launches the browser. UX gap — see PRD R-3a/R-3b. |
| `oauth_user_token` (RFC 8693, KC→KC) | 🟡 | Works only for direct-OIDC callers; session/API-key/mTLS fail closed. `dispatcher.py:275-314` |
| Keycloak→Graph via OBO | 🔴 N/A | Architecturally impossible (§1). Not a bug; do not attempt. |
| `tool_registry.entra_*` columns **read** by the dispatch path | 🔴 | Columns exist (V010), but **no code reads them at dispatch.** `M365Adapter` is built once at startup from `settings.ENTRA_*` (`oauth.py:33-38`); `dispatch_credential_injection` does not pass the tool row into `_inject_entra_user_token`. Per-tool tenancy requires a factory/dispatch refactor, not just a migration seed. |
| Per-client consent gate before downstream redirect | 🔴 | `/auth/enroll/{svc}` redirects straight to Entra (`oauth.py:93-111`). `consent.py` exists but is explicitly **NOT ENFORCED** and governs `injection_mode`/`custody_mode` changes, not OAuth enrollment. |
| Revocation endpoint / step-up scopes | 🔴 | No `DELETE /auth/enroll/{svc}` route; no `WWW-Authenticate scope=` step-up. Refresh-token rotation on mint ✅ (`broker.py:130-136`). |
| RFC 8707 `resource` indicator enforced on inbound flow | 🔴 | PRM document **is** served (`oauth_metadata.py:239`); but `auth.py` validates `aud` against `OIDC_AUDIENCE` only (enforced in prod, advisory in lab) — it does not require/validate a `resource` parameter. |

---

## 3. Components & data

| Component | File | Role |
|---|---|---|
| Auth middleware | `proxy/app/middleware/auth.py` | KC token validation, `client_id`, `user_kc_token` (3c) |
| Invocation service | `proxy/app/services/invocation.py` | Security gates + credential dispatch + upstream forward + audit |
| Dispatcher | `proxy/app/credential_broker/dispatcher.py` | Routes by `injection_mode`; fail-closed for every mode ≠ `none` |
| Broker | `proxy/app/credential_broker/broker.py` | Approach-A envelope crypto + refresh + rotate |
| KMS | `proxy/app/credential_broker/kms.py` | Vault master-secret fetch + hex/base64 decode |
| M365 adapter | `proxy/app/credential_broker/adapters/m365.py` | Entra `authorize`/`token` calls |
| Enrollment router | `proxy/app/routers/oauth.py` | `/auth/enroll/{svc}`, `/auth/callback/{svc}` |
| Leaf m365 server | `lab/mcp-servers/m365/server.py` | Receives delegated bearer, calls Graph as user |

**`credential_store`** (V006): `(user_sub, service)` unique; `encrypted_blob BYTEA` = AES-256-GCM(refresh_token), KEK from Vault. **`tool_registry`** (V010/V021/V023): `injection_mode` enum, `entra_tenant_id/client_id/scope`, `server_id`. **`audit_events`** (V001): append-only, synchronous.

### `injection_mode` matrix

| Mode | Acts as | Credential source | Keycloak→Graph? |
|---|---|---|---|
| `none` | — | none | — |
| `service` | the service | shared secret in `credential_store["__service__"]` | n/a |
| `user` | the user | per-user vaulted token (approach-A) | generic |
| `service_account` | the tool | KC client_credentials | n/a |
| `oauth_user_token` | the user | **RFC 8693 KC token exchange** | ❌ KC→KC only |
| `entra_client_credentials` | the **app** | `ENTRA_*` client_credentials | app-only (not delegated) |
| `entra_user_token` | **the user** | **vaulted Entra refresh token** → Graph access token | ✅ **the answer** |

---

## 4. Recommended design changes (forward plan)

Ordered by value/effort. Detailed acceptance criteria live in the PRD.

1. **Close the enrollment-UX loop (R-1, R-3a, R-3b).** When a delegated tool is hit without a credential, the gateway already returns `enrollment_url` (in the JSON-RPC error `data`). Add (a) MCP `elicitation`/structured `_meta` so capable clients surface a clickable link (R-3a), and (b) a self-authenticating enrollment deep-link (R-3b). **The deep-link is bearer-equivalent and must be treated as a credential** — it leaks via logs/Referrer/history and an agentic LLM with a browser tool can follow it unattended, so it is *not* "safe to hand to an LLM" without human-in-the-loop confirmation at follow time. The real gap today: the `enrollment_url` is unauthenticated, so a fresh browser that opens it has no proxy session — the callback cannot associate back to the original API caller, and whoever authenticates next gets the credential bound to *their* identity. R-3b's signed token closes that association gap; it does not make the link LLM-safe.

2. **Populate `tool_registry.entra_*` per tool (R-2).** Stop falling back to `ENTRA_*` env globals. Bind tenant/client/scope at the tool row so multiple Entra tenants and least-privilege scope sets are first-class. Add a migration seeding the m365-graph row.

3. **Enforce RFC 8707 resource indicators + RFC 9728 PRM (R-4).** Serve `/.well-known/oauth-protected-resource`, require `resource=<canonical /mcp URI>` on the inbound KC flow, and validate it against the token audience. This makes "token was minted for *this* gateway" enforceable, not assumed (`OIDC_AUDIENCE` is currently advisory).

4. **Per-client consent before downstream redirect (R-5).** The confused-deputy mitigation the MCP spec marks MUST: a server-side, single-use consent page bound to the requesting client + exact scopes + exact `redirect_uri`, set in a `__Host-` cookie, *before* redirecting to Entra. Today enrollment trusts the proxy session.

5. **Step-up scopes + token-vault hardening (R-6).** Least-privilege baseline Graph scopes, step-up via `WWW-Authenticate scope=`, refresh-token rotation (already done) + revocation endpoint + per-user key derivation; fail-closed on KMS/Vault loss (already done).

None of these change the core architecture — Pattern B stays. They harden the bootstrap, the audience binding, and the UX.

---

## 5. Security invariants touched

- **INV-001** (synchronous audit): enrollment and every delegated invoke emit synchronous events. Keep.
- **INV-003/004** (deny-default, OPA fail-closed): unchanged; delegated injection happens *after* OPA allow.
- **INV-002** (no raw secrets in logs): refresh/access tokens never logged; only `[REDACTED:*]`.
- **No token passthrough** (MCP spec): Pattern B preserves this by construction. Adding RFC 8707 validation (R-4) makes it enforced, not implicit.
- **No bespoke crypto**: broker uses `cryptography` AES-256-GCM + HKDF-SHA256 only. Keep.

---

## 6. Honest landscape answer

No shipping MCP gateway does **Keycloak-token → Graph in one hop** — because Entra OBO cannot consume a Keycloak token. Products that deliver the *effect* (Microsoft APIM Credential Manager, Cloudflare `workers-oauth-provider`, Auth0 Token Vault, WorkOS/Stytch connected apps) all use **Pattern B** (independent per-user downstream enrollment + vault), which is exactly what this repo's `entra_user_token` mode is. The differentiators this project can claim: synchronous tamper-evident audit on the credential path, OPA deny-default in front of injection, fail-closed broker, and discovery==invoke entitlement — none of the surveyed products bundle all four.

**Primary sources:** MCP Authorization spec & Security Best Practices (modelcontextprotocol.io — pin the exact revision before citing normative MUSTs); Entra OBO (learn.microsoft.com `v2-oauth2-on-behalf-of-flow`); APIM secure-MCP / Credential Manager; Cloudflare Agents authorization; Auth0 Token Vault; RFC 8693 / 9728 / 8707 / 7591.
