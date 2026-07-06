# Authentication & Identity Specification

**Status: matches code at HEAD (`4dfa7b5`).**

This document is a language-agnostic, normative specification of how the MCP Security Platform
resolves caller identity, authorizes it, and issues/validates tokens. It is written so the
authentication and identity layer can be re-implemented in any language or framework. Requirement
keywords (**MUST**, **MUST NOT**, **SHOULD**, **MAY**) are used per RFC 2119. Each rule cites a
"Reference implementation:" pointer into the Python/FastAPI proxy; those pointers are illustrative,
not normative — the normative content is the rule. Anything not enforced in the code at HEAD is
marked **(roadmap)**. The authoritative per-control status is the
[README Enforced-vs-Roadmap table](../../README.md#enforced-today-vs-roadmap); this doc explains the
rules a faithful re-implementation MUST preserve.

The governing principle is **fail-closed**: when identity cannot be established, or a security
dependency needed to establish it is unavailable, the implementation **MUST** deny (see
[06-implementation-lessons.md](06-implementation-lessons.md) fail-closed catalogue).

---

## 1. Client authentication methods & priority order

An implementation **MUST** support three inbound client-authentication methods and **MUST** evaluate
them in a strict, fixed priority order. The first method that yields an identity wins; later methods
**MUST NOT** be consulted once an identity is resolved.

| Priority | Method | Credential | Trust anchor |
|---|---|---|---|
| 1 | mTLS client-certificate CN | `X-Client-Cert-CN` header (set by the gateway) | gateway shared secret + trusted-proxy source IP |
| 2 | OIDC session JWT (cookie or Bearer) | proxy-issued HS256 session JWT | proxy signing key + server-side JTI record |
| 2 | External OIDC access token (Bearer) | IdP-issued RS256 access token | IdP JWKS + issuer/audience validation |
| 3 | API key (Bearer) | opaque token | HMAC-SHA-256 hash matched in DB, Redis-cached |

Reference implementation: `proxy/app/middleware/auth.py::AuthMiddleware.dispatch` (mTLS at ~L180,
session JWT at ~L194 & ~L232, external OIDC at ~L257, API key at ~L273).

### 1.1 Public paths

Certain endpoints **MUST** bypass authentication because they are the entry points of the auth flow
itself (discovery documents, the OIDC login/callback, dynamic client registration) or are
authenticated by a different mechanism (an inbound webhook shared secret). The implementation
**MUST** treat these as an explicit allowlist, never a prefix wildcard that could expose protected
routes. The OAuth *callback* path (`/auth/callback/*`) **MUST** be public **but MUST NOT** derive
identity from any request header — identity is recovered from a server-side single-use nonce (§3).

Reference implementation: `PUBLIC_PATHS` and `_PUBLIC_PATH_PREFIXES` in `auth.py` (~L94–L121). The
RBAC layer's public set **MUST** be kept identical to the auth layer's (`middleware/rbac.py::PUBLIC_PATHS`).

### 1.2 mTLS CN header (priority 1)

The gateway terminates mTLS and forwards the verified client-certificate CN to the proxy as a header
(`X-Client-Cert-CN`). Because a header is trivially forgeable by anything that can reach the proxy
directly, the proxy **MUST NOT** trust it on its own. The following rules are mandatory:

- The proxy **MUST** honour `X-Client-Cert-CN` only when the request also carries a gateway shared
  secret (`X-Gateway-Secret`) that matches the configured value, compared with a **constant-time**
  comparison (`hmac.compare_digest`-equivalent). A timing-variable comparison is a defect.
- If the shared secret is **not configured** (empty), mTLS-CN authentication **MUST** be disabled
  entirely (return "not trusted"), **not** fall back to trusting the header. This is the lab default.
- If the shared secret **is configured** but the request omits or mismatches it, the proxy **MUST**
  reject the CN (fail-closed, "GW-001").
- The CN value **MUST** be sanitised (control characters stripped, length-bounded) before use in
  logs or identity to prevent log injection.
- In production the service **MUST** refuse to start when `GATEWAY_SHARED_SECRET` is empty, because
  an empty secret silently disables the trust check (F-001). Reference: `core/config.py`
  `_reject_placeholders_in_production` (~L525).

A CIDR/source-IP allowlist alone is **insufficient**, because port-forwarding (e.g. gvproxy) can make
direct host connections appear to originate from the gateway's subnet. The shared secret is the
trust anchor; the source IP is defense-in-depth.

Reference implementation: `auth.py::_is_trusted_proxy` (~L40–L67), `_sanitize_cn` (~L35).

### 1.3 OIDC session JWT / external Keycloak Bearer (priority 2)

Two token shapes are accepted at priority 2, tried in this order:

1. **Internal session JWT** (proxy-issued, `HS256`, audience `mcp-proxy-session`). Presented via the
   session cookie (browser) or as a `Bearer` token (API clients). Validated with the proxy's own
   secret key. Reference: `auth.py` ~L194 (cookie) and ~L232 (Bearer).
2. **External OIDC access token** (IdP-issued, `RS256`). Validated against the IdP JWKS. Only tried
   if no internal session JWT matched and OIDC is enabled. Reference: `auth.py::_validate_oidc_jwt`
   (~L550).

For **both** shapes, the following are mandatory:

- A session JWT **MUST** carry a `jti`. A missing `jti` **MUST** be treated as forged/unknown and
  rejected (a legitimately issued session JWT always has one).
- The `jti` **MUST** be checked against the revocation store on **every** request, fail-closed (§4.3,
  INV-014).
- External OIDC JWT roles **MUST NOT** augment DB-authoritative roles outside a development
  environment (JWT-role-escalation guard). Internal (proxy-issued) session JWTs **MAY** supplement DB
  roles because the proxy minted them. Reference: `auth.py` ~L338.

### 1.4 API key (priority 3)

- The presented token **MUST** be hashed (HMAC-SHA-256 with a server key) before any lookup; the raw
  token **MUST NOT** be stored or logged.
- Resolution order: Redis cache (`api_key:{hash}` → client_id, TTL 300s) → DB lookup of `key_hash`
  with `revoked_at IS NULL` and non-expired → populate cache. A revoked or expired key **MUST**
  resolve to no identity (→ 401).

Reference implementation: `auth.py::_resolve_api_key` (~L646), `core/security.py::hash_api_key`.

### 1.5 401 challenge

When no method yields an identity for a protected endpoint, the implementation **MUST** return
`401` with a `WWW-Authenticate: Bearer` header whose `resource_metadata` parameter points at the
RFC 9728 protected-resource metadata document (§3). Browser clients (`Accept: text/html`) **MAY**
instead be 302-redirected to the OIDC login endpoint. Reference: `auth.py` ~L279–L311.

---

## 2. Typed principal model

After identity resolution, the implementation **MUST** attach a typed principal to the request in a
namespaced form, so downstream authorization never conflates a human with an agent or an API key:

| Auth method | `principal_id` | `principal_type` |
|---|---|---|
| mTLS | `agent:{CA_ID}:{cn}` | `agent` |
| API key | `human:apikey:{client_id}` | `human` |
| OIDC session / external OIDC | `human:{ISSUER_ID}:{client_id}` | `human` |

Reference implementation: `auth.py::_build_principal_id` (~L124). The `client_id` (bare identity
key) and the typed `principal_id` are both attached to request state and both flow to the invocation
pipeline (the entitlement/discovery gate keys on the typed principal).

`_build_principal_id` also derives `principal_issuer` (the issuer/CA component — the OIDC issuer id,
the mTLS CA id, or the literal `"apikey"`) and `principal_display_sub` (the bare `client_id`, kept
purely for display/compat purposes). All four values are attached to `request.state`.

### 2.1 Downstream propagation (CR-10)

The invocation pipeline (`services/invocation.py::invoke_tool`, `forward_base_headers`) forwards
four headers to every upstream MCP server, on top of the pre-existing `X-User-Sub`/`X-User-Role`:

| Header | Value | Notes |
|---|---|---|
| `X-Principal-Id` | the typed `principal_id` | collision-proof — the only safe key for per-caller state |
| `X-Principal-Type` | `human` \| `agent` | |
| `X-Principal-Issuer` | issuer/CA id, or `"apikey"` | |
| `X-Principal-Display-Sub` | the bare `client_id` | display-only, **never** an authorization key |
| `X-User-Sub` | the bare `client_id` | **kept as a compatibility/display alias — MUST NOT be removed** |

The typed headers are omitted (not sent as empty strings) when `principal_id`/`principal_type` are
unset — e.g. for pre-CR-10 code paths that don't populate request.state. An upstream MCP server built
against `mcphub_sdk` reads all of this via `identity()` (`sdk/mcphub-sdk/mcphub_sdk/context.py`),
which exposes `principal_id`/`principal_type`/`principal_issuer` alongside the legacy `sub`/`role` —
all `None` when the request predates CR-10 or bypassed the proxy. `identity()` requires
`stateless_http=True` on the server's `FastMCP` instance (already the SDK default) so per-request
ContextVars actually reach tool code — see
[06-implementation-lessons.md](06-implementation-lessons.md) for the underlying gotcha.

**Non-negotiable invariant:** a server-side integration that keys per-caller state (credentials,
notes, rate limits, ...) off `X-User-Sub`/`sub` alone remains exposed to the exact collision this
section exists to prevent — an OIDC human, an API-key caller, and an mTLS agent can share a bare
subject string. New integrations **MUST** key off `X-Principal-Id`/`principal_id` instead.

### 2.2 Typed-principal credential dual-read (CR-10)

`credential_store` (per-user OAuth/API-key rows — `V006`/`V011`) is keyed by its `user_sub` column.
Pre-CR-10, every row was written under the bare subject. Migrating every existing row to the typed
form in one shot ("big-bang rewrite") was explicitly rejected — it risks breaking live enrollments
mid-migration. Instead (`app/credential_broker/principal_resolution.py::resolve_credential_owner`,
`V062`):

1. **Typed lookup** (`user_sub == principal_id`) is tried first. This is the **only** key new
   enrollments ever write under — see `routers/oauth.py::callback`.
2. **Bare-sub fallback** (`user_sub == client_id`) is tried only on a typed miss, and only succeeds
   if the row's `principal_type` column matches the caller's own `principal_type`. A row with
   `principal_type IS NULL` (every pre-`V062` row) is treated as **inferred-legacy `human`** — safe,
   since `credential_store` was, before CR-10, only ever populated by OIDC/session human enrollment
   flows.
3. A **mismatch is never a match.** It raises `CrossTypePrincipalMismatch`
   (`app/credential_broker/dispatcher.py::CrossTypePrincipalFallbackDenied`, a
   `CredentialInjectionError`), which `services/invocation.py`'s credential-dispatch exception
   handler turns into an audited deny (`deny_reasons=["cross_type_principal_fallback_denied", ...]`)
   — never a silent cross-type credential match.

This dual-read is wired into the `user`, `basic_auth` (per-user leg), and `entra_user_token`
injection modes (`credential_broker/dispatcher.py`, `credential_broker/broker.py::_resolve_a`).
Backfilling every legacy row's `principal_type`, or renaming legacy `user_sub` values to the typed
form, is an explicit **out-of-scope follow-up** (a later, separate re-enrollment/cleanup step), not
part of this migration.

---

## 3. Zero-credential client connection flow

A conforming MCP client (e.g. Claude Code) connects with **only the gateway URL** in its
configuration — no API key, no pre-registered client ID. The implementation **MUST** support the
full discovery-and-registration chain below. The transport type **MUST** be Streamable HTTP
(`"type": "http"`), not SSE (see [06-implementation-lessons.md](06-implementation-lessons.md) §1).

Wire sequence:

1. **`GET /mcp` with no credentials → `401`.** The response **MUST** include
   `WWW-Authenticate: Bearer realm="mcp-proxy", resource_metadata="<base>/.well-known/oauth-protected-resource<path>"`.
   The metadata URL **SHOULD** be path-suffixed so its `resource` field can equal the exact protected
   URL the client called (some clients reject metadata whose `resource` is only the origin).
   Reference: `auth.py` ~L290–L311; `oauth_metadata.py::oauth_protected_resource_scoped` (~L294).

2. **RFC 9728 protected-resource metadata.** `GET /.well-known/oauth-protected-resource[/<path>]`
   returns `{ resource, authorization_servers: [<proxy_base>], bearer_methods_supported: ["header"],
   ... }`. `authorization_servers` **MUST** point at the **proxy's own** AS-metadata endpoint, not
   the IdP directly, so the proxy can filter advertised scopes (§3.1). Reference:
   `oauth_metadata.py::_protected_resource_metadata` (~L261).

3. **RFC 8414 authorization-server metadata.** `GET /.well-known/oauth-authorization-server` proxies
   the IdP's discovery document and **MUST** override:
   - `registration_endpoint` → the proxy's own `/oauth/register` (so the proxy controls client
     issuance);
   - `code_challenge_methods_supported` → `["S256"]`;
   - `scopes_supported` → only the scopes actually enabled on the public client.
   Reference: `oauth_metadata.py::oauth_server_metadata` (~L159).

4. **RFC 7591 dynamic client registration.** `POST /oauth/register` returns a **public** client
   (`token_endpoint_auth_method: "none"`, **no `client_secret`**), PKCE S256 required. The
   implementation **MUST**:
   - rate-limit registration per source IP, fail-closed on rate-limiter error (Redis down → reject,
     not allow);
   - validate every `redirect_uri`: `https://` for any host, `http://` only for loopback
     (`localhost`/`127.0.0.1`/`::1`); reject `javascript:`, `data:`, `file:`, custom schemes with
     `422`.
   Reference: `oauth_metadata.py::dynamic_client_registration` (~L202), `_validate_redirect_uri`
   (~L45), `_check_register_rate_limit` (~L74).

5. **OAuth 2.1 authorization-code + PKCE S256.** The client opens the browser to the IdP, authenticates,
   and receives an authorization code. PKCE with `S256` **MUST** be required; `plain` **MUST** be
   rejected.

6. **Bearer.** The client presents the IdP access token as `Authorization: Bearer <token>` on
   subsequent `/mcp` requests; it is validated per §1.3.

**No credential is ever written to the client's config file.**

### 3.1 Scope filtering

The proxy **MUST** advertise (in AS metadata) only the scopes enabled on the public client, not the
IdP's full realm scope list. Advertising a scope the public client cannot request causes
`invalid_scope` at authorization time. Reference: `oauth_metadata.py` ~L197.

### 3.2 Server-side pending-flow state (credential enrollment)

For the credential-enrollment OAuth flow (a *separate* flow from client login — the proxy acting as
an OAuth client to a downstream service), the implementation **MUST** hold flow state
**server-side**, never in a client-readable cookie or the URL:

- A pending-flow record **MUST** be stored keyed on the OAuth `state` (an unguessable nonce),
  single-use, with a bounded TTL (**300s**).
- The record **MUST** be consumed **atomically** (get-and-delete) at callback time so a captured
  callback URL cannot be replayed.
- Consent **MUST** precede PKCE-state minting: the pending PKCE record is written **only after** a
  valid `POST /consent`, never at the initial `GET /enroll`.
- The CSRF/consent token **MUST** be single-use (atomic get-and-delete) **and** bound to the
  authenticated identity that initiated it — a valid CSRF token is necessary but not sufficient; the
  consuming request's identity **MUST** equal the identity stored in the consent record, else deny.
- Identity for the enrollment binding **MUST** be taken from the server-side record (the
  authenticated identity), **never** from a request header/param.

Reference implementation: `routers/oauth.py` — `_PENDING_PREFIX`/`_PENDING_TTL_SECONDS` (~L27),
`enroll` (~L207), `enroll_consent` (~L357, atomic consume + identity re-check ~L414–L438),
`callback` (~L515, atomic nonce consume ~L525–L533). Every consent grant/deny and every enrollment
completion **MUST** emit a synchronous audit event before the response (INV-001).

---

## 4. Token validation requirements

### 4.1 Issuer & audience

- The `iss` (issuer) claim **MUST** always be validated against the configured issuer, on every JWT
  path (external Bearer and the browser ID-token). Reference: `auth.py` ~L605; `oidc_browser.py` ~L483.
- The `aud` (audience) claim **MUST** be validated in production. In dev/lab, when `OIDC_AUDIENCE` is
  unset, audience validation **MAY** be disabled — but the implementation **MUST** then explicitly
  disable the check (`verify_aud=false`) and log a warning, **not** silently accept, and **MUST NOT**
  substitute another value as the expected audience. Production startup **MUST** be blocked when
  OIDC is enabled and `OIDC_AUDIENCE` is empty. Reference: `auth.py` ~L583–L607; `core/config.py`
  ~L506.

### 4.2 Audience/client-id separation (normative)

> The proxy's own outbound OAuth `client_id` **MUST NEVER** be used as the expected inbound audience.

Dynamically-registered clients (RFC 7591) receive tokens whose `aud`/`azp` is *their own*
dynamically-generated client id (e.g. `dyn-<uuid>`), not the proxy's. If the proxy demanded its own
`client_id` as the audience, every dynamic client would be rejected with `401`. When no expected
audience is configured, the implementation **MUST** disable the audience check — it **MUST NOT**
fall back to its own client id. Reference: `auth.py` ~L576–L589 (comment + `expected_aud` logic).
This exact defect is documented in [06-implementation-lessons.md](06-implementation-lessons.md) §2.

### 4.3 Session JTI revocation (INV-014, fail-closed)

Revocation **MUST** be checked on every request that authenticates via a session JWT, and the check
**MUST** fail closed:

- Return **DENY** if: the `jti` is present in the Redis fast-path revocation cache
  (`revoked_jti:{jti}`, written at logout); **or** the `jti` is absent from the authoritative
  sessions table (never legitimately issued → forged/replay); **or** the row has `revoked_at` set;
  **or** any Redis-and-DB error occurs.
- Return **ALLOW** only when Redis misses (key absent, store reachable) **and** the DB row exists
  with `revoked_at IS NULL`.
- Two-tier lookup: Redis error alone **MUST** fall through to the DB (DB may be healthy); a DB error
  **MUST** deny regardless. A total Redis+DB outage **MUST** block all session-JWT auth (accepted
  availability cost).

Reference implementation: `auth.py::_is_session_jti_revoked` (~L401), `_redis_jti_lookup` (~L356),
`_db_jti_lookup` (~L373).

### 4.4 JWT BCP (RFC 8725)

- Algorithms **MUST** be pinned per token class: `HS256` for proxy session JWTs, `RS256` for IdP
  tokens. The `alg` header **MUST NOT** be trusted to select the family (no `none`, no HS/RS
  confusion). Reference: fixed `algorithms=[...]` lists in `auth.py` and `oidc_browser.py`.
- The signing key **MUST** be selected by `kid` from the JWKS; JWKS **SHOULD** be cached with a
  bounded TTL (300s) and refreshed via OIDC discovery.
- The browser ID-token signature **MUST** be verified against JWKS; if JWKS is unavailable the
  implementation **MUST** fail closed (503), never issue a session backed by unverified claims
  (AUTH-002). Reference: `oidc_browser.py` ~L494–L508.
- A `nonce` bound at `/login` **MUST** be validated at `/callback`; a missing stored nonce **MUST**
  be treated as reject, not skip. Reference: `oidc_browser.py` ~L515–L531.

### 4.5 OAuth/IdP policy engine — requested vs approved config (CR-13, CR-03 fold-in)

An onboarded server's OAuth/IdP configuration (`server_registry.upstream_idp_config`) is always
**submitter-requested**, never directly enforced. A separate reviewer-approved copy governs what
the runtime actually does:

- `server_registry.approved_upstream_idp_config` / `approved_token_audience` /
  `approved_oauth_scopes` **MUST** be populated only by the admin `/approve` endpoint, after
  policy validation (below) passes. They are never writable by the submitter.
- All dispatch-time code (credential injection, tool discovery) **MUST** read only the
  approved-* values — never `upstream_idp_config` directly. Reference implementation:
  `routers/tools.py::resolve_approved_kc_token_audience` (writes `tool_registry.kc_token_audience`
  from `approved_token_audience` at discovery time, never from the requested config);
  `credential_broker/dispatcher.py::_inject_kc_token_exchange` then reads only that
  already-approved value.

**Two independent validation dimensions** (deliberately not collapsed into one allowlist — a
prior attempt to do so broke every existing `service_account` tool on its default `openid`
scope; see `services/oauth_policy.py` module docstring):

1. **Scope-set dimension** — `oauth_provider_policy` table: issuer(+tenant) →
   `allowed_scopes`/`blocked_scopes`/`allowed_redirect_patterns`/`allowed_client_auth_methods`/
   `max_risk`. Governs `entra_client_credentials`/`entra_user_token` (and, via
   `SERVICE_ACCOUNT_ALLOWED_SCOPES`, `service_account`'s `scope` field — a **separate**
   allowlist from #2 below, keyed on scope tokens, not an audience string).
   - An issuer/tenant with **no matching policy row** **MUST** fail closed (unknown issuer).
   - A requested scope **MUST** be a subset of `allowed_scopes` and **MUST NOT** appear in
     `blocked_scopes`. An empty `allowed_scopes` list **MUST** be read as "nothing approved
     yet", not "anything goes".
   - High-risk scopes — `write`, `admin`, `mail`, `files`, `offline_access` (the canonical
     set) — **MUST** additionally require the reviewer to set
     `high_risk_scopes_approved=true` on the `/approve` request; a policy-subset pass alone
     is insufficient. Recorded as `server_registry.high_risk_scopes_approved_by`/`_at`.
   - Reference implementation: `services/oauth_policy.py::validate_requested_config`,
     invoked from `routers/submission.py::_validate_oauth_policy_at_approval`.
2. **Audience-string dimension** — `kc_token_exchange` (RFC 8693): a single opaque audience
   string (e.g. `lab-tickets`), not a scope set. Two gates, both enforced: the per-server
   `approved_token_audience` (DB, reviewer-set) **MUST** equal the requested audience, **and**
   the audience **MUST** be within the platform-wide `KC_TOKEN_EXCHANGE_ALLOWED_AUDIENCES`
   env allowlist (outer/bootstrap ceiling; CR-03's original config-driven fix, kept as
   defense in depth). A server with no `approved_token_audience` recorded **MUST** fail
   closed — kc_token_exchange cannot be used until a reviewer approves it under this model.

Requested-vs-approved is surfaced to reviewers via `GET /api/v1/submissions/{id}`, which
returns both `upstream_idp_config`/`upstream_idp_type` (requested) and
`approved_upstream_idp_config`/`approved_token_audience`/`approved_oauth_scopes`/
`oauth_policy_id`/`high_risk_scopes_approved_by`/`_at` (approved) side by side.

**Migration note**: servers already `status='approved'` before this policy engine existed are
grandfathered — their `approved_upstream_idp_config`/`approved_token_audience`/
`approved_oauth_scopes` were backfilled from the then-existing `upstream_idp_config` at
migration time (V065), since they already passed human review under the pre-existing model.
Only approvals from V065 onward go through `oauth_provider_policy` validation.

### 4.6 External IdP adapters — generic + Jira (CR-04 remainder, WP-A3)

`kc_token_exchange` (same Keycloak realm) and `entra_*` (Microsoft-specific) do not cover a
third case: a self-service-onboarded server whose upstream IdP is neither. Two injection modes
close this gap, added to `InjectionMode`/`AuthMode`: `external_oauth_user_token` (per-user
delegated OAuth 2.0, approach A) and `external_oauth_client_credentials` (app-only, approach B
shape). Both are governed by §4.5's `oauth_provider_policy` at approval time exactly like
`entra_*` — no special-casing needed, since the policy engine only looks at issuer/tenant/
scopes/redirect_uri/client_auth_method, all present in `external_oauth`'s config shape.

- **Static vs dynamic adapters.** `m365`/`dex`/`bitbucket`/`jira` (all in
  `credential_broker/adapters/`) are statically registered from env vars — one platform-wide
  instance per module, right for integrations the platform itself owns an app registration
  for. A self-service-onboarded external OAuth server needs the OPPOSITE: one adapter instance
  PER SERVER, parameterized from that server's own approved config. `GenericOAuthAdapter`
  (`adapters/generic_oauth.py`) is that parameterized adapter (same
  build_auth_url/exchange_code/refresh interface as every static one);
  `adapters/dynamic_external_oauth.py::resolve_external_oauth_adapter` builds it per call from
  `server_registry.approved_upstream_idp_config` (issuer, client_id, authorization_endpoint,
  token_endpoint, scopes, redirect_uri, client_auth_method) — **never** the submitter-requested
  `upstream_idp_config`, same non-negotiable as §4.5. The client_secret is a service-owned
  `credential_store` row, resolved via `tool_registry.credential_id` the same way
  `entra_client_credentials` resolves its own (no new admin write path needed).
- **Resolution order.** `routers/oauth.py::_get_adapter` and `broker.py::_resolve_a` both try
  the static registry first (backward compatible with existing m365/dex/bitbucket/jira
  enrollments), then fall back to the dynamic per-server resolver. Any DB/Vault error during
  dynamic resolution **MUST** be caught and treated as "no adapter" (→ 404 / "not enrolled")
  — never a raw exception surfaced to the enrollment page or credential broker.
- **`client_auth_method`.** Some external IdPs (Atlassian, some SaaS OAuth providers) require
  `client_secret_basic` (HTTP Basic auth header) instead of the more common
  `client_secret_post` (form body). `GenericOAuthAdapter` and
  `_inject_external_oauth_client_credentials` both branch on
  `approved_upstream_idp_config.client_auth_method` — validated at onboarding time
  (`services/server_onboarding.py::validate_upstream_idp_config`) to be one of these two values.
- **Enrollment status.** `GET /auth/status/{service}` reports `{"enrolled": bool,
  "enrollment_url"}` for the AUTHENTICATED caller via the same typed-principal dual-read the
  broker uses at resolve time (§2.2) — an existence-only check, never decrypts the credential.
  Applies to every approach-A adapter (m365, dex, bitbucket, jira, entra_user_token,
  external_oauth_user_token), not just the new mode.
- **Jira (D2 fast-follow, droppable).** `credential_broker/adapters/jira.py` is a real, working
  Atlassian Jira Cloud OAuth 2.0 3LO adapter, statically registered like m365/dex/bitbucket. It
  handles the OAuth token lifecycle only — resolving a Jira Cloud site's `cloudId` (a separate
  Atlassian API call required before any real Jira REST call) is left to the downstream Jira MCP
  tool, not the platform. This is a documented limitation, not a silent gap.

### 4.7 Generic OAuth 2.0 substrate productization — provider profiles + service adapters (WP-A6)

User-approved extension of §4.6 (`docs/spec/08-finalization-findings-generic-oauth.md`, Findings
1–3; explicit scoping decision: **generic OIDC, not Jira-focused** — Jira `cloudId` resolution
(Finding 4) and the apply/deploy/verify pipeline (Finding 5, being built separately as WP-B3) are
both out of scope for this package).

- **`oauth_provider_profile` catalog (V070, Finding 1).** Sits ABOVE `oauth_provider_policy`
  (§4.5) — an admin-curated, reviewer-approved catalog a non-expert submitter picks from
  ("Same platform IdP" / "Generic OAuth 2.0" / "Microsoft Entra" / "Custom OIDC"; `jira_cloud` is
  a reserved `provider_type` value, not implemented). It does **not** replace `oauth_provider_policy`
  — a profile's issuer still validates against a matching policy row (via
  `oauth_policy.get_policy_for_issuer`, the same `UnknownIssuerError` class, not a parallel
  mechanism) at profile-approval time in `services/oauth_provider_profile.py::approve_profile`,
  and again independently at server-submission-approval time via the existing
  `_validate_oauth_policy_at_approval` gate — unchanged. Profile approval is fail-closed the same
  way §4.5 is: unknown issuer, un-acknowledged high-risk scope (`oauth_policy.HIGH_RISK_SCOPES`),
  or an invalid state transition (`draft`/`pending_review` → `approved` only) all reject rather
  than silently pass. `server_registry.oauth_provider_profile_id` records which profile (if any) a
  server's submission was built from.
- **RFC 8414 / OIDC discovery (Finding 1).** `oauth_provider_profile.discover_metadata` fetches
  `.well-known/oauth-authorization-server` first, falling back to
  `.well-known/openid-configuration` — a plain HTTPS GET + JSON parse, no new dependency. This is
  a UX convenience, not a trust boundary: **any** failure (network error, 404, malformed/partial
  document, a 200 response with no `token_endpoint`) returns `None` rather than raising, and the
  caller (profile creation / onboarding wizard) falls back to manual endpoint entry. Discovered
  `token_endpoint_auth_methods_supported`/`scopes_supported` only pre-fill the draft profile —
  they are never themselves enforced (that stays `oauth_provider_policy`'s job).
- **"Same platform IdP" non-expert path (Finding 2).** `oauth_provider_profile.recommend_provider_type`
  is a pure wizard-answer → `(provider_type, injection_mode)` mapping; when the answer is
  "same IdP as this platform", the recommendation's `provider_type` is `same_platform_idp` and its
  `display_label` is the literal string **"Same platform IdP"** — the `kc_token_exchange`
  implementation name is asserted (by unit test) to never appear in submitter-facing text. Under
  the hood this still produces an ordinary `kc_token_exchange` submission (§4.2/§4.5) — no new
  persistence or dispatch path, everything downstream of submission is unchanged.
- **Same-IdP deploy verification probe (Finding 2).** `services/same_idp_verify.run_same_idp_verify_probe`
  is a standalone, independently-testable check: given a running MCP server URL and its approved
  audience, it sends three requests directly to that server (bypassing the proxy, so it measures
  the *upstream's own* validation) — no `Authorization` header, a signed-but-wrong-audience token,
  and a signed-but-expired token — and asserts all three are rejected (non-2xx, or an MCP
  JSON-RPC `error` body). **WP-B3's verify pipeline does not exist yet** as of this writing; this
  module is deliberately not wired into any verify endpoint. Whoever finishes WP-B3 should call
  `run_same_idp_verify_probe()` from the verify-phase worker for the `kc_token_exchange` /
  "same platform IdP" auth-mode branch and persist its result into whatever verification-report
  structure that phase produces (see §4.6-adjacent `server_registry.verification_report`, V068).
- **`ServiceAdapter` contract (Finding 3).** `credential_broker/adapters/service_adapter.py`
  defines what OAuth alone cannot know about a specific upstream service — resource API base URL,
  tenant/site/workspace id, post-enrollment discovery, a safe read-only probe endpoint, and the
  non-secret runtime context handed to the deployed MCP server. A `ServiceAdapter` **never**
  stores or returns a refresh token or client secret — those remain exclusively in
  `credential_store`, managed by the broker; the adapter only ever receives a short-lived
  `access_token` for the duration of one discovery/verify call. `server_registry.service_context`
  (JSONB, V070) persists the non-secret result of `build_runtime_context()` — e.g.
  `{"adapter": "generic", "api_base_url": "..."}` — explicitly separate from `credential_store`.
  `GenericServiceAdapter` (`adapters/generic_service_adapter.py`) is the reference "no extra
  discovery needed" implementation: most external OAuth services need nothing beyond a fixed
  `api_base_url`, proving the contract holds for the common case before any service-specific
  adapter (e.g. a future Jira Cloud `cloudId`-resolving one, Finding 4 — **not built by WP-A6**)
  is layered on top.
- **Router.** `routers/oauth_provider_profiles.py` exposes the catalog CRUD + approval endpoints
  (`/api/v1/admin/oauth-provider-profiles*`, admin/platform_admin role required) plus the
  self-service wizard mapping (`POST /api/v1/wizard/recommend-provider-type`, no admin role
  required — pure recommendation, no state change, no secrets).

---

## 5. Browser OIDC session flow

The browser login flow issues an internal session JWT and keeps the IdP tokens server-side. A
conforming implementation:

1. **`GET /login`** — generate PKCE (`S256`) verifier/challenge, persist the flow (state, verifier,
   `pkce_code_challenge_method`, nonce, derived `redirect_uri`) in the sessions store, and 302 to the
   IdP authorization endpoint using the **external** issuer URL. The `redirect_uri` **MUST** be
   derived from the host the browser actually reached (§5.1). The post-login destination and optional
   profile name **MAY** be carried in the OAuth `state` (base64url segments); a redirect destination
   **MUST** be constrained to a local path (`/`-prefixed). Reference: `oidc_browser.py::oidc_login`
   (~L195).
2. **`GET /callback`** — look up the flow by `state`; reject unknown/used state (anti-replay); reject
   any flow whose stored PKCE method is not `S256` (downgrade guard); exchange the code at the IdP
   **internal** token endpoint; verify the ID token (JWKS, `iss`, `aud`, `nonce`), fail closed on
   JWKS-unavailable; resolve identity (§6, verified-email rule); mint the session JWT; **encrypt the
   IdP access/refresh tokens at rest** (AES-256-GCM under the broker master secret) before persisting;
   register the `jti` in the sessions table (a failed write **MUST** 503, never issue an
   unregisterable JWT); set the session JWT as an **HttpOnly** cookie; 302 to the post-login
   destination. Reference: `oidc_browser.py::oidc_callback` (~L280).
3. **`POST /logout`** — set `revoked_at` in the DB and write the Redis fast-path revocation marker
   (`revoked_jti:{jti}`, TTL bounded to the JWT's remaining life). Reference: ~L676.
4. **`GET /session`**, **`POST /token/refresh`** — both **MUST** re-check JTI revocation. Refresh
   **MUST** try-decrypt-else-revoke the stored refresh token (a legacy plaintext row fails AES-GCM →
   revoke + force re-login, never 500). Reference: ~L737, ~L770.

The session JWT **MUST NOT** contain raw IdP tokens; it carries `sub`, `client_id`, `roles`, `jti`,
`iss`, `aud=mcp-proxy-session`, and an optional `profile` UUID claim.

### 5.1 Callback/issuer URL derivation

- The `redirect_uri` **MUST** match the address the browser used (LAN IP, Tailscale IP, hostname), or
  the IdP callback fails for remote clients. Priority: `PROXY_BASE_URL` when set; else, if
  `OIDC_TRUST_FORWARDED_HOST` is on, `X-Forwarded-Proto`/`X-Forwarded-Host` (or `Host`), validated
  against a host allowlist and a strict host regex to prevent Host-header injection.
- The **public** issuer URL (for browser redirects) and the **internal** issuer URL (for
  server-to-server JWKS/token/introspection fetches over the container network) **MUST** be separate
  configuration values. Discovery documents fetched over the internal URL **MUST** have their URLs
  rewritten to the public URL before being handed to browser clients.

Reference implementation: `oidc_browser.py::_derive_callback_url` (~L91), `_issuer_url_internal`/
`_issuer_url_external` (~L45–L57); `oauth_metadata.py::_fetch_idp_discovery` URL rewrite (~L126);
`auth.py::_get_jwks_base_url` (~L502). See [06-implementation-lessons.md](06-implementation-lessons.md) §3.

---

## 6. Identity resolution & anti-spoofing

- **Verified-email rule (P1-1).** An OIDC email **MUST** be used as the identity key only when the
  IdP asserts it **verified** (`email_verified == true`). An unverified or absent email **MUST** fall
  back to the immutable `sub`. With realm `verifyEmail=true`, changing one's email resets
  `email_verified` to false until re-proven, so a user cannot rename their email to a privileged
  identity (e.g. `admin@corp`) and inherit its roles/entitlements/credentials. Reference:
  `auth.py::verified_oidc_identity` (~L72); shared by the Bearer path (~L615) and the browser path
  (`oidc_browser.py` ~L551).
- **Machine-token restriction (P1-2).** Client-credentials (service-account) tokens **MUST** be
  flagged (`preferred_username` starting `service-account-`) and **MUST** be barred from human-only
  self-service actions (e.g. mutating a profile). A service account that could self-expand its own
  profile is a privilege-escalation vector. Reference: `auth.py::_validate_oidc_jwt` `is_service_account`
  (~L621); enforced downstream in the entitlement layer.

---

## 7. RBAC — two-layer role model

Authorization uses **two** distinct role layers; conflating them is the usual source of error.

1. **IdP (Keycloak) realm roles** — what the token carries (`admin`, `agent`, `auditor`,
   `security_reviewer`, `readonly`, …).
2. **Platform RBAC roles** — what the middleware actually checks
   (`admin`/`platform_admin`, `manager`, `server_owner`, `auditor`, `user`/`agent`/`readonly`).

An IdP realm role **MUST** be translated to a platform role through an **explicit allowlist**. A KC
role missing from that map **MUST** be silently dropped (fail-closed) — an IdP-side role can never
grant platform access without an explicit code change on the proxy side. Reference:
`oidc_browser.py::_ROLE_MAP` (~L546).

### 7.1 Role levels

Reference: `middleware/rbac.py::ROLE_LEVELS` (~L45), mirrored in `services/entitlement.py::ROLE_LEVELS`.

| Role | Level | Notes |
|---|---|---|
| `admin` / `platform_admin` | 4 | Same tier, two names (see §7.2). |
| `auditor` | 3 | Read-only everywhere (audit, anomaly, compliance, policy, submission queue). No mutation. |
| `server_owner` | 2 | Per-row ownership is enforced in handlers via `owner_sub`, **not** granted by this role alone. |
| `manager` | 1 | Ops tier: manage entitlements alongside `server_owner`/`admin`. |
| `user` / `agent` / `readonly` | 0 | Base tier: invoke tools, see/submit only own drafts. `agent`/`readonly` are legacy aliases. |
| `security_reviewer` | — | Narrow, orthogonal: approve/reject/request-changes on **submissions only** (§7.3). |

### 7.2 `admin` vs `platform_admin` (IDOR-005 exception)

`admin` (legacy/KC-facing) and `platform_admin` (canonical "v3") are treated as synonyms almost
everywhere. The **one deliberate exception**: mutating **another principal's** profile **MUST**
require specifically `platform_admin`, not plain `admin`. This narrowed trust was an IDOR-005 fix —
KC only ever issues `admin` in the lab, so no KC-mapped human holds `platform_admin` until it is
granted directly via the RBAC panel. Reference: `routers/profiles.py::_CROSS_PROFILE_WRITE_ROLES`.

### 7.3 Segregation of duties (`security_reviewer`)

A submission reviewer **MUST NOT** review a submission they themselves own, even if they also hold
`admin`. This is a real SoD boundary, not a UI convention. Reference:
`submission.py::_require_not_self_review`.

### 7.4 Append-only role assignments

The role-assignment store **MUST** be append-only (single-writer; `UPDATE`/`DELETE` revoked from the
app DB role at the schema level, INV-011):

- **Grant** = insert a new active event row (`revoked=false`).
- **Revoke** = insert a **tombstone** row (`revoked=true`) for the same `(client_id, role)` — never an
  in-place update/delete.
- **Current state** = the most recent event per `(client_id, role)` by `created_at`, filtered to
  `revoked=false` and unexpired (`DISTINCT ON (client_id, role) ... ORDER BY created_at DESC`).
- Any prior `UNIQUE(client_id, role)` constraint **MUST** be dropped — it would block re-granting
  after a revoke and re-syncing the same KC role twice.

Reference: `auth.py::_load_roles` (~L715, the "latest event wins" read), migrations
`V009`/`V050`, `routers/admin_grants.py`.

**KC-resync tension:** the login flow re-inserts an active `granted_by='keycloak'` row for every
KC-derived role on each login (only when the latest event isn't already an active keycloak grant, to
bound row growth). Consequently, revoking a KC-sourced role via the panel only sticks if the role is
**also** removed in Keycloak; otherwise the next login re-grants it. The implementation **SHOULD**
surface this to the operator rather than hide it. Reference: `oidc_browser.py` ~L635.

### 7.5 Admin-lockout guard

Revoking `admin`/`platform_admin` **MUST** be blocked with `409` if it would zero out every admin
grant on the platform (count active admin/platform_admin holders across all clients, excluding the
one being revoked). This is a platform-wide lockout guard, not just a self-lockout check. Reference:
`routers/admin_grants.py`.

### 7.6 Enforcement points

- RBAC is enforced as middleware after identity resolution: resolve the allowed role set for
  `(method, path)`; deny `403` if the caller holds none. Reference: `middleware/rbac.py::RBACMiddleware`
  (~L136), `PATH_ROLE_MAP` (~L59), `_resolve_allowed_roles` (~L117, longest/most-specific prefix wins).
- The RBAC public-path set **MUST** equal the auth public-path set exactly.
- RBAC is coarse (role × route). Fine-grained per-tool authorization is OPA's job at invocation time
  (deny-by-default; see [ARCHITECTURE.md](../ARCHITECTURE.md) §6). DB roles are authoritative; JWT
  roles are lab-convenience only (see [06-implementation-lessons.md](06-implementation-lessons.md) §6).

---

## 8. Standards conformance

| Standard | Where used | Status |
|---|---|---|
| RFC 6749 / OAuth 2.1 | authorization-code + PKCE client login; public-client model | Enforced |
| RFC 7636 (PKCE) | S256 mandatory on client login and credential enrollment; `plain` rejected | Enforced |
| RFC 7591 (dynamic client registration) | `POST /oauth/register` public-client bridge | Enforced |
| RFC 8414 (AS metadata) | `/.well-known/oauth-authorization-server` (proxied + filtered) | Enforced |
| RFC 9728 (protected-resource metadata) | `/.well-known/oauth-protected-resource[/path]` + 401 hint | Enforced |
| RFC 7519 (JWT) | session JWT (HS256) + IdP tokens (RS256) | Enforced |
| RFC 8725 (JWT BCP) | pinned algs, `kid` selection, `iss`/`aud`/`nonce`, fail-closed JWKS | Enforced |
| RFC 8693 (token exchange) | `kc_token_exchange` / `oauth_user_token` injection mode | **Partial** — direct-OIDC (Bearer) callers only; internal-session (browser) callers fail closed **(roadmap)** |

RFC 8693 status detail: on-behalf-of exchange requires the caller's own IdP access token as the
subject token. That token exists only on the direct-OIDC Bearer path (`request.state.user_kc_token`,
`auth.py` ~L270). Browser/session callers have no such token stored, so `oauth_user_token` for them
fails closed today. Reference: `credential_broker/dispatcher.py` mode docs (~L9–L17); README
"Credential injection modes" row.
