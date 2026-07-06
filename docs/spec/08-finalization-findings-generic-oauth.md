# Finalization Findings: Generic OAuth 2.0 Substrate and Service Adapters

**Status:** proposed finalization backlog, 2026-07-06.

**WP-A6 update (2026-07-07):** the user explicitly scoped a follow-up package to **Findings 1–3
only** ("main thing what should be done - generic oidc, not jira focused"). Findings 4 and 5 are
deliberately deferred and NOT built by WP-A6 — see the per-finding notes below.

- **Finding 1 (generic OAuth substrate as a product primitive): implemented, first pass.**
  `oauth_provider_profile` table (V070) + `services/oauth_provider_profile.py` +
  `routers/oauth_provider_profiles.py`. RFC 8414 discovery with OIDC-discovery fallback and a
  fail-soft-to-manual posture (`discover_metadata`, never raises). Reviewer-approval gate reuses
  WP-A2's `oauth_policy.get_policy_for_issuer` / `UnknownIssuerError` and its
  `HIGH_RISK_SCOPES` high-risk-scope-acknowledgement pattern rather than inventing a parallel
  mechanism. **Honest gap:** no admin UI (API only); a profile's `allowed_scopes` /
  `blocked_scopes` / `allowed_redirect_patterns` / `allowed_client_auth_methods` columns exist in
  the schema but `create_draft_profile` does not yet accept them as constructor args (only
  `default_scopes` is wired end-to-end) — extending that is a small, low-risk follow-up.
- **Finding 2 (same-IdP non-expert path): implemented, first pass.**
  `oauth_provider_profile.recommend_provider_type` maps the wizard's plain-language questions to
  `provider_type`/`injection_mode`, asserting (via unit test) that "kc_token_exchange" never
  appears in the submitter-facing `display_label` — the only user-visible string is
  "Same platform IdP". `services/same_idp_verify.run_same_idp_verify_probe` is the standalone
  missing/wrong-audience/expired-token rejection probe, with its own unit test suite (mocked
  httpx transport) — **not wired into any verify endpoint**, since WP-B3's verify pipeline is
  being built concurrently and did not exist yet when this was written. See the wiring note in
  `same_idp_verify.py`'s module docstring and in `docs/spec/01-authentication.md` §4.7. **Honest
  gap:** no scaffold-template generation for a same-IdP backend server's JWT-validation
  middleware (the finding doc's "Add scaffold templates..." backlog item) — not built.
- **Finding 3 (generic ServiceAdapter contract): implemented, first pass.**
  `credential_broker/adapters/service_adapter.py` (a `runtime_checkable` `Protocol`, not an ABC —
  a deliberate choice so `GenericServiceAdapter` needs no explicit inheritance to satisfy the
  contract) + `credential_broker/adapters/generic_service_adapter.py` (the reference "no extra
  discovery needed" adapter) + `server_registry.service_context` JSONB column (V070). Full unit
  test coverage including a structural `isinstance(adapter, ServiceAdapter)` conformance check.
  **Honest gap:** nothing yet calls `GenericServiceAdapter` from the actual onboarding/dispatch
  code path — it exists and is tested as a standalone contract + reference implementation, but is
  not yet invoked from `routers/submission.py` or `credential_broker/dispatcher.py`. Wiring it in
  is the natural next step once a submission flow needs to persist `service_context`.
- **Finding 4 (Jira Cloud `cloudId` resolution): explicitly deferred, out of scope for WP-A6.**
  Jira-specific; the existing `credential_broker/adapters/jira.py` (WP-A3/D2) is unchanged and
  remains the documented fast-follow it already was. `oauth_provider_profile.provider_type`
  reserves the `jira_cloud` value for a future adapter, but no `cloudId` discovery logic exists.
- **Finding 5 (apply/deploy/verify pipeline): out of scope for WP-A6, built separately as WP-B3.**
  A different work package is building this concurrently
  (`Codex_review/Claude_status.md`'s WP-B3 entry, `server_registry.verification_report` / V068).
  WP-A6 deliberately does not build a competing `/apply` endpoint, build worker, or deploy
  pipeline — see the Finding-2 same-IdP verify probe note above for how the two packages are
  meant to connect once WP-B3 lands its verify phase.

**Scope:** what remains to make self-service onboarding usable by a non-expert for MCP servers that call authenticated upstream services, especially services using the same OAuth/IdP as the MCP Security Platform, arbitrary external OAuth 2.0 services, and Jira Cloud.

**Primary references:**

- RFC 6749, OAuth 2.0 Authorization Framework: https://datatracker.ietf.org/doc/html/rfc6749
- RFC 7636, PKCE: https://datatracker.ietf.org/doc/html/rfc7636
- RFC 8414, OAuth 2.0 Authorization Server Metadata: https://datatracker.ietf.org/doc/html/rfc8414
- Atlassian OAuth 2.0 3LO apps: https://developer.atlassian.com/cloud/jira/software/oauth-2-3lo-apps/
- Atlassian OAuth API calls and cloudId format: https://developer.atlassian.com/cloud/oauth/getting-started/making-calls-to-api/

---

## Executive Finding

The platform should not treat Jira as the only "external OAuth" solution. It needs a generic OAuth 2.0 authentication substrate, plus service-specific adapters layered on top.

The split should be:

1. **Generic OAuth 2.0 auth substrate**
   - Stores provider/client metadata.
   - Drives authorization-code + PKCE enrollment.
   - Stores encrypted refresh tokens.
   - Refreshes access tokens per call.
   - Supports client-credentials where the upstream service is app-only.
   - Enforces reviewer-approved issuer, scopes, redirect URI, token audience/resource, and client auth method.

2. **Service adapter contract**
   - Adds service-specific behavior that OAuth alone cannot know.
   - Examples: Jira Cloud `cloudId`, Microsoft Graph base URL/resource, GitHub API base URL, custom tenant/workspace identifiers.
   - Verifies that a token actually works against a safe upstream API endpoint.
   - Provides runtime context to the MCP server without exposing stored credentials.

Jira Cloud should be one adapter using the generic OAuth substrate. It should not be the architecture.

---

## Current Code State

### Already Present

- `proxy/app/credential_broker/adapters/generic_oauth.py` provides a parameterized OAuth 2.0 authorization-code + refresh-token adapter.
- `proxy/app/credential_broker/adapters/dynamic_external_oauth.py` resolves a per-server adapter from `server_registry.approved_upstream_idp_config`.
- `proxy/app/services/oauth_policy.py` enforces issuer/scope/redirect/client-auth policy at approval time.
- `proxy/app/services/server_onboarding.py` validates `external_oauth_*` structural fields.
- `proxy/app/credential_broker/dispatcher.py` has branches for:
  - `kc_token_exchange`
  - `entra_user_token`
  - `entra_client_credentials`
  - `external_oauth_user_token`
  - `external_oauth_client_credentials`
  - `service`
  - `user`
  - `service_account`
  - `basic_auth`

### Not Complete

1. There is no product-level "OAuth provider profile" abstraction that a non-expert can select and enable.
2. Same-IdP upstream servers are not easy enough to onboard. The user must understand `kc_token_exchange`, audience allowlists, approved audiences, and upstream trust in the platform Keycloak realm.
3. Generic OAuth is code-present but not a complete user journey. It lacks provider discovery, admin/provider setup UX, verifier UX, and service-adapter context.
4. Jira Cloud is only a token-lifecycle adapter. It does not resolve or persist `cloudId`, which is required for Jira Cloud API calls via `https://api.atlassian.com/ex/jira/{cloudId}/...`.
5. The apply/deploy/verify pipeline is not built. Even with correct OAuth, self-service still stops before platform-managed deployment.

---

## Finding 1: Generic OAuth 2.0 Auth Substrate Is the Missing Product Primitive

### Problem

Today the platform has several auth modes, but the user-facing model is still too implementation-shaped. A non-expert should not need to know whether a service is implemented as `external_oauth_user_token`, `entra_user_token`, `kc_token_exchange`, or `service`.

They should answer:

- Is the backend service protected by the same IdP as this platform?
- If not, does it support OAuth 2.0 authorization code?
- Is access per-user or app-only?
- Does the service need an API key/bearer token/basic auth instead?

The platform should map that to the right mode and required admin/reviewer setup.

### Required End-State

Add a first-class OAuth provider profile model:

```text
oauth_provider_profile
  id
  slug
  display_name
  provider_type
    - same_platform_idp
    - generic_oauth2
    - jira_cloud
    - entra
    - custom_oidc
  issuer
  authorization_endpoint
  token_endpoint
  jwks_uri
  metadata_url
  default_scopes
  allowed_scopes
  blocked_scopes
  high_risk_scopes
  allowed_redirect_patterns
  allowed_client_auth_methods
  token_audience_or_resource
  supports_pkce
  supports_refresh_token
  supports_client_credentials
  service_adapter
  created_by
  approved_by
  status
```

The existing `oauth_provider_policy` table can remain the enforcement table, but the user journey needs an explicit provider profile abstraction above it.

### Behavior

When a submitter selects "OAuth 2.0 service", the platform should:

1. Ask for issuer or metadata URL.
2. Fetch RFC 8414 metadata when available.
3. Pre-fill authorization endpoint, token endpoint, supported auth methods, scopes, and JWKS URI.
4. Require an admin/reviewer to approve the provider profile before use.
5. Store client secret in `credential_store`, never in plain config.
6. Enforce PKCE S256 for authorization-code flows where possible.
7. Store refresh tokens encrypted per authenticated principal.
8. Mint/refresh access tokens per invocation.
9. Never pass the stored refresh token or client secret to the MCP server.

### Acceptance Criteria

- A new external OAuth provider can be added without a Python code change if it follows normal OAuth 2.0 authorization-code or client-credentials behavior.
- A provider with RFC 8414 metadata can be configured by entering only the issuer/metadata URL plus client registration details.
- A provider without RFC 8414 metadata can still be configured manually with explicit endpoints.
- Unknown issuer or missing provider policy fails closed at approval.
- Scope requests outside the approved policy fail closed.
- High-risk scopes require explicit reviewer acknowledgement.
- A failed token refresh aborts the tool call and returns an enrollment/actionable error, not an unauthenticated upstream request.

---

## Finding 2: Same-IdP MCP Server Onboarding Needs a Simple First-Class Path

### Problem

For a service protected by the same IdP as the MCP Security Platform, the desired user story is:

> The user signs into the platform once. The MCP server accepts a token minted by the same IdP. No second OAuth enrollment is needed.

The current code shape is `kc_token_exchange`: the caller's Keycloak token is exchanged for a token with an upstream audience. That is correct for same-realm delegation, but not yet simple enough as a self-service workflow.

### Required End-State

Add a self-service/provider option:

```text
Auth option: Same platform IdP
Meaning: upstream service trusts the platform's IdP issuer.
Mode: kc_token_exchange
Required admin fields:
  - approved upstream audience
  - allowed scopes, if used
  - upstream JWKS/issuer expectation, if the verifier needs it
  - whether upstream validates azp/actor/delegation claims
Required MCP server behavior:
  - validate issuer
  - validate audience
  - validate expiry
  - validate signature
  - use token subject for per-user authorization
```

### Flow

1. Submitter says the backend service uses the same IdP as the platform.
2. Wizard recommends `kc_token_exchange`.
3. Wizard asks for the upstream token audience, not raw OAuth internals.
4. Reviewer approves audience and scopes.
5. Discovery writes the approved audience into each discovered tool.
6. At invocation, the broker exchanges the caller's platform token for an upstream-audience token.
7. MCP server receives `Authorization: Bearer <exchanged-token>`.
8. MCP server validates token and executes under the user's identity.

### What Must Be Done

- Hide `kc_token_exchange` terminology from non-expert users; show "same platform IdP".
- Add wizard validation that explains what the upstream MCP server must validate.
- Add scaffold templates for same-IdP backend servers with JWT validation middleware.
- Add a verify check that calls the MCP server and confirms it rejects:
  - missing token
  - wrong audience token
  - expired/invalid token
- Add an acceptance test for a new self-service server using same-IdP auth, not just pre-seeded lab tools.

---

## Finding 3: Generic OAuth 2.0 Needs a Service Adapter Contract

### Problem

OAuth authenticates to an authorization server. It does not define:

- the resource API base URL,
- tenant/site/workspace identifiers,
- how to discover the target account,
- which endpoint is safe for verification,
- how the MCP server should receive service context.

Without a service adapter layer, every real SaaS integration becomes ad hoc.

### Required Adapter Interface

Each service adapter should implement:

```text
ServiceAdapter
  slug
  display_name
  auth_provider_type
  required_oauth_fields()
  default_scopes()
  validate_provider_config(config)
  post_enrollment_discovery(access_token, requested_config)
  select_resource(discovered_resources, user_choice)
  build_runtime_context(approved_config, selected_resource)
  verify_access(access_token, runtime_context)
  safe_probe_endpoint(runtime_context)
```

### Runtime Context

The adapter should persist non-secret service context separately from OAuth secrets:

```text
server_registry.service_context
  adapter: jira_cloud
  api_base_url: https://api.atlassian.com/ex/jira/{cloudId}
  resource_id: <cloudId>
  resource_name: <site name>
  resource_url: https://example.atlassian.net
  verified_at
```

This context is not a credential. It may be passed to the MCP server as config or environment during deploy/verify.

### Acceptance Criteria

- Adding a new OAuth service does not require modifying the broker if it has no API-specific discovery needs.
- Adding a service with API-specific discovery requires only a new adapter implementing the contract.
- The OAuth token lifecycle remains centralized in the broker.
- The service adapter never stores refresh tokens or client secrets.
- Verification is adapter-specific but uses the same platform verify state machine.

---

## Finding 4: Jira Cloud Should Be a First-Class Adapter on Top of Generic OAuth

### Problem

Jira Cloud OAuth 2.0 3LO is not complete when the platform only obtains an Atlassian access token. Jira Cloud API calls require a `cloudId`; Atlassian documents API calls as:

```text
https://api.atlassian.com/ex/jira/{cloudId}/{api}
```

The `cloudId` is discovered from Atlassian's accessible resources endpoint after OAuth succeeds.

### Required Jira Adapter Behavior

The Jira Cloud adapter should:

1. Use generic OAuth 2.0 authorization-code + PKCE enrollment.
2. Request Atlassian scopes approved by policy.
3. Exchange code for access/refresh token.
4. Call:

```text
GET https://api.atlassian.com/oauth/token/accessible-resources
Authorization: Bearer <access_token>
```

5. If one Jira site is returned, persist it automatically.
6. If multiple sites are returned, ask the user/reviewer to choose one.
7. Persist:

```text
service_context.adapter = "jira_cloud"
service_context.cloud_id = "<cloudId>"
service_context.site_url = "https://example.atlassian.net"
service_context.api_base_url = "https://api.atlassian.com/ex/jira/<cloudId>"
```

8. Verify access with a safe endpoint such as:

```text
GET /rest/api/3/myself
```

or another read-only endpoint approved by the adapter policy.

9. Pass only `api_base_url` and non-secret context to the MCP server. The platform still injects the access token per call.

### Acceptance Criteria

- A Jira Cloud MCP server can be onboarded without hardcoding a tenant URL into the broker.
- The user can complete OAuth enrollment and select a Jira site if needed.
- The platform verifies the selected Jira site before marking deployment verified.
- Invocation injects `Authorization: Bearer <access_token>` and the MCP server calls the resolved `api_base_url`.
- The raw refresh token is never visible to the MCP server or client.

---

## Finding 5: Self-Service Must Lead to Apply, Verify, Release, Not Just Submit

### Problem

Even perfect OAuth handling will not satisfy the goal if a non-expert user still has to self-host the MCP server and manually provide a URL.

The current flow ends in:

- `approved_pending_url` for repo-backed submissions, requiring the user to run the server somewhere and call `provide-url`.
- `scaffold_ready` for no-code submissions, requiring the user to download/build/host/submit again.

### Required End-State

Self-service should expose a guided lifecycle:

```text
draft
scan_pending
scan_running
awaiting_review
approved
apply_requested
building
built
deploying
deployed
verifying
verified
tools_discovered_quarantined
released
active
```

### Apply Step

`POST /api/v1/submissions/{id}/apply` should:

1. Require approved submission.
2. Require scan status `passed` or reviewer-accepted `review_required`.
3. Pin the exact scanned commit/content digest.
4. Enqueue build job.
5. Return status and next polling URL.

### Verify Step

Verification should be auth-mode aware:

- `none`: MCP initialize + tools/list + safe tool call.
- `service`: credential exists, token injected, safe call succeeds.
- `basic_auth`: structured credential exists, upstream sees Basic header, safe call succeeds.
- `service_account`: KC client credentials can mint a token and upstream accepts it.
- `kc_token_exchange`: exchanged same-IdP token is accepted by upstream.
- `entra_user_token`: user enrollment exists and delegated token works.
- `external_oauth_user_token`: user enrollment exists, service adapter verification succeeds.
- `external_oauth_client_credentials`: app token works, service adapter verification succeeds.

### Release Step

Tool release should remain explicit:

1. Verify server first.
2. Discover tools into quarantine.
3. Reviewer releases tools.
4. Invocation becomes available.

This preserves the security model: deployment success is not the same as tool trust.

---

## Prioritized Backlog

### P0: Generic OAuth Substrate Productization

- Add OAuth provider profile model and admin UI/API.
- Add provider metadata discovery using RFC 8414 when available.
- Add provider policy creation/approval UX.
- Store OAuth client secrets via existing encrypted credential store.
- Make self-service wizard select provider profiles instead of raw endpoints where possible.

### P0: Same-IdP Onboarding

- Add "same platform IdP" wizard path.
- Generate JWT-validating MCP server scaffold for same-IdP mode.
- Add verification tests for audience/issuer enforcement.
- Add end-to-end acceptance: self-service server using same platform IdP.

### P0: Apply/Deploy/Verify

- Implement `POST /apply`.
- Implement build worker.
- Implement isolated deploy launcher.
- Implement verifier and `GET /verification-report`.
- Promote runtime URL only after verification.

### P1: Jira Cloud Adapter

- Complete `JiraCloudServiceAdapter`.
- Resolve accessible resources and `cloudId`.
- Add site selection when multiple resources exist.
- Persist service context.
- Verify with safe Jira endpoint.
- Add Jira-specific scaffold/config example.

### P1: Adapter Contract

- Define `ServiceAdapter` interface.
- Add generic "no extra discovery" adapter.
- Add Jira Cloud adapter.
- Add Entra/Microsoft Graph adapter shape using the same contract.

### P1: Documentation Honesty

- Update README auth-mode table to reflect current dispatcher support.
- Update `docs/spec/05-integrations.md` to distinguish:
  - generic OAuth substrate,
  - same-IdP token exchange,
  - service adapter behavior,
  - Jira Cloud specifics.

---

## Definition of Done

This work is final when a non-expert can complete these flows:

1. **Same platform IdP**
   - User selects "same platform IdP".
   - Platform generates or validates a scaffold that checks issuer/audience.
   - Platform builds/deploys/verifies it.
   - User invokes it after reviewer release.

2. **Generic OAuth 2.0 per-user**
   - Admin creates/approves provider profile.
   - User enrolls with provider.
   - Platform stores refresh token encrypted.
   - Platform injects fresh access token per call.
   - MCP server works without seeing stored secrets.

3. **Jira Cloud**
   - User selects Jira Cloud preset.
   - User completes Atlassian OAuth.
   - Platform discovers/selects `cloudId`.
   - Platform verifies a safe Jira endpoint.
   - MCP server calls Jira through the resolved `api_base_url`.

4. **Service account / bearer / basic**
   - Admin uploads credential or client secret.
   - Platform verifies injection.
   - MCP server works without user-managed secrets.

5. **No manual hosting required**
   - The platform can apply, deploy, verify, discover, and release a server from a self-service submission.

