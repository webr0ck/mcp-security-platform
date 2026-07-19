# Lessons: Generic OAuth 2.0 — Six Test Findings and Their Fixes

> A worked example of the kind of issue you find wiring a real generic-OAuth
> substrate, and how each was resolved. Dated evidence retained below.

## Remediation status (2026-07-07, same day)

All six findings' backend gaps are fixed — see the `[x]` items inline below and
the Finalization Checklist at the end. Verified via a full lab wipe
(`make -f Makefile.lab lab-setup-reset`) + fresh boot on the same code:
`make test-lab-functional` → 46 passed/1 skipped/0 failed; `make -f
Makefile.lab lab-acceptance` → 28 passed/2 skipped/0 failed — matching the
platform's known-good baseline with all six findings' code live, including
`test_kc_token_exchange_lab_tickets` and `test_at4_apply_deploy_verify`
(the platform-managed deploy/verify pipeline Findings 3/4 modified).
Remaining open items are UI work (wizard/admin screens) and live-lab E2E
tests per mode — both explicitly deferred, noted where they occur below.

## Repeat verification (2026-07-07)

Rerun from this workspace using the project venv (`proxy/.venv/bin/python`) after
the backend remediation changes landed:

- Generic OAuth/provider-profile/dispatcher unit set: `106 passed, 6 warnings`.
- Onboarding/submission OAuth unit set: `85 passed`.
- Deploy verifier/launcher/OAuth router/profile-router/scaffold unit set: `43 passed`.
- Dex external OAuth lab acceptance: `2 passed`.

One dependency drift was found during this repeat pass: `proxy/pyproject.toml`
declared `jsonschema==4.26.0`, but `proxy/requirements.txt` did not. That caused
the deploy verifier tests to fail under the system interpreter when importing
`app.services.contract_check`. `proxy/requirements.txt` is now aligned.

## Scope

Focused repeat review of the Generic OAuth 2.0 substrate from the perspective of the target user journey:

> A non-expert user can use mcp-selfservice to prepare or update MCP server code, apply it, verify it, and end with an MCP server that works against the backend service the user needs.

Special focus: adding and enabling an MCP server that works with:

- the same IdP as MCP Security Platform (`same_platform_idp` -> `kc_token_exchange`);
- a different OAuth/OIDC provider (`external_oauth_user_token` / `external_oauth_client_credentials`);
- service credentials (bearer/API key/basic auth);
- per-user bearer/JWT-style credentials.

## Tests Run

```bash
PYTHONPATH=proxy:observability/mcp-audit-logger proxy/.venv/bin/python -m pytest \
  proxy/tests/unit/test_generic_oauth_adapter.py \
  proxy/tests/unit/test_oauth_provider_profile.py \
  proxy/tests/unit/test_generic_service_adapter.py \
  proxy/tests/unit/test_dynamic_external_oauth.py \
  proxy/tests/unit/test_dispatcher_external_oauth.py \
  proxy/tests/unit/test_submission_mode_idp_validator.py \
  proxy/tests/unit/test_oauth_policy.py \
  proxy/tests/unit/test_oauth_enrollment_status.py \
  proxy/tests/unit/test_same_idp_verify.py \
  proxy/tests/unit/test_jira_adapter.py \
  -q
```

Result on repeat pass: `106 passed, 6 warnings in 1.32s`.

```bash
PYTHONPATH=proxy:observability/mcp-audit-logger proxy/.venv/bin/python -m pytest \
  proxy/tests/unit/test_server_onboarding_validation.py \
  proxy/tests/unit/test_submission_oauth_approval_gate.py \
  proxy/tests/unit/test_submission_mode_idp_validator.py \
  proxy/tests/unit/test_oauth_provider_profile.py \
  -q
```

Result on repeat pass: `85 passed in 0.96s`.

```bash
PYTHONPATH=proxy:observability/mcp-audit-logger proxy/.venv/bin/python -m pytest \
  lab/tests/acceptance/test_at1_dex_external_oauth.py \
  -q
```

Result on repeat pass: `2 passed in 2.44s`.

```bash
PYTHONPATH=proxy:observability/mcp-audit-logger proxy/.venv/bin/python -m pytest \
  proxy/tests/unit/test_deploy_verifier.py \
  proxy/tests/unit/test_deploy_launcher.py \
  proxy/tests/unit/test_oauth_router.py \
  proxy/tests/unit/test_oauth_provider_profiles_router.py \
  proxy/tests/unit/test_scaffold_generator.py \
  -q
```

Result on repeat pass: `43 passed in 1.56s`.

## What Is Proven Working

1. The generic OAuth adapter can build authorization URLs with PKCE, exchange authorization codes, refresh tokens, and support both `client_secret_post` and `client_secret_basic`.
2. The dynamic external OAuth resolver builds a per-server adapter only from reviewer-approved `server_registry.approved_upstream_idp_config`; it does not fall back to submitter-requested config.
3. Dispatcher support exists for `external_oauth_user_token` and `external_oauth_client_credentials`.
4. `oauth_provider_profile` exists as a schema and service/API layer with RFC 8414/OIDC discovery, profile approval, high-risk-scope acknowledgement, and recommendation mapping.
5. `same_idp_verify.run_same_idp_verify_probe()` exists and tests missing-token, wrong-audience, and expired-token rejection behavior.
6. `ServiceAdapter` and `GenericServiceAdapter` exist and are unit-tested as the reference "no extra discovery needed" service adapter.
7. The Dex acceptance test proves the external OAuth authorization-code path can work against a real lab provider.

## Findings

### Finding 1: OAuth Provider Profiles Are Not Wired Into Server Registration

Severity: high for self-service product completion.

`oauth_provider_profile` is implemented as a catalog primitive, and `server_registry` has `oauth_provider_profile_id`. But `ServerRegister` still accepts only raw `upstream_idp_type` and `upstream_idp_config`; it has no `oauth_provider_profile_id` field and does not copy approved profile metadata into the server registration.

Evidence:

- `proxy/app/routers/server_registry.py::ServerRegister` exposes `service_name`, `upstream_url`, `injection_mode`, `upstream_idp_type`, `upstream_idp_config`, and `adapter_name`, but no provider-profile selection field.
- `register_server_self_service()` inserts `upstream_idp_type` and raw `upstream_idp_config`; it does not persist `oauth_provider_profile_id`.
- `infra/db/migrations/V070__oauth_provider_profile.sql` added `server_registry.oauth_provider_profile_id`, but no production route writes it.

Impact:

A non-expert still needs to understand and submit raw OAuth/IdP fields. The new provider-profile catalog is testable as an API, but it is not the actual self-service path for enabling a server.

Required completion:

- Add `oauth_provider_profile_id` to the self-service submission/register model.
- Validate that the selected profile is `approved`.
- Derive `provider_type`, `injection_mode`, issuer, endpoints, default scopes, client auth method, token audience/resource, and service adapter from the profile.
- Persist `server_registry.oauth_provider_profile_id`.
- Materialize approved provider metadata into the existing approval path so dispatch still reads only approved config.
- Add tests proving a server can be registered by selecting a profile without manually supplying raw OAuth endpoints.

### Finding 2: Enrollment Consent Uses Unapproved Requested Config For Registered Servers

Severity: high for correctness and audit integrity.

`/auth/enroll/{service}` first resolves a server from the registry. If found, it queries `server_registry.upstream_idp_config` and uses that to render scopes on the consent page. The actual adapter used after consent is resolved via `_get_adapter()`, and dynamic external OAuth correctly uses `approved_upstream_idp_config`.

Evidence:

- `proxy/app/routers/oauth.py` reads `SELECT upstream_idp_config FROM server_registry WHERE service_name = :sname AND status = :st`.
- `proxy/app/credential_broker/adapters/dynamic_external_oauth.py` correctly reads `approved_upstream_idp_config`.
- `proxy/app/routers/oauth.py` stores consent-time scopes from the GET/POST flow into `credential_store.scopes`.

Impact:

For external OAuth, the UI/audit scope record can reflect submitter-requested config rather than reviewer-approved config. The access token request itself still uses the approved adapter, so this is not an immediate token-injection bypass, but it is a real product and audit mismatch.

Required completion:

- Change enrollment GET to read `approved_upstream_idp_config` and `approved_oauth_scopes`.
- If approved config is missing, fail closed with a clear admin-actionable error instead of falling back to requested config.
- Render the exact redirect URI from the resolved adapter/config, not the Entra-specific fallback.
- Add regression tests where requested scopes differ from approved scopes and the consent page/audit uses only approved scopes.

### Finding 3: Generic ServiceAdapter Exists But Is Not In The Runtime Flow

Severity: medium-high for final product completion.

`ServiceAdapter` and `GenericServiceAdapter` are implemented and tested, and `server_registry.service_context` exists. Nothing in actual submission, enrollment, apply, deploy, verify, or dispatch calls the adapter contract yet.

Evidence:

- `proxy/app/credential_broker/adapters/service_adapter.py` defines the contract.
- `proxy/app/credential_broker/adapters/generic_service_adapter.py` implements the generic no-discovery adapter.
- `infra/db/migrations/V070__oauth_provider_profile.sql` adds `server_registry.service_context`.
- Search shows no production code path that invokes `post_enrollment_discovery()`, `build_runtime_context()`, or persists `service_context`.

Impact:

Generic OAuth works only for services where OAuth token alone is enough and the MCP server already knows all required API context. It does not yet handle the intended "OAuth plus resource/service context" flow in a productized way.

Required completion:

- Add an adapter registry for `ServiceAdapter` slugs.
- Invoke post-enrollment discovery after successful OAuth enrollment where a profile has `service_adapter`.
- Persist selected non-secret context to `server_registry.service_context`.
- Pass `service_context` into apply/deploy/verify and MCP server config generation.
- Run `verify_access()` during verification and fail closed if the token cannot access the selected resource.

### Finding 4: Same-IdP Verify Probe Is Standalone Only

Severity: medium-high for same-IdP confidence.

The same-IdP probe exists and unit tests prove its behavior, but the deploy verifier does not call it. Same-platform-IdP servers can therefore pass the general MCP verify path without proving they reject missing, wrong-audience, and expired tokens at the upstream server boundary.

Required completion:

- When a server is `same_platform_idp` / `kc_token_exchange`, the verify phase must call `run_same_idp_verify_probe()` against the upstream runtime URL.
- Persist probe details into `server_registry.verification_report`.
- Make verify fail closed if any of the three negative probes is accepted.

### Finding 5: Same-IdP Server Scaffold/Config Generation Is Still Missing

Severity: medium for non-expert usability.

The platform can recommend "Same platform IdP", but it does not appear to generate the MCP server-side JWT validation middleware/config that a non-expert backend owner needs. The server still needs to validate issuer, audience, expiry, and signature itself.

Required completion:

- mcp-selfservice should generate language/framework-specific JWT validation code or configuration.
- Generated server config must include issuer, JWKS URI, expected audience, accepted algorithms, clock skew, and required claims.
- Verification must prove the generated server rejects bad tokens before release.

### Finding 6: OAuth Provider Profile API Is Admin-Usable But Not Yet User-Complete

Severity: medium.

The profile API supports discovery, create, approve, reject, and list. It is not yet a complete user flow:

- no admin UI or guided wizard screen is visible in this code pass;
- no route exposes "select approved provider profile for this server";
- no tests cover a full create-profile -> select-profile -> approve-server -> enroll -> invoke sequence;
- no automatic creation/sync of `oauth_provider_policy` from a provider profile was observed in the active server approval path.

Required completion:

- Build the self-service wizard around `recommend_provider_type`. **UI work, deferred** — needs a ui-dev pass; the backend it would call (`recommend-provider-type`, the new self-service listing below, `POST /api/v1/servers` from Finding 1) is now in place.
- Build admin/reviewer UI for provider profiles. **UI work, deferred** for the same reason.
- ~~no route exposes "select approved provider profile for this server"~~ (2026-07-07): added `GET /api/v1/oauth-provider-profiles` — self-service, non-admin, always filtered to `status='approved'` regardless of query params, so a submitter can list what to pass as `oauth_provider_profile_id`.
- ~~no automatic creation/sync of `oauth_provider_policy`~~ (2026-07-07): `oauth_provider_profile.py::approve_profile` now calls `oauth_policy.sync_policy_from_provider_profile`, upserting by `(issuer, tenant)` and only ever widening allow-lists — never silently narrowing a policy another submission already relies on.
- Add end-to-end tests for same-IdP, external OAuth per-user, external OAuth app-only, bearer/API key, and basic auth. **Deferred to a live-lab QA pass** — these need running Keycloak/Dex/lab containers (`lab/tests/acceptance/`), not unit-test mocks; this pass added thorough unit/integration coverage for the derivation and enforcement logic each mode depends on instead (see the test files touched per finding above).

## Concrete Generic OAuth End-State Specification

### Provider Profile Layer

The platform should maintain approved provider profiles as the product-facing abstraction:

```text
oauth_provider_profile
  provider_type: same_platform_idp | generic_oauth2 | entra | custom_oidc | jira_cloud
  issuer
  authorization_endpoint
  token_endpoint
  jwks_uri
  metadata_url
  default_scopes
  allowed_scopes
  blocked_scopes
  allowed_redirect_patterns
  allowed_client_auth_methods
  token_audience_or_resource
  supports_pkce
  supports_refresh_token
  supports_client_credentials
  service_adapter
  status
```

The user should select an approved profile, not hand-author raw OAuth JSON.

### Same IdP Flow

1. User selects "Same platform IdP".
2. Platform maps it to `kc_token_exchange` internally.
3. Reviewer approves audience/scope.
4. mcp-selfservice generates server JWT validation config/code.
5. Platform exchanges the caller's token for the approved audience at invocation.
6. Upstream MCP server validates the exchanged token.
7. Verify phase proves missing/wrong-audience/expired tokens are rejected.

### External OAuth Per-User Flow

1. Admin creates/approves a provider profile using RFC 8414 or manual endpoints.
2. User selects the profile for an MCP server.
3. Reviewer approves requested scopes and redirect/client-auth method.
4. User enrolls at `/auth/enroll/{service}`.
5. Platform stores only encrypted refresh token in `credential_store`.
6. Each invocation refreshes an access token and injects only the access token.
7. Service adapter optionally resolves and verifies resource context.

### External OAuth App-Only Flow

1. User/admin selects an approved profile with `supports_client_credentials=true`.
2. Admin stores client credentials in `credential_store`.
3. Dispatcher fetches a token from the approved token endpoint per call/cache policy.
4. The MCP server receives only a short-lived bearer token.

### Service Account / Bearer / Basic Flow

1. Wizard maps API key/bearer/basic to the existing `service`, `user`, or `basic_auth` injection modes.
2. Secrets stay in `credential_store`.
3. The self-service-generated MCP server code receives headers only, never stored secrets.
4. Verify proves missing/wrong credential is rejected where the upstream can be probed safely.

## Finalization Checklist

- [x] Wire `oauth_provider_profile_id` into self-service server registration/submission. (2026-07-07: `ServerRegister.oauth_provider_profile_id` added; `register_server_self_service` requires the profile `approved`, derives `injection_mode`/`upstream_idp_type`/issuer+endpoints/scopes from it, and rejects requested scopes outside the profile's allowed/blocked ceiling. `oauth_provider_profile` gained an `injection_mode` column (V074) since `provider_type` alone was ambiguous. `approve_server` (D3 dual-control admin path) now also materializes `approved_upstream_idp_config`/`approved_token_audience`/`approved_oauth_scopes`, which it previously never populated for self-service-registered servers.)
- [x] Use approved provider/profile data, not requested raw config, in OAuth enrollment consent. (2026-07-07: `GET /auth/enroll/{service}` now reads `approved_upstream_idp_config`/`approved_oauth_scopes` instead of the submitter's `upstream_idp_config`; fails closed with 409 if a config was requested but not yet approved; redirect_uri display now reflects the resolved config/adapter instead of always `ENTRA_REDIRECT_URI`.)
- [x] Persist and consume `server_registry.service_context`. (2026-07-07: `oauth.py::callback` persists it post-enrollment; `deploy_launcher.py` passes it to the container as `MCP_SERVICE_CONTEXT` env; `deploy_verifier.py` reads it for verify_access.)
- [x] Add ServiceAdapter registry and post-enrollment discovery flow. (2026-07-07: `app/credential_broker/adapters/service_adapter_registry.py` added — slug lookup defaulting to `GenericServiceAdapter`. `oauth.py::_run_post_enrollment_discovery` runs after a successful OAuth callback for any server backed by an `oauth_provider_profile`, fail-soft by design. `deploy_verifier.py::_run_service_adapter_verify` runs `verify_access()` fail-closed at deploy-verify time, scoped to `external_oauth_client_credentials` — the one mode with a verify-time token obtainable without a specific enrolled user; per-user coverage deferred, noted as a `ponytail:` ceiling in the code.)
- [x] Wire same-IdP negative-token probe into deploy verification. (2026-07-07: `deploy_verifier.py::_run_same_idp_verify` calls `run_same_idp_verify_probe()` for `kc_token_exchange`/`oauth_user_token` servers, persists the probe report into `verification_report.same_idp_verify`, and fails verification closed — including fail-closed when no `approved_token_audience` is recorded at all — if any of the three negative probes is accepted.)
- [x] Generate same-IdP JWT validation scaffold/config in mcp-selfservice. (2026-07-07: `scaffold_generator.py` now emits `jwt_validator.py` for `kc_token_exchange` scaffolds — issuer/JWKS URI pre-filled from `settings.OIDC_ISSUER_URL`, `KC_AUDIENCE` deliberately left unset since it's only known at reviewer-approval time, validates issuer/audience/expiry/signature with a 60s clock-skew leeway, fails closed with no default audience. The generated `server.py` calls it before touching the injected token. Finding 4's `run_same_idp_verify_probe` wiring is what actually proves this before release — the two findings compose.)
- [ ] Add E2E tests for profile-selected external OAuth per-user. **Needs a live lab** (Keycloak/Dex + a real registered server) — deferred to a QA pass; unit coverage for the derivation/consent/dispatch logic this depends on is in place (Findings 1-4's test files).
- [ ] Add E2E tests for profile-selected external OAuth client-credentials. Same as above.
- [ ] Add E2E tests for profile-selected same-platform IdP. Same as above — `run_same_idp_verify_probe` itself is unit-tested and now wired into verify; a live E2E would additionally prove a real deployed scaffold's `jwt_validator.py` rejects real bad tokens end-to-end.
- [ ] Add E2E tests for bearer/API-key/basic modes from self-service generation through verify/invoke. Same as above.
- [x] `GET /api/v1/oauth-provider-profiles` self-service listing + `oauth_provider_policy` auto-sync at profile-approval time (2026-07-07 — see Finding 6 above; this closes the two backend-completable gaps Finding 6 flagged. The wizard/admin UI and live-lab E2E items above remain open — UI and live-infra work respectively, out of scope for a backend-only pass).
