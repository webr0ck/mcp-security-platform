# API endpoint reference

**Audience:** anyone integrating against the platform's REST API directly (not through the portal
UI). This is an index — each row links to the doc that has full request/response detail and
worked examples; FastAPI's own OpenAPI docs (`/docs`, `/openapi.json`) are the byte-for-byte
authoritative schema for every field.

## Self-service submission

| Method | Path | Role required | See |
|---|---|---|---|
| POST | `/api/v1/submissions` | any authenticated principal | [../user/self-service-onboarding.md](../user/self-service-onboarding.md) |
| PATCH | `/api/v1/submissions/{id}` | owner | [../user/self-service-onboarding.md](../user/self-service-onboarding.md) |
| POST | `/api/v1/submissions/{id}/submit` | owner | [../user/self-service-onboarding.md](../user/self-service-onboarding.md) |
| GET | `/api/v1/submissions` | owner (own only) | — |
| GET | `/api/v1/submissions/{id}` | owner | [../user/submission-lifecycle.md](../user/submission-lifecycle.md) |
| POST | `/api/v1/submissions/{id}/provide-url` | owner | [../user/self-service-onboarding.md](../user/self-service-onboarding.md) |
| POST | `/api/v1/submissions/{id}/apply` | owner | [../admin/post-approval-activation.md](../admin/post-approval-activation.md) |
| GET | `/api/v1/submissions/{id}/verification-report` | owner | [../admin/post-approval-activation.md](../admin/post-approval-activation.md) |
| GET | `/api/v1/submissions/{id}/scaffold` | owner | — (no-code path scaffold download) |
| GET | `/api/v1/design-assist` | any | agent-native wizard question API |

## Review queue (admin)

| Method | Path | Role required | See |
|---|---|---|---|
| GET | `/api/v1/admin/submissions` | reviewer (read: `admin`/`platform_admin`/`security_auditor`/`auditor`) | [../admin/submission-review.md](../admin/submission-review.md) |
| GET | `/api/v1/admin/submissions/{id}/sbom` | reviewer | [../admin/submission-review.md](../admin/submission-review.md) |
| POST | `/api/v1/admin/submissions/{id}/approve` | `admin`/`platform_admin`/`security_reviewer` | [../admin/submission-review.md](../admin/submission-review.md) |
| POST | `/api/v1/admin/submissions/{id}/reject` | `admin`/`platform_admin`/`security_reviewer` | [../admin/submission-review.md](../admin/submission-review.md) |
| POST | `/api/v1/admin/submissions/{id}/request-changes` | `admin`/`platform_admin`/`security_reviewer` | [../admin/submission-review.md](../admin/submission-review.md) |
| POST | `/api/v1/admin/tools/{tool_id}/release` | `admin`/`platform_admin`/`security_reviewer` | [../admin/submission-review.md](../admin/submission-review.md) |

## Credentials (admin)

| Method | Path | Role required | See |
|---|---|---|---|
| PUT | `/admin/credentials/{tool_id}` | `admin` | [../admin/credential-provisioning.md](../admin/credential-provisioning.md) |
| DELETE | `/admin/credentials/{tool_id}` | `admin` | [../admin/credential-provisioning.md](../admin/credential-provisioning.md) |
| PUT | `/admin/credentials/{tool_id}/injection-mode` | `admin` | [../admin/credential-provisioning.md](../admin/credential-provisioning.md) |
| POST | `/admin/credentials/{tool_id}/enroll` | `admin` | device-flow OAuth2 enrollment |
| GET | `/auth/status/{service}` | any authenticated principal | per-user enrollment status check |

## OAuth provider profiles (admin)

| Method | Path | Role required | See |
|---|---|---|---|
| POST | `/api/v1/admin/oauth-provider-profiles` | `admin`/`platform_admin` | [../admin/oauth-provider-setup.md](../admin/oauth-provider-setup.md) |
| POST | `/api/v1/admin/oauth-provider-profiles/discover` | `admin`/`platform_admin` | [../admin/oauth-provider-setup.md](../admin/oauth-provider-setup.md) |
| GET | `/api/v1/admin/oauth-provider-profiles` | `admin`/`platform_admin` | [../admin/oauth-provider-setup.md](../admin/oauth-provider-setup.md) |
| POST | `/api/v1/admin/oauth-provider-profiles/{id}/approve` | `admin`/`platform_admin` | [../admin/oauth-provider-setup.md](../admin/oauth-provider-setup.md) |
| POST | `/api/v1/admin/oauth-provider-profiles/{id}/reject` | `admin`/`platform_admin` | [../admin/oauth-provider-setup.md](../admin/oauth-provider-setup.md) |
| POST | `/api/v1/wizard/recommend-provider-type` | any authenticated principal | [../user/auth-mode-decision-guide.md](../user/auth-mode-decision-guide.md) |

## RBAC / grants (admin)

| Method | Path | Role required | See |
|---|---|---|---|
| POST/DELETE | `/api/v1/admin/roles`, `/api/v1/admin/roles/{client_id}/{role}` | `admin`/`platform_admin` | [../admin/rbac-and-grants.md](../admin/rbac-and-grants.md) |
| GET/POST/DELETE | `/api/v1/admin/grants` | `admin`/`platform_admin` | [../admin/rbac-and-grants.md](../admin/rbac-and-grants.md) |
| POST | `/api/v1/admin/sync-grants` | `admin`/`platform_admin` | [../admin/rbac-and-grants.md](../admin/rbac-and-grants.md) |
| GET/POST/DELETE | `/api/v1/admin/api-keys` | `admin`/`platform_admin` | [../admin/rbac-and-grants.md](../admin/rbac-and-grants.md) |
| GET | `/api/v1/admin/principals` | `admin`/`platform_admin` | [../admin/rbac-and-grants.md](../admin/rbac-and-grants.md) |

## Invocation

| Method | Path | Role required | See |
|---|---|---|---|
| POST | `/mcp` (JSON-RPC: `initialize`, `tools/list`, `tools/call`) | any entitled principal | [../user/using-approved-server.md](../user/using-approved-server.md) |

## Envelope conventions

Every JSON response is a plain JSON object (no forced envelope wrapper across all routers — check
each endpoint's own shape above). Errors from these REST endpoints use standard HTTP status codes
(401/403/404/409/422/503) with a `detail` field — sometimes a plain string, sometimes a structured
`{"code": "...", "message": "..."}` object for policy-shaped rejections (e.g.
`OAUTH_POLICY_VIOLATION`). MCP tool-invocation errors are different — see
[../user/using-approved-server.md#important-http-200-does-not-mean-success](../user/using-approved-server.md#important-http-200-does-not-mean-success).
