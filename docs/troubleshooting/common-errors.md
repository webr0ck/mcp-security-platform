# Common errors and remediation

**Audience:** anyone debugging a rejected submission, a failed approval, or a tool call that isn't
working. Read [../user/invoking-tools.md#important-http-200-does-not-mean-success](../user/invoking-tools.md#important-http-200-does-not-mean-success)
first if you're debugging a tool call specifically — the HTTP status code alone will mislead you.

## Submission / review errors

| Symptom | Cause | Fix |
|---|---|---|
| `409 "submission is not in a rejectable state"` / similar 409s on approve/reject/request-changes | You're calling the endpoint from the wrong `submission_status`. | Check `GET /api/v1/submissions/{id}` first; see [../user/submission-lifecycle.md](../user/submission-lifecycle.md) for the valid state to call each endpoint from. |
| `403 "cannot review your own submission"` | Segregation of duties — reviewers can't approve/reject their own submissions. | Ask a different reviewer. |
| `422 OAUTH_POLICY_VIOLATION` on approve | The submission's issuer has no matching `oauth_provider_policy` row, requested scopes exceed the policy's `allowed_scopes`, or a high-risk scope wasn't acknowledged. | See [../admin/reviewer-approval-guide.md](../admin/reviewer-approval-guide.md) — usually: add a policy row for the issuer, narrow the requested scopes, or pass `high_risk_scopes_approved: true` if the reviewer genuinely intends to allow it. |
| `409 "cannot approve a scan-blocked submission"` | Scan hasn't finished, or genuinely failed (not `review_required`). | Wait for the scan, or check `GET /api/v1/admin/submissions/{id}/sbom` for why it failed. |
| `422 "no recorded scan_commit yet"` on `/apply` | Trying to `/apply` before a scan has completed and pinned a commit digest. | Wait for `scan_pending`/`scan_running` to finish. |
| `409 "/apply is only valid from ..."` | Submission is self-hosted (no `github_repo_url`) or already applied. | No-code submissions can't use `/apply` at all — self-host via `provide-url` or download the scaffold. |

## Tool invocation errors

The proxy speaks JSON-RPC over HTTP — **every** gate failure in the invoke path (auth, network/SSRF,
entitlement, OPA policy, credential injection) returns an HTTP 200 with a JSON-RPC `error` object,
not an HTTP 4xx. Always check the response body's `error` key.

| `error.code` / message pattern | Cause | Fix |
|---|---|---|
| Tool absent from `tools/list` entirely | Quarantined, or you're not entitled to it, or it's `disabled`. | Ask an admin to check `tool_registry.status` and release it if appropriate (see [../admin/reviewer-approval-guide.md](../admin/reviewer-approval-guide.md)); check your client's grants (see [../admin/rbac-and-grants.md](../admin/rbac-and-grants.md)). |
| `"Tool '<name>' (<id>) is quarantined and cannot be invoked."` | Explicitly calling a quarantined tool by name. | Same as above — needs an admin release, not a client-side fix. |
| `-32001 "Downstream authorization required."` | The upstream itself (a foreign IdP, e.g. Entra) is challenging — a delegated/`passthrough` mode where the caller isn't enrolled or their token expired. | Follow the `data.www_authenticate`/`downstream_challenge` in the error, or re-enroll via `GET /auth/status/{service}`. |
| `-32603 "Upstream MCP server error."` | The upstream server itself errored, timed out, or the invoke/init handshake failed. | Check the upstream server's own health/logs — this is downstream of the platform's own gates, not a platform-side auth failure. |
| Deny audited with reason `"not_entitled:<reason>"` | Your client's grants don't cover this tool/tag/risk-level. | See [../admin/rbac-and-grants.md](../admin/rbac-and-grants.md) — an admin needs to add a grant. |
| `CredentialInjectionError` (surfaces as a `-32603`-shaped error, always DENY-audited) | The configured auth mode couldn't produce a credential: not enrolled yet, revoked/missing secret, an OAuth policy violation at dispatch time, or the credential broker itself is unreachable. | Check [../reference/injection-modes.md](../reference/injection-modes.md) for what that mode needs; for per-user modes (`entra_user_token`, `external_oauth_user_token`, `kc_token_exchange`) the caller usually just needs to (re-)enroll. **This never means the request went through unauthenticated** — the platform fails closed rather than forwarding without the intended credential. |
| `ValueError`/deny: `"SSRF blocked upstream URL at invoke time: ..."` | The upstream host re-resolved to a different/private IP since registration (DNS-rebind guard) or genuinely violates the SSRF policy. | If legitimate (e.g. a lab-internal target), the server needs to be registered with the correct `UPSTREAM_PRIVATE_CIDR_ALLOWLIST` entry — an admin/infra concern, not something a caller can work around. |

## OAuth provider profile errors

See [../admin/oauth-provider-setup.md](../admin/oauth-provider-setup.md) for the full flow. Quick
reference:

| Symptom | Fix |
|---|---|
| `discovery_applied: false` on profile creation | Not an error — the provider doesn't publish RFC 8414/OIDC metadata, or it was unreachable. Supply `authorization_endpoint`/`token_endpoint` manually. |
| Profile approval fails with a missing-fields error | `token_endpoint`/`authorization_endpoint`/`issuer` are required for every `provider_type` except `same_platform_idp` — fill them in before retrying approval. |
| Profile approval fails with an unknown-issuer error | No `oauth_provider_policy` row exists for that issuer yet — create one first. |

## "I changed `auth_modes.py` and something broke in docs/tests"

`proxy/tests/unit/test_auth_modes_doc_current.py` will fail — that's by design (WP-D2's
docs-drift guard). Run `python3 scripts/generate_auth_modes_doc.py` and commit the regenerated
[../reference/auth-modes.md](../reference/auth-modes.md).
