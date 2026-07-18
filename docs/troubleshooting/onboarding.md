# Troubleshooting: onboarding and submission review

**Audience:** anyone debugging a rejected submission, a failed approval, or an OAuth provider
profile that won't approve. For a tool call / credential-injection problem after a server is
already active, see [credential-injection.md](credential-injection.md) instead.

## Submission / review errors

| Symptom | Cause | Fix |
|---|---|---|
| `409 "submission is not in a rejectable state"` / similar 409s on approve/reject/request-changes | You're calling the endpoint from the wrong `submission_status`. | Check `GET /api/v1/submissions/{id}` first; see [../user/submission-lifecycle.md](../user/submission-lifecycle.md) for the valid state to call each endpoint from. |
| `403 "cannot review your own submission"` | Segregation of duties — reviewers can't approve/reject their own submissions. | Ask a different reviewer. |
| `422 OAUTH_POLICY_VIOLATION` on approve | The submission's issuer has no matching `oauth_provider_policy` row, requested scopes exceed the policy's `allowed_scopes`, or a high-risk scope wasn't acknowledged. | See [../admin/submission-review.md](../admin/submission-review.md) — usually: add a policy row for the issuer, narrow the requested scopes, or pass `high_risk_scopes_approved: true` if the reviewer genuinely intends to allow it. |
| `409 "cannot approve a scan-blocked submission"` | Scan hasn't finished, or genuinely failed (not `review_required`). | Wait for the scan, or check `GET /api/v1/admin/submissions/{id}/sbom` for why it failed. |
| `422 "no recorded scan_commit yet"` on `/apply` | Trying to `/apply` before a scan has completed and pinned a commit digest. | Wait for `scan_pending`/`scan_running` to finish. |
| `409 "/apply is only valid from ..."` | Submission is self-hosted (no `github_repo_url`) or already applied. | No-code submissions can't use `/apply` at all — self-host via `provide-url` or download the scaffold. |
| Server `verified`/`active` but no tools show up in `tools/list` | Tools are quarantined by design — deployment success ≠ tool trust. | An admin must release each tool: `POST /api/v1/admin/tools/{tool_id}/release` — see [../admin/submission-review.md](../admin/submission-review.md#after-approval--releasing-tools). |
| Build/deploy stuck or `deployment_status = 'failed'` | See [../admin/post-approval-activation.md](../admin/post-approval-activation.md#when-a-stage-fails) for the platform-managed pipeline's own failure modes. | Re-trigger with a fresh `POST .../apply`, or check the scanned commit still exists upstream. |

## OAuth provider profile errors

See [../admin/oauth-provider-setup.md](../admin/oauth-provider-setup.md) for the full flow. Quick
reference:

| Symptom | Fix |
|---|---|
| `discovery_applied: false` on profile creation | Not an error — the provider doesn't publish RFC 8414/OIDC metadata, or it was unreachable. Supply `authorization_endpoint`/`token_endpoint` manually. |
| Profile approval fails with a missing-fields error | `token_endpoint`/`authorization_endpoint`/`issuer` are required for every `provider_type` except `same_platform_idp` — fill them in before retrying approval. |
| Profile approval fails with an unknown-issuer error | No `oauth_provider_policy` row exists for that issuer yet — create one first. |

## Connecting your MCP client (OAuth login) fails

If your MCP client (Codex, Claude Code, …) fails to *log in* to the gateway —
e.g. `missing required issuer` at the callback — that's a client↔gateway OAuth
issue, distinct from the server-onboarding errors above. See
[oauth-client-connection.md](oauth-client-connection.md) for the cause, the
`grep oauth.discovery` log check, and the fix.

## "I changed `auth_modes.py` and something broke in docs/tests"

`proxy/tests/unit/test_auth_modes_doc_current.py` will fail — that's by design (WP-D2's
docs-drift guard). Run `python3 scripts/generate_auth_modes_doc.py` and commit the regenerated
[../reference/auth-modes.md](../reference/auth-modes.md).
