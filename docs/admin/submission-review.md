# Reviewer approval guide

**Audience:** anyone with the `security_reviewer`, `admin`, or `platform_admin` role reviewing an
MCP server submission.

> Commands below assume you're either going through the real gateway/mTLS path, or (for a lab
> walkthrough) running inside the `mcp-proxy` container — see
> [../user/self-service-onboarding.md's Prerequisites](../user/self-service-onboarding.md#prerequisites).

## Roles

- `admin` / `platform_admin` / `security_reviewer` — may approve, reject, or request changes
  (`_require_submission_reviewer`).
- `admin` / `platform_admin` / `security_auditor` / `auditor` — may view the review queue
  read-only (`_require_reviewer`), but not mutate it unless they also hold one of the roles above.
- **Segregation of duties**: you cannot review your own submission, even with a reviewer/admin
  role (`_require_not_self_review` — 403 if you try).

## Queue

```bash
curl -sf http://localhost:8000/api/v1/admin/submissions -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
```

Filter to what needs your attention: `submission_status` in `awaiting_review` (scan finished or
not applicable, needs a decision) — do not approve out of `scan_pending`/`scan_running`
(the scan must complete or be genuinely not-applicable first; the approve endpoint enforces this).

## Before you approve — check the scan result

`scan_status` must be `passed`, `not_applicable` (no repo to scan), or `review_required` before
approval is even accepted (HTTP 409 otherwise). `review_required` (WP-B2/CR-12) means the CVE gate
found something ambiguous — an unknown-severity CVE, a missing lockfile, or a scanner-tool
load failure — not necessarily malicious. Read the scan report
(`GET /api/v1/admin/submissions/{id}/sbom`) before approving past it; you may still approve, but
do so deliberately, optionally after adding a waiver for a specific finding.

## Approve

```bash
curl -sf -X POST http://localhost:8000/api/v1/admin/submissions/$SID/approve \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"notes": "looks good"}'
```

**If the submission has no OAuth/IdP-governed auth mode** (e.g. `none`, `service`, `user`,
`basic_auth`, `service_account`), that's the whole approval — done.

**If the mode is `kc_token_exchange`** you must also supply `approved_token_audience` (unless the
submitter already put one in their `upstream_idp_config`):

```bash
curl -sf -X POST http://localhost:8000/api/v1/admin/submissions/$SID/approve \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"notes": "approved for kc token exchange", "approved_token_audience": "my-service"}'
```

The audience must also be in the platform's `KC_TOKEN_EXCHANGE_ALLOWED_AUDIENCES` ceiling — a
mismatch or missing audience returns `422 OAUTH_POLICY_VIOLATION`, not a silent pass.

**If the mode is `entra_user_token`/`entra_client_credentials`/`external_oauth_*`** the requested
`upstream_idp_config` (issuer, scopes, redirect_uri, client_auth_method) is validated against a
matching `oauth_provider_policy` row (by issuer+tenant). An **unknown issuer fails closed** —
`422 OAUTH_POLICY_VIOLATION` — you (or another admin) must first add a policy row for that issuer
before the submission can be approved. If the requested scopes include a high-risk one
(`write`/`admin`/`mail`/`files`/`offline_access`), you must explicitly acknowledge it:

```bash
curl -sf -X POST http://localhost:8000/api/v1/admin/submissions/$SID/approve \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"notes": "high-risk scope reviewed and accepted", "high_risk_scopes_approved": true}'
```

Without `high_risk_scopes_approved: true`, this returns `422` — the platform never silently
approves a high-risk scope. This is the same non-negotiable pattern used by the OAuth provider
profile catalog (see [oauth-provider-setup.md](oauth-provider-setup.md)) — no PASS/approval
without a recorded policy evaluation, and no high-risk grant without an explicit, identity-stamped
acknowledgement.

**Result:** `submission_status` becomes `approved_pending_url` (has a repo URL) or
`scaffold_ready` (no-code). Neither is invocable yet — the submitter still needs to provide a
running URL or call `/apply` (see [post-approval-activation.md](post-approval-activation.md)).

## Reject

```bash
curl -sf -X POST http://localhost:8000/api/v1/admin/submissions/$SID/reject \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"notes": "does not meet policy: <reason>"}'
```

Terminal — only valid from `awaiting_review`/`scan_blocked`/`scan_pending`/`changes_requested`
(409 otherwise, so you can't accidentally reject an already-active server).

## Request changes

```bash
curl -sf -X POST http://localhost:8000/api/v1/admin/submissions/$SID/request-changes \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"notes": "please fix: <specific ask>"}'
```

Sends it back to the submitter (`submission_status = changes_requested`); they can `PATCH` and
resubmit.

## After approval — releasing tools

Approval and even a fully `verified` platform-managed deployment do **not** make tools invocable.
Every discovered tool starts `quarantined`; you must explicitly release each one:

```bash
curl -sf -X POST http://localhost:8000/api/v1/admin/tools/$TOOL_ID/release -H "Authorization: Bearer $TOKEN"
```

This is intentional (deployment success ≠ tool trust) — review what the tool actually does before
releasing it, same diligence as the submission approval itself.
