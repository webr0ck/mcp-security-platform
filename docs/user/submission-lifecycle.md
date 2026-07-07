# Submission lifecycle

**Audience:** anyone submitting an MCP server for onboarding, and reviewers/admins tracking one
through review.

This describes the REAL states a submission moves through today (post-WP-B3). There are two
independent state machines on the same `server_registry` row:

- `submission_status` — the review/hosting-path state machine (every submission has one).
- `deployment_status` — the platform-managed build→deploy→verify pipeline state (only set for
  submissions that use `/apply` instead of self-hosting; `NULL` otherwise).

A third, separate concept — **tool quarantine** — governs whether an already-provisioned tool can
actually be invoked, independent of both state machines above.

## 1. `submission_status`

```
draft
  │  POST /api/v1/submissions/{id}/submit
  ▼
scan_pending ──► scan_running ──► scan_blocked (scan infra failure — retry)
  │
  │ scan completes: passed | review_required | failed
  ▼
awaiting_review ──► changes_requested (reviewer sends it back; submitter edits, resubmits)
  │
  │ admin approves (POST /admin/submissions/{id}/approve)
  ▼
  ├─ has a github_repo_url ──► approved_pending_url ─┐
  └─ no-code (scaffold) submission ──► scaffold_ready ┤
                                                       │
                              ┌────────────────────────┴────────────────────────┐
                              │                                                 │
                    self-hosted path:                                platform-managed path:
                    POST .../provide-url                              POST .../apply
                    (submitter runs the server                        (see deployment_status
                     themselves, gives the URL)                        below — this is what
                              │                                        sets deployment_status,
                              ▼                                        submission_status stays
                          active                                       approved_pending_url/
                     (tools discovered,                                 scaffold_ready until
                      quarantined — see                                 the platform verify
                      §3 below)                                        phase finishes)
```

`rejected` can happen from `awaiting_review` (admin rejects instead of approves) — terminal, no
further action.

**Where this is enforced:** `server_registry.submission_status`, CHECK constraint
`ck_submission_status_valid` (`infra/db/migrations/V060__submission_status_check.sql`). Endpoints:
`routers/submission.py` (`/submit`, `/admin/submissions/{id}/approve`, `/reject`,
`/request-changes`, `/provide-url`, `/apply`).

## 2. `deployment_status` (platform-managed path only)

Set only once a submission calls `POST /api/v1/submissions/{id}/apply` instead of self-hosting.
`NULL` for every self-hosted (`provide-url`) submission and for anything not yet applied.

```
build_requested ──► building ──► built
                                    │
                                    ▼
                          deploy_requested ──► deploying ──► deployed
                                                                │
                                                                ▼
                                                      verify_requested ──► verifying ──► verified
```

Any stage can fail closed to `failed` — there is no automatic retry-forward; call `/apply` again
to start a fresh attempt. Poll `GET /api/v1/submissions/{id}/verification-report` for progress and
the final verification report (probe results, tools discovered).

**Where this is enforced:** `server_registry.deployment_status`, CHECK constraint
`ck_deployment_status_valid` (`infra/db/migrations/V068__deploy_verify_schema.sql`). See
[../admin/post-approval-activation.md](../admin/post-approval-activation.md) for the admin-facing
operational view of this pipeline.

## 3. Tool quarantine (separate from both state machines above)

The instant a server is provisioned (either path), the **tools it exposes are always discovered
into quarantine first** — `tool_registry.status = 'quarantined'`. A quarantined tool is registered
and visible in the catalog but **cannot be invoked**. An admin/reviewer must explicitly release
each tool: `POST /api/v1/admin/tools/{tool_id}/release`, which flips `status` to `active`.

This is deliberate and does not shortcut, even for a fully-verified platform-managed deployment:
**deployment success is not the same as tool trust.** A server can be `verified` /
`submission_status=active` and still have zero invocable tools until a human releases them.

Tool status values: `active` (invocable) | `quarantined` (discovered, awaiting release) |
`deprecated` | `disabled` (admin-disabled, was previously active).

## 4. What each status means for you

| You are... | State to watch | What to do |
|---|---|---|
| Submitter | `awaiting_review` | Wait — or `changes_requested` means a reviewer left notes; check `GET /api/v1/submissions/{id}`. |
| Submitter, self-hosting | `approved_pending_url` | Run your server, then `POST .../provide-url` with its URL. |
| Submitter, no-code | `scaffold_ready` | Either download the generated scaffold and self-host it (then `provide-url`), or call `/apply` to have the platform build/deploy it for you. |
| Submitter, using `/apply` | `deployment_status` progressing | Poll `GET .../verification-report`. |
| Anyone | Tools show up but calls fail with "quarantined" | Normal — ask an admin to release the tool once they've reviewed it. |

See also: [self-service-onboarding.md](self-service-onboarding.md) (the full walkthrough) and
[../admin/submission-review.md](../admin/submission-review.md) (the reviewer's side).
