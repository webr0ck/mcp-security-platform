# PRD-0007 — Submission lifecycle: state machine, reviewer authority, quarantine release

- **Status:** SPEC v1 — closes the 5 MEDIUM completeness gaps from validation-2026-07-05.
- **Date:** 2026-07-05
- **Author:** platform team
- **Scope:** formalize what the code already does (state machine, reviewer roles) and specify the
  under-defined bits (quarantine-release, update/resubmit, submission-endpoint ACs). Code-accurate.

## 1. Submission state machine (gap #2)

`server_registry.submission_status` — 11 states, now DB-guarded (`V060` CHECK). NULL = admin-registered
server that skipped the submission workflow.

**States:** `draft` · `scan_pending` · `scan_running` · `scan_blocked` · `awaiting_review` ·
`changes_requested` · `approved_pending_url` · `scaffold_ready` · `approved` · `active` · `rejected`.

**Legal transitions** (source of truth: `submission.py`):
```
draft ─submit(repo)──────────→ scan_pending ─scan──→ scan_running ─┬─pass─→ awaiting_review
draft ─submit(no-code)───────→ awaiting_review                     └─block→ scan_blocked
scan_blocked ─(reject|request-changes)→ rejected | changes_requested
awaiting_review ─approve(repo)───→ approved_pending_url
awaiting_review ─approve(no-code)→ scaffold_ready       (terminal — submitter builds + resubmits)
awaiting_review ─reject──────────→ rejected             (terminal)
awaiting_review ─request-changes─→ changes_requested ─(update_draft)→ draft/awaiting_review
approved_pending_url ─provide-url→ active               (synchronous quarantined discovery, INV-005)
```
**Guard-rails:** approve requires `awaiting_review` AND `scan_status IN (passed, not_applicable)`
(`submission.py:430-435`); reject/request-changes are state-guarded (`:475`); provide-url requires
`approved_pending_url` (`:565`). **MUST** implement any new transition as a guarded UPDATE (never a
blind status write) so the CHECK + the code guard both hold. Approval atomicity: the tool_registry
insert during discovery is best-effort and does **not** roll back the status flip (`:622`) — the
discover-tools admin route is the retry path.

## 2. Reviewer authority model (gap #3)

- **Approve / reject / request-changes:** `_require_submission_reviewer` = any of
  `{admin, platform_admin, security_reviewer}` (`submission.py:96`).
- **Segregation of duties:** `_require_not_self_review` — the reviewer **MUST NOT** be the submission's
  `owner_sub`, even if they hold `admin` (`:100`, enforced on approve/reject/request-changes).
- **Read-only** roles (`auditor`) see the review queue but get **no** mutate rights.
- `security_reviewer` is the *narrow* role: submission review only, nothing else in the admin surface
  (ARCHITECTURE §6.5).

## 3. Quarantine-release operationalization (gap #4)

Discovery registers tools **quarantined** (INV-005) — non-invocable until released. **Today the release
is a manual admin action** and there is **no dedicated release endpoint or SLA** — this is the gap.
**Spec:**
- **Who:** `platform_admin` (or `admin`) — NOT `security_reviewer` (submission review ≠ runtime tool
  release; keep them separate).
- **How (to build):** `POST /api/v1/admin/tools/{tool_id}/release` flipping `tool_registry.status`
  `quarantined → active`, audited via the HMAC chain, blocked if the tool's server is not `approved`.
- **SLA:** none enforced; a released-nothing tool stays non-invocable indefinitely (fail-safe). The
  admin UI **MUST** surface quarantined tools so they don't rot silently.
- **Until built:** release is via a direct `tool_registry.status` update by an admin (documented here so
  it's not invisible).

## 4. Submission-endpoint acceptance criteria (gap #1)

`POST /api/v1/submissions` + `PATCH`/`submit`. **MUST** specify + test:
- `name`: 2–63 chars, `^[a-z0-9][a-z0-9-]*$` (already enforced, `DraftCreate`); 400 on violation.
- `github_repo_url`: structural https guard only at submit (PRD-0005 R-2); provider/SSRF gate is the
  async scanner; 400 on embedded creds / non-https / whitespace.
- `injection_mode`: must be in `_VALID_MODES`; 400 otherwise. **`service_name` is NOT submitter-settable**
  (CRITICAL-1 fix) — reject/ignore any client attempt to set it.
- Owner scoping: a submitter may read/patch only their **own** drafts (`owner_sub` match); 404 (not 403)
  on another's submission (no existence leak).
- Field-level 400s with a machine-readable `detail`; never a 500 for user-input validation.

## 5. Server update / resubmit semantics (gap #5)

Self-service assumes updates but never defined them. **Spec:**
- **`changes_requested` → edit:** `update_draft` re-opens the submission for edits (same `server_id`),
  then re-submit → re-scan. Same identity, new scan. **Preferred** for iterating on a rejected/changed
  submission.
- **A new version of an *active* server:** **MUST** be a **new submission** (new `server_id`) — do not
  mutate an approved+running server's registry row in place. The old server's tools are **not**
  auto-orphaned; an admin quarantines/retires them explicitly when the new version is approved.
- **Name reuse:** `server_registry.name` is UNIQUE — a resubmit under the same name while the old row
  exists (non-deleted) is rejected; the old must be retired (soft-deleted) first. Document this so a
  submitter isn't surprised.

## Implementation status
- Done now: `V060` submission_status CHECK (guard-rail); this spec (documentation).
- Roadmap (build items surfaced here): the `POST .../tools/{id}/release` endpoint + quarantined-tool UI
  surfacing; formal AC test suite for the submission endpoints.
