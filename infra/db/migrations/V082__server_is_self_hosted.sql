-- V082__server_is_self_hosted.sql
-- PRD-0012 (url-first onboarding, re-approval on change, debug-mode-first) —
-- Phase 1 backend state machine.
--
-- Discriminator (architect §3): server_registry.is_self_hosted replaces the
-- fragile github_repo_url/deployment_status heuristics C2/C3 would otherwise
-- have to infer from. Backfilled TRUE where deployment_status IS NULL (no
-- platform-managed build/deploy was ever requested for the row) else FALSE.
-- New rows default TRUE — self-hosted is the default assumption until
-- POST /submissions/{id}/apply explicitly opts a submission into the
-- platform-managed pipeline (apply_submission sets it FALSE at that point).
--
-- Also lands the last-known-good snapshot columns request-change (C3) writes
-- immediately before demoting a live server, and reject_submission's rollback
-- path (product HIGH-3) reads back if a change-triggered re-review is
-- rejected. All nullable/additive — a server that has never been through
-- request-change has NULL last_good_* forever, which is exactly how
-- reject_submission distinguishes "first-time reject" (terminal) from
-- "routine-update reject" (rollback to last-good).
ALTER TABLE server_registry
    ADD COLUMN IF NOT EXISTS is_self_hosted BOOLEAN NOT NULL DEFAULT TRUE,
    ADD COLUMN IF NOT EXISTS last_good_upstream_url TEXT,
    ADD COLUMN IF NOT EXISTS last_good_scan_commit TEXT,
    ADD COLUMN IF NOT EXISTS last_good_tool_schema JSONB,
    ADD COLUMN IF NOT EXISTS last_good_recorded_at TIMESTAMPTZ;

UPDATE server_registry
SET is_self_hosted = (deployment_status IS NULL)
WHERE is_self_hosted IS DISTINCT FROM (deployment_status IS NULL);

COMMENT ON COLUMN server_registry.is_self_hosted IS
    'PRD-0012 §Discriminator: explicit self-hosted vs platform-deployed flag, '
    'set at registration/apply time. C2/C3 branch on this directly rather than '
    'inferring from github_repo_url/deployment_status. Platform-deployed '
    '(apply_submission) sets this FALSE; everything else defaults TRUE.';
COMMENT ON COLUMN server_registry.last_good_upstream_url IS
    'PRD-0012 C3/reject-rollback: snapshot of upstream_url taken at '
    'request-change time, immediately before demoting a live server. NULL '
    'until the first request-change on this server.';
COMMENT ON COLUMN server_registry.last_good_scan_commit IS
    'PRD-0012 C3: snapshot of scan_commit taken at request-change time — the '
    'classifier''s "same stored commit" baseline for the IP-only-vs-code-change '
    'split.';
COMMENT ON COLUMN server_registry.last_good_tool_schema IS
    'PRD-0012 C3: snapshot of the last-approved tool set as a JSONB array of '
    '{"name","schema"} objects, sorted by name, taken at request-change time. '
    'The IP-only classifier compares a fresh live tools/list fetch against '
    'this for byte-identical equality; reject-rollback restores tool_registry '
    'rows whose name appears here back to status=''active''.';

-- scan_jobs: new guarded re-review job type (TRAP-6) — request-change's
-- code-change path must NOT reuse the unguarded _evaluate_submission_scan,
-- so it gets its own job_type the evaluator dispatches on separately.
ALTER TABLE scan_jobs
    DROP CONSTRAINT IF EXISTS scan_jobs_job_type_check;
ALTER TABLE scan_jobs
    ADD CONSTRAINT scan_jobs_job_type_check
    CHECK (job_type IN (
        'submission_scan', 'rescan',
        'build_requested', 'deploy_requested', 'verify_requested',
        'change_rereview_scan'
    ));
