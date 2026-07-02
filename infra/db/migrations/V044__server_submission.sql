-- V044: guided self-service MCP server submission flow
--
-- Adds submission workflow columns to server_registry.
-- submission_status tracks the onboarding pipeline state (draft → scan → review → active).
-- Operational status column is unchanged — it only flips to 'approved' after URL discovery.

ALTER TABLE server_registry
    ADD COLUMN IF NOT EXISTS github_repo_url       text,
    ADD COLUMN IF NOT EXISTS submission_status     text NOT NULL DEFAULT 'draft',
    ADD COLUMN IF NOT EXISTS scan_status           text NOT NULL DEFAULT 'pending',
    ADD COLUMN IF NOT EXISTS scan_report           jsonb NOT NULL DEFAULT '[]',
    ADD COLUMN IF NOT EXISTS data_categories       text[] NOT NULL DEFAULT '{}',
    ADD COLUMN IF NOT EXISTS has_write_ops         boolean NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS mode_override_reason  text,
    ADD COLUMN IF NOT EXISTS review_notes          text,
    ADD COLUMN IF NOT EXISTS reviewed_by           text,
    ADD COLUMN IF NOT EXISTS reviewed_at           timestamp with time zone;

-- submission_status values:
--   draft              → wizard in progress, not yet submitted
--   scan_pending       → submitted, clone + scan queued
--   scan_running       → scan in progress
--   scan_blocked       → automatic scan found issues; returned to submitter
--   awaiting_review    → scan passed; in security team queue
--   changes_requested  → reviewer requested changes; returned to submitter
--   rejected           → permanently rejected by security team
--   approved_pending_url → approved; waiting for submitter to provide running URL
--   (then operational status → approved once discover-tools completes)

CREATE INDEX IF NOT EXISTS idx_server_registry_submission_status
    ON server_registry (submission_status)
    WHERE deleted_at IS NULL;
