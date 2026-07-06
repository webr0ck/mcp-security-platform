-- =============================================================================
-- V068__deploy_verify_schema.sql
-- MCP Security Platform — CR-01 / CR-06 / CR-07 (WP-B3) apply/deploy/verify
-- loop, Phase 1: schema + state machine.
-- PostgreSQL 16
-- =============================================================================
-- This migration lands ONLY the schema/state-machine substrate for the
-- platform-managed build->deploy->verify pipeline (PRD-8). The build worker
-- (unprivileged rootless buildah/kaniko), the privileged launcher, and the
-- deploy/verify routers are a separate, larger follow-up — see
-- docs/superpowers/plans/2026-07-06-platform-finalisation.md WP-B3 and
-- Codex_review/Claude_status.md CR-01 row for what's built vs deferred.
--
-- Reuses WP-B1's scan_jobs queue (no new broker/queue dependency) rather than
-- standing up a second job table — 'build_requested'/'deploy_requested'/
-- 'verify_requested' are just three more job_type values a future
-- build-worker/launcher will claim the same way scanner-worker claims
-- 'submission_scan'/'rescan' today (SELECT ... FOR UPDATE SKIP LOCKED).
-- =============================================================================

-- ---------------------------------------------------------------------------
-- server_registry: platform-managed deployment state machine + provenance.
-- All nullable/additive — a self-hosted submission (provide-url path) never
-- touches these columns and stays NULL throughout, exactly like
-- oauth_policy_id/high_risk_scopes_approved_by before it.
-- ---------------------------------------------------------------------------
ALTER TABLE server_registry
    ADD COLUMN IF NOT EXISTS deployment_status      TEXT,
    ADD COLUMN IF NOT EXISTS build_artifact_digest   TEXT,
    ADD COLUMN IF NOT EXISTS runtime_url             TEXT,
    ADD COLUMN IF NOT EXISTS verification_report     JSONB,
    ADD COLUMN IF NOT EXISTS build_provenance        JSONB;

-- State machine (PRD-8 phase 1): build_requested -> building -> built ->
-- deploy_requested -> deploying -> deployed -> verify_requested ->
-- verifying -> verified -> failed (any stage can fail-closed to 'failed';
-- there is no automatic retry-forward, a fresh /apply starts a new attempt).
-- NULL = platform-managed build/deploy was never requested for this server
-- (the self-hosted provide-url path, or a submission not yet applied).
ALTER TABLE server_registry
    DROP CONSTRAINT IF EXISTS ck_deployment_status_valid;
ALTER TABLE server_registry
    ADD CONSTRAINT ck_deployment_status_valid
    CHECK (deployment_status IS NULL OR deployment_status IN (
        'build_requested', 'building', 'built',
        'deploy_requested', 'deploying', 'deployed',
        'verify_requested', 'verifying', 'verified',
        'failed'
    ));

-- build_artifact_digest is the TOCTOU pin (PRD-8 §2): the build worker MUST
-- consume this exact scanned+approved commit/content digest, never a
-- re-clone of branch HEAD — a digest mismatch at build time is a refused
-- build, not a warning. Format is scanner/build-tool dependent (git commit
-- sha256 today, an OCI image digest once a built image exists) so this is
-- deliberately TEXT, not a fixed-length column.
COMMENT ON COLUMN server_registry.deployment_status IS
    'CR-01 (WP-B3) platform-managed build/deploy/verify state machine. NULL = '
    'self-hosted (provide-url) path or not yet applied. See ck_deployment_status_valid.';
COMMENT ON COLUMN server_registry.build_artifact_digest IS
    'CR-01 (WP-B3): content-addressed pin of what was actually scanned+approved '
    '(git commit sha, later an OCI image digest) — the build worker must refuse '
    'to build anything else (TOCTOU guard, PRD-8 §2).';
COMMENT ON COLUMN server_registry.runtime_url IS
    'CR-01 (WP-B3): the platform-launched instance URL, set once deploy '
    'succeeds. Distinct from upstream_url (which self-hosted submitters set '
    'directly via provide-url) — kept separate so a platform-managed '
    'deployment''s address is never conflated with a submitter-supplied one '
    'until verify explicitly promotes it.';
COMMENT ON COLUMN server_registry.verification_report IS
    'CR-01/CR-06 (WP-B3): structured result of the post-deploy verify phase '
    '(healthcheck, discovery, invocation probe, CR-06 contract-subset check). '
    'Never implies release — quarantined tools still require the separate '
    'evidence-gated /release step (CR-07).';
COMMENT ON COLUMN server_registry.build_provenance IS
    'CR-01 (WP-B3): {commit, scan_ids, image_digest, builder_version, built_at, ...} '
    '— provenance record for the platform-built artifact, analogous to the scan '
    'engine''s provenance fields.';

-- ---------------------------------------------------------------------------
-- scan_jobs: extend job_type for the build/deploy/verify pipeline. Reuses the
-- existing queue/claim/retry/dead-letter machinery (V063) rather than a new
-- table — a future build-worker/launcher claims these exactly like
-- scanner-worker claims 'submission_scan'/'rescan' today.
-- ---------------------------------------------------------------------------
ALTER TABLE scan_jobs
    DROP CONSTRAINT IF EXISTS scan_jobs_job_type_check;
ALTER TABLE scan_jobs
    ADD CONSTRAINT scan_jobs_job_type_check
    CHECK (job_type IN (
        'submission_scan', 'rescan',
        'build_requested', 'deploy_requested', 'verify_requested'
    ));

-- ---------------------------------------------------------------------------
-- tool_registry: CR-07 remainder — released_by/released_at/release_notes.
-- Mirrors server_registry_approval_consistency's paired-nullability pattern:
-- a tool is either fully attributed (all three set) or none are (never a
-- release timestamp with no attributed reviewer, or vice versa).
-- ---------------------------------------------------------------------------
ALTER TABLE tool_registry
    ADD COLUMN IF NOT EXISTS released_by    TEXT,
    ADD COLUMN IF NOT EXISTS released_at    TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS release_notes  TEXT;

ALTER TABLE tool_registry
    DROP CONSTRAINT IF EXISTS ck_tool_registry_release_consistency;
ALTER TABLE tool_registry
    ADD CONSTRAINT ck_tool_registry_release_consistency
    CHECK (
        (released_by IS NULL AND released_at IS NULL)
        OR (released_by IS NOT NULL AND released_at IS NOT NULL)
    );

COMMENT ON COLUMN tool_registry.released_by IS
    'CR-07 (WP-B3 remainder): typed identity of the reviewer who cleared this '
    'tool''s quarantine via POST /api/v1/admin/tools/{id}/release (never set by '
    'a generic PATCH status change). NULL until a dedicated, evidence-gated '
    'release has occurred.';
COMMENT ON COLUMN tool_registry.released_at IS
    'CR-07 (WP-B3 remainder): timestamp of the dedicated release action above.';
COMMENT ON COLUMN tool_registry.release_notes IS
    'CR-07 (WP-B3 remainder): reviewer-supplied rationale recorded at release time.';

-- No new GRANTs needed — these are additive columns on tables proxy_app
-- already owns in full (server_registry, tool_registry, scan_jobs); V003's
-- blanket per-table GRANTs already cover them. scanner_worker_app's
-- column-scoped UPDATE grant on scan_jobs (V063) does NOT include job_type,
-- so it still cannot alter/forge a build/deploy/verify job's identity —
-- unaffected by this migration.
