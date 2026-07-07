-- V072__build_worker_queue.sql
-- CR-01 (WP-B3 phase 2a): isolated build worker + build_results table.
--
-- Mirrors V063's scanner_worker_app execution/adjudication split exactly:
-- an unprivileged build_worker_app claims build_requested/deploy_requested/
-- verify_requested jobs from the EXISTING scan_jobs queue (no new job
-- table — see V068) and writes RAW build output ONLY to a new
-- build_results table. A trusted evaluator living in the proxy
-- (build_evaluator.py, Task 3) reads build_results and drives
-- server_registry.deployment_status — the worker structurally lacks the
-- grant to write that column itself.
--
-- Also adds scan_jobs.expected_digest: the TOCTOU pin threaded through from
-- server_registry.scan_commit at build-job-enqueue time (PRD-8 §2) so the
-- build worker can refuse to build anything except the exact scanned+
-- approved commit.

-- ---------------------------------------------------------------------------
-- Role: build_worker_app (idempotent create, per V063 pattern)
-- ---------------------------------------------------------------------------
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT FROM pg_catalog.pg_roles WHERE rolname = 'build_worker_app'
    ) THEN
        CREATE ROLE build_worker_app LOGIN PASSWORD 'PLACEHOLDER_REPLACED_AT_RUNTIME';
    END IF;
END
$$;

-- ---------------------------------------------------------------------------
-- scan_jobs: add expected_digest (nullable, additive — existing
-- submission_scan/rescan jobs never set it).
-- ---------------------------------------------------------------------------
ALTER TABLE scan_jobs
    ADD COLUMN IF NOT EXISTS expected_digest TEXT;

COMMENT ON COLUMN scan_jobs.expected_digest IS
    'CR-01 (WP-B3): TOCTOU pin for build_requested jobs — the exact '
    'server_registry.scan_commit value recorded at scan-approval time. The '
    'build worker MUST refuse to build if a fresh clone''s HEAD does not '
    'match this exactly (PRD-8 sec 2). NULL for submission_scan/rescan jobs.';

-- ---------------------------------------------------------------------------
-- build_results — RAW build/deploy/verify worker output. Same shape
-- convention as scan_raw_results: no deployment_status/pass-fail column at
-- all, so a compromised worker cannot forge a verdict — there is no column
-- to write one into.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS build_results (
    result_id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    job_id                  UUID NOT NULL REFERENCES scan_jobs(job_id),
    server_id               UUID NOT NULL,
    job_type                TEXT NOT NULL
                             CHECK (job_type IN ('build_requested', 'deploy_requested', 'verify_requested')),
    build_artifact_digest   TEXT,
    image_ref               TEXT,
    sbom_cyclonedx          JSONB,
    provenance              JSONB,
    -- worker_error: set when the worker itself failed (digest mismatch,
    -- clone error, crash, missing buildah binary) — the evaluator maps ANY
    -- non-null worker_error to deployment_status='failed', never advancing.
    worker_error            TEXT,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- evaluated_at: set by build_evaluator.py once it has applied policy and
    -- written deployment_status to server_registry. NULL = pending.
    evaluated_at            TIMESTAMPTZ,
    CONSTRAINT uq_build_results_job UNIQUE (job_id)
);

CREATE INDEX IF NOT EXISTS ix_build_results_pending
    ON build_results (created_at) WHERE evaluated_at IS NULL;
CREATE INDEX IF NOT EXISTS ix_build_results_server_id ON build_results (server_id);

-- ---------------------------------------------------------------------------
-- GRANTS: build_worker_app — narrow, execution-only
-- ---------------------------------------------------------------------------
GRANT CONNECT ON DATABASE mcp_security TO build_worker_app;
GRANT USAGE ON SCHEMA public TO build_worker_app;

-- Claim/heartbeat over the SAME scan_jobs queue scanner_worker_app already
-- claims from — filtered at the application-query level (WHERE job_type IN
-- (...)), not by a separate table. Same column-scoped UPDATE grant pattern
-- as V063: this role can never alter job identity/policy-relevant fields
-- (server_id, github_url, job_type, expected_digest, max_attempts, force,
-- created_at).
GRANT SELECT ON scan_jobs TO build_worker_app;
GRANT UPDATE (status, attempts, claimed_by, claimed_at, heartbeat_at, last_error, updated_at)
    ON scan_jobs TO build_worker_app;
REVOKE INSERT, DELETE ON scan_jobs FROM build_worker_app;

-- Build results: INSERT-only. No SELECT, no UPDATE, no DELETE.
GRANT INSERT ON build_results TO build_worker_app;
REVOKE SELECT, UPDATE, DELETE ON build_results FROM build_worker_app;

-- git_providers: SELECT-only, non-secret config — same rationale as V063
-- (the build worker re-clones the same repo to verify the digest pin before
-- building; it needs the same host-allowlist/clone-account lookup).
GRANT SELECT ON git_providers TO build_worker_app;

-- Explicit belt-and-suspenders: zero access to secrets/admin/adjudication
-- tables. In particular, no grant whatsoever on server_registry — the build
-- worker must never be able to read or write deployment_status,
-- build_artifact_digest, runtime_url, verification_report, or
-- build_provenance directly; only the trusted evaluator (proxy_app) does.
REVOKE ALL ON
    platform_secrets,
    credential_store,
    server_registry,
    audit_events,
    audit_events_archive,
    api_keys,
    oidc_sessions,
    scan_raw_results
FROM build_worker_app;

GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO build_worker_app;
REVOKE DELETE ON ALL TABLES IN SCHEMA public FROM build_worker_app;

-- ---------------------------------------------------------------------------
-- GRANTS: proxy_app — evaluate (verdict-writing) side of build_results.
-- Enqueue-side (scan_jobs INSERT/UPDATE(force,updated_at)) is already
-- granted by V063; this migration only adds the new table.
-- ---------------------------------------------------------------------------
GRANT SELECT ON build_results TO proxy_app;
GRANT UPDATE (evaluated_at) ON build_results TO proxy_app;
REVOKE INSERT, DELETE ON build_results FROM proxy_app;

-- proxy_app also needs to set scan_jobs.expected_digest at build-job-enqueue
-- time (submission.py's /apply handler, Task 6) — additive to its existing
-- UPDATE(force, updated_at) grant from V063.
GRANT UPDATE (expected_digest) ON scan_jobs TO proxy_app;
