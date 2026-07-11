-- V063__scanner_worker_queue.sql
-- CR-14 (WP-B1): isolated scanner worker + Postgres-backed job queue.
--
-- Problem this closes: untrusted git-clone + scanner execution (trufflehog,
-- pip-audit, mcp_checker/semgrep) used to run INSIDE the proxy container —
-- the same process holding DB-admin creds, Vault tokens, and the gateway
-- shared secret. Attacker-controlled repo content (malicious setup.py,
-- package.json prescript, etc.) executed with access to those secrets.
--
-- Fix: a new unprivileged `scanner-worker` service claims jobs from
-- scan_jobs, executes scanners, and writes RAW output ONLY to
-- scan_raw_results. A trusted evaluator living in the proxy (never touches
-- attacker-controlled content — it only reads structured JSON the worker
-- produced) reads scan_raw_results, applies policy, and writes the verdict
-- (server_registry.scan_status / block / submission_status transitions).
--
-- Execution/adjudication split enforced at the DB-role level, not just in
-- application logic (non-negotiable per PRD-6):
--   scanner_worker_app  — INSERT-only on scan_raw_results; UPDATE limited to
--                         its own claim/heartbeat/attempt columns on
--                         scan_jobs; SELECT on scan_jobs (to claim) and on
--                         git_providers (non-secret host/allowlist config
--                         needed for its own SSRF validation + clone URL
--                         construction — the token itself is NOT stored here,
--                         see git_providers.py comment; the worker receives a
--                         narrowly-scoped clone token via its OWN env var,
--                         never proxy's DB-admin/Vault/gateway secrets).
--   proxy_app           — owns scan_jobs.server_id/github_url/job_type/force
--                         (enqueue) and scan_raw_results.evaluated_at plus
--                         server_registry verdict columns (evaluator).
--
-- A corrupted/compromised worker can therefore at worst write a garbled
-- scan_raw_results row (which the evaluator maps to scan_status='error' —
-- fail closed); it structurally lacks the GRANT to write scan_status/block
-- itself, so it can never forge a PASS.

-- ---------------------------------------------------------------------------
-- Role: scanner_worker_app (idempotent create, per V003 pattern)
-- ---------------------------------------------------------------------------
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT FROM pg_catalog.pg_roles WHERE rolname = 'scanner_worker_app'
    ) THEN
        CREATE ROLE scanner_worker_app LOGIN PASSWORD 'PLACEHOLDER_REPLACED_AT_RUNTIME';
    END IF;
END
$$;

-- ---------------------------------------------------------------------------
-- scan_jobs — the queue. Lifecycle: queued -> running -> completed | failed
-- (retried back to queued until max_attempts) -> dead_letter.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS scan_jobs (
    job_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    server_id     UUID NOT NULL REFERENCES server_registry(server_id),
    github_url    TEXT NOT NULL,
    job_type      TEXT NOT NULL DEFAULT 'submission_scan'
                  CHECK (job_type IN ('submission_scan', 'rescan')),
    -- queue lifecycle state — NOT a policy/adjudication verdict. 'completed'
    -- means "the worker finished executing and wrote a raw result row", not
    -- "the scan passed". Only the evaluator (proxy_app) decides pass/fail,
    -- and it does so in server_registry.scan_status, a disjoint table.
    status        TEXT NOT NULL DEFAULT 'queued'
                  CHECK (status IN ('queued', 'running', 'completed', 'failed', 'dead_letter')),
    attempts      INT NOT NULL DEFAULT 0,
    max_attempts  INT NOT NULL DEFAULT 3,
    force         BOOLEAN NOT NULL DEFAULT false,
    claimed_by    TEXT,             -- worker instance identity (hostname/pid), for diagnostics
    claimed_at    TIMESTAMPTZ,
    heartbeat_at  TIMESTAMPTZ,
    last_error    TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ix_scan_jobs_status_created ON scan_jobs (status, created_at);
CREATE INDEX IF NOT EXISTS ix_scan_jobs_server_id ON scan_jobs (server_id);

-- Idempotency: at most one job "in flight" (queued/running) per
-- (server_id, github_url) unless force=true bypasses this at the app layer
-- by simply not being blocked by it (the partial unique index only covers
-- the default non-force path — force=true jobs are allowed to coexist so a
-- manual re-scan is never silently dropped).
CREATE UNIQUE INDEX IF NOT EXISTS ux_scan_jobs_inflight
    ON scan_jobs (server_id, github_url)
    WHERE status IN ('queued', 'running') AND force = false;

-- ---------------------------------------------------------------------------
-- scan_raw_results — RAW scanner output. Execution/adjudication split lives
-- here: this table has no `block`/`scan_status`/pass-fail column at all —
-- structurally, a worker cannot write a verdict because there is no column
-- to write one into.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS scan_raw_results (
    result_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    job_id            UUID NOT NULL REFERENCES scan_jobs(job_id),
    server_id         UUID NOT NULL,
    raw_findings      JSONB NOT NULL DEFAULT '[]'::jsonb,
    scan_commit       TEXT,
    sbom_components   JSONB,
    sbom_cyclonedx    JSONB,
    -- worker_error: set when the worker itself failed (clone error, crash,
    -- missing binary) as opposed to the scanners running and finding
    -- nothing. The evaluator maps ANY non-null worker_error to
    -- scan_status='error' or 'blocked' as appropriate — never 'passed'.
    worker_error      TEXT,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- evaluated_at: set by the evaluator (proxy_app) once it has applied
    -- policy and written the verdict to server_registry. NULL = pending
    -- evaluation. The worker never sets this column.
    evaluated_at      TIMESTAMPTZ,
    CONSTRAINT uq_scan_raw_results_job UNIQUE (job_id)
);

CREATE INDEX IF NOT EXISTS ix_scan_raw_results_pending
    ON scan_raw_results (created_at) WHERE evaluated_at IS NULL;

-- ---------------------------------------------------------------------------
-- GRANTS: scanner_worker_app — narrow, execution-only
-- ---------------------------------------------------------------------------
GRANT CONNECT ON DATABASE mcp_security TO scanner_worker_app;
GRANT USAGE ON SCHEMA public TO scanner_worker_app;

-- Claim/heartbeat: needs SELECT (to find queued work) and UPDATE limited to
-- its own process-state columns. It must NOT be able to alter server_id,
-- github_url, job_type, force, max_attempts, or created_at (job identity/
-- policy-relevant fields belong to proxy_app / the enqueuer).
GRANT SELECT ON scan_jobs TO scanner_worker_app;
GRANT UPDATE (status, attempts, claimed_by, claimed_at, heartbeat_at, last_error, updated_at)
    ON scan_jobs TO scanner_worker_app;
REVOKE INSERT, DELETE ON scan_jobs FROM scanner_worker_app;

-- Raw results: INSERT-only. No SELECT, no UPDATE, no DELETE — a compromised
-- worker cannot even read back or tamper with results it (or another job)
-- already wrote.
GRANT INSERT ON scan_raw_results TO scanner_worker_app;
REVOKE SELECT, UPDATE, DELETE ON scan_raw_results FROM scanner_worker_app;

-- git_providers: SELECT-only, non-secret config (host/allow_private/
-- clone_account/enabled). The token itself lives in platform_secrets, which
-- scanner_worker_app has NO grant on — it is proxy's secret store, not the
-- worker's. The worker's own clone token is injected via its own env var.
GRANT SELECT ON git_providers TO scanner_worker_app;

-- Explicit belt-and-suspenders: no access whatsoever to anything else,
-- especially the tables that hold actual secrets or admin authority.
REVOKE ALL ON
    platform_secrets,
    credential_store,
    server_registry,
    audit_events,
    audit_events_archive,
    api_keys,
    oidc_sessions
FROM scanner_worker_app;

GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO scanner_worker_app;
REVOKE DELETE ON ALL TABLES IN SCHEMA public FROM scanner_worker_app;

-- ---------------------------------------------------------------------------
-- GRANTS: proxy_app — enqueue + evaluate (verdict-writing side)
-- ---------------------------------------------------------------------------
GRANT SELECT, INSERT ON scan_jobs TO proxy_app;
-- proxy_app may cancel/requeue but never impersonate the worker's own
-- claim/heartbeat bookkeeping columns — restrict its UPDATE to the
-- job-identity/control columns it legitimately owns (e.g. re-enqueue via
-- `force`, or manual dead-letter acknowledgement outside this migration's
-- scope). Kept narrow on purpose; extend explicitly if a future need arises.
GRANT UPDATE (force, updated_at) ON scan_jobs TO proxy_app;

GRANT SELECT ON scan_raw_results TO proxy_app;
GRANT UPDATE (evaluated_at) ON scan_raw_results TO proxy_app;
REVOKE INSERT, DELETE ON scan_raw_results FROM proxy_app;
