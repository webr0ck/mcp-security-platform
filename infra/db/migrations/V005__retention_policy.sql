-- =============================================================================
-- V005__retention_policy.sql
-- MCP Security Platform — Audit Log Retention and Archival Policy
-- =============================================================================
-- This migration implements the retention policy for audit_events:
--
--   Active window:  90 days  (rows in audit_events)
--   Archive window: indefinite (rows in audit_events_archive, append-only)
--
-- The archive table was created in V001 to ensure it exists before any
-- archival runs. This migration adds the archival function and the pg_cron
-- schedule (if pg_cron is available).
--
-- WORM guarantee:
--   The trigger installed in V003 prevents UPDATE/DELETE on audit_events_archive.
--   No application role has UPDATE or DELETE on audit_events_archive.
--   Physical deletion of archive rows requires a DBA using the superuser role
--   and disabling the trigger — an out-of-band operation that is audited at
--   the OS / Postgres log level.
--
-- Retention periods for all tables (documented here as the authoritative source):
--   audit_events             90 days active, then archived indefinitely
--   audit_events_archive     permanent (compliance-critical)
--   compliance_reports       7 years (regulatory minimum)
--   tool_registry            indefinite (soft-delete; DBA-only physical removal)
--   sbom_records             follows tool_registry (cascade on physical delete)
--   tool_audit_results       follows tool_registry (cascade on physical delete)
--   anomaly_alerts           1 year from detected_at (application-level soft-purge)
--   anomaly_baselines        1 year after client last seen (application-level TTL)
--   api_keys                 2 years after revocation (audit hold)
--   audit_jobs               90 days (operational data; pruned by scheduler)
-- =============================================================================

-- ---------------------------------------------------------------------------
-- Function: archive_old_audit_events()
-- ---------------------------------------------------------------------------
-- Moves audit_events rows older than p_retention_days (default 90) to
-- audit_events_archive in batches, then deletes the originals from
-- audit_events. Returns the count of rows archived.
--
-- Batching (default 10,000 rows per call) prevents lock contention on a
-- high-write table. The function is designed to be called repeatedly by
-- pg_cron until no more rows qualify.
--
-- Safety: the function runs inside a single transaction. If the INSERT into
-- archive fails for any reason, the DELETE is rolled back — no data loss.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION archive_old_audit_events(
    p_retention_days INTEGER DEFAULT 90,
    p_batch_size     INTEGER DEFAULT 10000
)
RETURNS INTEGER
LANGUAGE plpgsql
AS $$
DECLARE
    v_cutoff     TIMESTAMPTZ;
    v_archived   INTEGER;
BEGIN
    v_cutoff := NOW() - (p_retention_days || ' days')::INTERVAL;

    -- Step 1: Insert qualifying rows into archive (INSERT ... SELECT with CTE
    -- to capture the exact set being moved atomically).
    WITH rows_to_archive AS (
        SELECT
            event_id,
            event_ts,
            client_id,
            tool_name,
            tool_id,
            outcome,
            latency_ms,
            bytes_in,
            bytes_out,
            sha256_hash,
            anomaly_score,
            opa_reasons,
            request_id,
            source_ip,
            created_at
        FROM audit_events
        WHERE event_ts < v_cutoff
        -- ORDER BY event_ts ASC ensures we archive oldest first.
        -- LIMIT keeps the batch bounded.
        ORDER BY event_ts ASC
        LIMIT p_batch_size
        -- FOR UPDATE SKIP LOCKED avoids blocking concurrent proxy_app inserts
        -- that are touching the same partition boundary rows.
        FOR UPDATE SKIP LOCKED
    ),
    inserted AS (
        INSERT INTO audit_events_archive (
            event_id,
            event_ts,
            client_id,
            tool_name,
            tool_id,
            outcome,
            latency_ms,
            bytes_in,
            bytes_out,
            sha256_hash,
            anomaly_score,
            opa_reasons,
            request_id,
            source_ip,
            created_at,
            archived_at
        )
        SELECT
            event_id,
            event_ts,
            client_id,
            tool_name,
            tool_id,
            outcome,
            latency_ms,
            bytes_in,
            bytes_out,
            sha256_hash,
            anomaly_score,
            opa_reasons,
            request_id,
            source_ip,
            created_at,
            NOW()   -- archived_at set at archive time
        FROM rows_to_archive
        ON CONFLICT (event_id) DO NOTHING  -- idempotent: skip already-archived rows
        RETURNING event_id
    )
    -- Step 2: Delete from audit_events only the rows that were successfully inserted.
    DELETE FROM audit_events
    WHERE event_id IN (SELECT event_id FROM inserted);

    -- Capture how many rows were archived in this batch
    GET DIAGNOSTICS v_archived = ROW_COUNT;

    RAISE NOTICE 'archive_old_audit_events: archived % rows (cutoff: %, batch_size: %)',
        v_archived, v_cutoff, p_batch_size;

    RETURN v_archived;
END;
$$;

-- Revoke EXECUTE from application roles — only the DB superuser (migration owner)
-- or a dedicated maintenance role should call this function.
REVOKE EXECUTE ON FUNCTION archive_old_audit_events(INTEGER, INTEGER)
    FROM proxy_app, compliance_checker_app;


-- ---------------------------------------------------------------------------
-- Function: purge_old_audit_jobs()
-- ---------------------------------------------------------------------------
-- Removes completed/failed audit_jobs older than 90 days.
-- audit_jobs is operational data with no compliance retention requirement.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION purge_old_audit_jobs(
    p_retention_days INTEGER DEFAULT 90
)
RETURNS INTEGER
LANGUAGE plpgsql
AS $$
DECLARE
    v_deleted INTEGER;
BEGIN
    DELETE FROM audit_jobs
    WHERE status IN ('completed', 'failed')
      AND created_at < NOW() - (p_retention_days || ' days')::INTERVAL;

    GET DIAGNOSTICS v_deleted = ROW_COUNT;

    RAISE NOTICE 'purge_old_audit_jobs: deleted % rows', v_deleted;
    RETURN v_deleted;
END;
$$;

REVOKE EXECUTE ON FUNCTION purge_old_audit_jobs(INTEGER)
    FROM proxy_app, compliance_checker_app;


-- ---------------------------------------------------------------------------
-- pg_cron schedule (PostgreSQL 16 + pg_cron extension)
-- ---------------------------------------------------------------------------
-- If pg_cron is available, schedule the archival function to run daily at
-- 01:00 UTC (one hour before the compliance checker's 02:00 UTC run, ensuring
-- the archive is up to date before compliance sampling begins).
--
-- To install pg_cron:
--   shared_preload_libraries = 'pg_cron'
--   cron.database_name = 'mcp_security'
--
-- If pg_cron is NOT available, run this manually via OS cron:
--   0 1 * * * psql -U mcp_app -d mcp_security -c "SELECT archive_old_audit_events();"
--   5 1 * * * psql -U mcp_app -d mcp_security -c "SELECT purge_old_audit_jobs();"
-- ---------------------------------------------------------------------------
-- NOTE: outer block is tagged $do$ (not $$) because the cron.schedule() command
-- strings below are themselves dollar-quoted with $$. A plain `DO $$ ... $$`
-- outer block would be terminated early by the first inner $$, producing
-- "syntax error at or near SELECT" and ABORTING the entire fresh-DB init (so
-- V006+ never run). Distinct tags keep the nesting unambiguous.
DO $do$
BEGIN
    -- Check if pg_cron is installed before attempting to schedule
    IF EXISTS (
        SELECT FROM pg_catalog.pg_extension WHERE extname = 'pg_cron'
    ) THEN
        -- Remove existing schedules first to make this migration idempotent
        PERFORM cron.unschedule('mcp-audit-archive')
            WHERE EXISTS (
                SELECT FROM cron.job WHERE jobname = 'mcp-audit-archive'
            );

        PERFORM cron.unschedule('mcp-audit-jobs-purge')
            WHERE EXISTS (
                SELECT FROM cron.job WHERE jobname = 'mcp-audit-jobs-purge'
            );

        -- Schedule archival: daily at 01:00 UTC
        PERFORM cron.schedule(
            'mcp-audit-archive',
            '0 1 * * *',
            $$SELECT archive_old_audit_events(90, 10000);$$
        );

        -- Schedule audit_jobs purge: daily at 01:05 UTC
        PERFORM cron.schedule(
            'mcp-audit-jobs-purge',
            '5 1 * * *',
            $$SELECT purge_old_audit_jobs(90);$$
        );

        RAISE NOTICE 'V005: pg_cron schedules registered: mcp-audit-archive, mcp-audit-jobs-purge';
    ELSE
        RAISE NOTICE
            'V005: pg_cron not available. Schedule archival manually: '
            '0 1 * * * psql -U mcp_app -d mcp_security -c "SELECT archive_old_audit_events();" '
            '5 1 * * * psql -U mcp_app -d mcp_security -c "SELECT purge_old_audit_jobs();"';
    END IF;
END
$do$;


-- ---------------------------------------------------------------------------
-- Rollback notes (down migration)
-- ---------------------------------------------------------------------------
-- To reverse V005 (if Flyway undo is used):
--
--   DROP FUNCTION IF EXISTS archive_old_audit_events(INTEGER, INTEGER);
--   DROP FUNCTION IF EXISTS purge_old_audit_jobs(INTEGER);
--   -- If pg_cron was used:
--   SELECT cron.unschedule('mcp-audit-archive');
--   SELECT cron.unschedule('mcp-audit-jobs-purge');
--
-- NOTE: The audit_events_archive table is NOT dropped on rollback because it
-- may contain archived data. Dropping it would be a destructive operation
-- requiring explicit DBA approval. The archive table was created in V001 and
-- would only be dropped if V001 itself is reversed (which requires the same
-- DBA approval process).
