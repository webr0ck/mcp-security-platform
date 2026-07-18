-- =============================================================================
-- lab/seeder/sql/mark_seeded_servers_scanned.sql
-- PRD-0011: on a fresh lab boot, seeded servers have last_rescanned_at=NULL, so
-- invocation.py's supply-chain scan-freshness gate (SCAN_MAX_AGE_HOURS) fail-
-- closes EVERY tool call with "server supply-chain scan is stale". Nothing on a
-- fresh boot enqueues scan_jobs for the seeded fixtures, so without this the lab
-- is unusable until each server is manually rescanned.
--
-- Seeded lab servers are trusted fixtures defined in-repo, NOT real submissions,
-- so we mark every 'approved' server scan-passed with a fresh timestamp — the
-- same state the self-service seed already ships. This is a LAB fixture-trust
-- convention: real submissions still go through submit -> scan -> approve, and
-- this file is a lab seed (never an infra/db migration), so it cannot affect a
-- production deployment.
--
-- Runs after all server-creating seeds (servers.sql, dex_external_oauth.sql) so
-- every seeded 'approved' server is covered. Idempotent: the WHERE guard makes
-- re-runs no-ops once a server is already fresh-passed.
-- =============================================================================
UPDATE server_registry
SET scan_status       = 'passed',
    last_rescanned_at = now(),
    scan_report       = COALESCE(scan_report, '[]'::jsonb),
    updated_at        = now()
WHERE status = 'approved'
  AND (last_rescanned_at IS NULL OR scan_status IS DISTINCT FROM 'passed');
