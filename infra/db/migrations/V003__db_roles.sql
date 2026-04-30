-- =============================================================================
-- V003__db_roles.sql
-- MCP Security Platform — PostgreSQL Role Grants
-- Implements INV-011: only designated services write to designated tables.
-- =============================================================================
-- Roles created here:
--   proxy_app              — MCP Security Proxy (FastAPI) service account
--   compliance_checker_app — Compliance Checker (daily cron) service account
--
-- Passwords are NOT set in this migration (INV-008: no secrets in files).
-- Passwords are applied at container start by infra/scripts/init-db-roles.sh
-- using ALTER ROLE with values from environment variables.
--
-- This migration is idempotent: DO $$ blocks guard CREATE ROLE against
-- duplicate errors; GRANT is always idempotent in PostgreSQL.
-- =============================================================================

-- ---------------------------------------------------------------------------
-- Create application roles (idempotent)
-- ---------------------------------------------------------------------------
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT FROM pg_catalog.pg_roles WHERE rolname = 'proxy_app'
    ) THEN
        -- LOGIN required; password set at startup via init-db-roles.sh
        CREATE ROLE proxy_app LOGIN PASSWORD 'PLACEHOLDER_REPLACED_AT_RUNTIME';
    END IF;

    IF NOT EXISTS (
        SELECT FROM pg_catalog.pg_roles WHERE rolname = 'compliance_checker_app'
    ) THEN
        CREATE ROLE compliance_checker_app LOGIN PASSWORD 'PLACEHOLDER_REPLACED_AT_RUNTIME';
    END IF;
END
$$;

-- ---------------------------------------------------------------------------
-- GRANTS: proxy_app
-- ---------------------------------------------------------------------------
-- proxy_app is the single writer for all operational tables (INV-011).
-- It has SELECT on everything, INSERT/UPDATE on owned tables, and
-- INSERT-only on compliance_reports (to create in_progress rows?).
-- CLARIFICATION: per ARCHITECTURE.md §4.6 and INV-011, only compliance-checker
-- writes compliance_reports. proxy_app gets SELECT-only on compliance_reports.
-- ---------------------------------------------------------------------------

GRANT CONNECT ON DATABASE mcp_security TO proxy_app;
GRANT USAGE ON SCHEMA public TO proxy_app;

-- Read access: proxy needs to read every table for auth, policy, and health checks
GRANT SELECT ON
    tool_registry,
    sbom_records,
    audit_events,
    audit_events_archive,
    anomaly_baselines,
    anomaly_alerts,
    api_keys,
    tool_audit_results,
    oidc_role_mappings,
    audit_jobs,
    compliance_reports
TO proxy_app;

-- Write access: tables owned by proxy (INV-011)
GRANT INSERT, UPDATE ON
    tool_registry,
    sbom_records,
    anomaly_baselines,
    anomaly_alerts,
    api_keys,
    tool_audit_results,
    oidc_role_mappings,
    audit_jobs
TO proxy_app;

-- audit_events: INSERT only — never UPDATE or DELETE (append-only, INV-001)
GRANT INSERT ON audit_events TO proxy_app;

-- audit_events_archive: proxy_app has no write access — archive is written
-- by the archive function (runs as the migration owner / superuser).
-- proxy_app may query the archive for historical lookups.
-- (SELECT already granted above via the full list)

-- Explicit REVOKE: belt-and-suspenders to ensure no UPDATE/DELETE on audit tables
REVOKE UPDATE, DELETE ON audit_events FROM proxy_app;
REVOKE ALL ON audit_events_archive FROM proxy_app;
GRANT SELECT ON audit_events_archive TO proxy_app;

-- compliance_reports: proxy_app has SELECT only
REVOKE INSERT, UPDATE, DELETE ON compliance_reports FROM proxy_app;
GRANT SELECT ON compliance_reports TO proxy_app;

-- No DELETE on any table (soft-delete via deleted_at UPDATE is sufficient)
REVOKE DELETE ON ALL TABLES IN SCHEMA public FROM proxy_app;

-- Sequences (needed for UUID generation via gen_random_uuid() — actually not
-- sequence-based in PG16, but needed for any SERIAL or BIGSERIAL columns)
GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO proxy_app;


-- ---------------------------------------------------------------------------
-- GRANTS: compliance_checker_app
-- ---------------------------------------------------------------------------
-- compliance_checker_app is the single writer for compliance_reports (INV-011).
-- It reads audit_events and tool_registry for sampling + name resolution.
-- It has NO write access to any other table.
-- ---------------------------------------------------------------------------

GRANT CONNECT ON DATABASE mcp_security TO compliance_checker_app;
GRANT USAGE ON SCHEMA public TO compliance_checker_app;

-- Read access: audit events (sampling) + tool registry (name resolution)
-- + archive (historical compliance windows that span the 90-day archive boundary)
GRANT SELECT ON
    audit_events,
    audit_events_archive,
    tool_registry
TO compliance_checker_app;

-- Write access: compliance_reports only
-- INSERT to create new report rows; UPDATE to transition in_progress → pass/fail
GRANT INSERT, UPDATE ON compliance_reports TO compliance_checker_app;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO compliance_checker_app;

-- Explicit revoke of everything else — belt-and-suspenders
REVOKE ALL ON
    sbom_records,
    anomaly_baselines,
    anomaly_alerts,
    api_keys,
    tool_audit_results,
    oidc_role_mappings,
    audit_jobs
FROM compliance_checker_app;

-- No DELETE, ever
REVOKE DELETE ON ALL TABLES IN SCHEMA public FROM compliance_checker_app;


-- ---------------------------------------------------------------------------
-- Append-only enforcement: audit_events and audit_events_archive
-- ---------------------------------------------------------------------------
-- PostgreSQL does not have a native "INSERT-only" table modifier, so we enforce
-- append-only semantics through two complementary mechanisms:
--
-- 1. ROLE GRANTS (above): no UPDATE or DELETE is granted to any application role
--    on audit_events or audit_events_archive.
--
-- 2. TRIGGER GUARD: the trigger below raises an exception if any role (including
--    future roles that may accidentally receive broader grants) attempts an UPDATE
--    or DELETE on audit_events. This is a defence-in-depth layer.
--    The trigger runs as SECURITY DEFINER is not needed here — the trigger fires
--    regardless of the executing role because it is an AFTER trigger on the table.
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION fn_audit_events_immutability_guard()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION
        'audit_events is append-only. UPDATE and DELETE are prohibited. '
        'TG_OP=%, table=%, event_id=%',
        TG_OP, TG_TABLE_NAME, OLD.event_id
        USING ERRCODE = 'insufficient_privilege';
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

-- Guard on live audit_events
DROP TRIGGER IF EXISTS trg_audit_events_immutability ON audit_events;
CREATE TRIGGER trg_audit_events_immutability
    BEFORE UPDATE OR DELETE ON audit_events
    FOR EACH ROW EXECUTE FUNCTION fn_audit_events_immutability_guard();

-- Guard on archive table (same semantics: once archived, never modified)
CREATE OR REPLACE FUNCTION fn_audit_archive_immutability_guard()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION
        'audit_events_archive is append-only. UPDATE and DELETE are prohibited. '
        'TG_OP=%, event_id=%',
        TG_OP, OLD.event_id
        USING ERRCODE = 'insufficient_privilege';
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_audit_events_archive_immutability ON audit_events_archive;
CREATE TRIGGER trg_audit_events_archive_immutability
    BEFORE UPDATE OR DELETE ON audit_events_archive
    FOR EACH ROW EXECUTE FUNCTION fn_audit_archive_immutability_guard();
