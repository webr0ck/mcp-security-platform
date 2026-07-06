-- =============================================================================
-- V030__audit_event_ts_iso.sql
-- MCP Security Platform — audit_events verbatim ISO 8601 timestamp column
-- PostgreSQL 16
-- =============================================================================
-- appsec finding 0.2-F1 (CRITICAL, blocking)
--
-- Problem:
--   The existing event_ts column is TIMESTAMPTZ.  When the compliance checker
--   SELECTs it via "event_ts::text AS timestamp", PostgreSQL renders the value
--   as "2026-06-11 00:10:36.123456+00" (space separator, shortened offset "+00")
--   rather than "2026-06-11T00:10:36.123456+00:00" (the ISO 8601 string that
--   Python's datetime.isoformat() produces).  This byte-level divergence causes
--   every post-V028 row to fail both SHA-256 and HMAC verification.
--
-- Fix:
--   Add event_ts_iso TEXT to store the verbatim Python isoformat() string at
--   write time.  The compliance checker SELECT reads event_ts_iso directly
--   (no cast needed) so the timestamp bytes are identical on both sides.
--
-- Legacy-row handling:
--   Rows written between V028 and V030 (the migration window) will have
--   event_ts_iso IS NULL but the other V028 canonical columns present.
--   The compliance checker's legacy detection is extended: a row is
--   "unverifiable_legacy" if ANY of the canonical columns needed for
--   recomputation is NULL (event_ts_iso is now required alongside
--   event_type, platform_version, and original_outcome).
--
-- INV-011: explicit GRANT/REVOKE per-role per table.
-- INV-001: every row written after this migration is fully verifiable.
-- =============================================================================

-- Add verbatim ISO 8601 timestamp column (nullable — pre-V030 rows are NULL)
ALTER TABLE audit_events
    ADD COLUMN IF NOT EXISTS event_ts_iso TEXT;

-- Partial index: fast lookup of rows with the new column populated (post-V030).
CREATE INDEX IF NOT EXISTS idx_audit_events_event_ts_iso
    ON audit_events (event_id)
    WHERE event_ts_iso IS NOT NULL;

-- =============================================================================
-- GRANTs (INV-011: explicit grants, never wildcard)
-- =============================================================================

-- proxy_app: INSERT + SELECT (append-only; no UPDATE/DELETE).
GRANT INSERT, SELECT ON audit_events TO proxy_app;
REVOKE UPDATE, DELETE ON audit_events FROM proxy_app;

-- compliance_checker: SELECT only (read audit events for verification runs).
GRANT SELECT ON audit_events TO compliance_checker_app;

-- audit_reader: SELECT only (conditional — role may not exist in all deployments).
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'audit_reader') THEN
        GRANT SELECT ON audit_events TO audit_reader;
    END IF;
END
$$;

-- =============================================================================
-- Column comment
-- =============================================================================
COMMENT ON COLUMN audit_events.event_ts_iso IS
    'Verbatim Python datetime.isoformat() string (e.g. "2026-06-11T00:10:36.123456+00:00"). '
    'Written by the proxy INSERT alongside event_ts (TIMESTAMPTZ). '
    'The compliance checker reads this column directly to avoid the Postgres '
    'TIMESTAMPTZ::text rendering divergence (space separator, "+00" vs "+00:00") '
    'that would cause every post-V028 row to fail SHA-256/HMAC verification. '
    'NULL for rows written before V030 (treated as unverifiable_legacy). '
    'appsec finding 0.2-F1.';
