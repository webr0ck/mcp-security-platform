-- =============================================================================
-- V083__audit_events_notices.sql
-- MCP Security Platform — persist advisory `notices` on audit_events
-- PostgreSQL 16
-- =============================================================================
-- PRD-0012/Fix-7 added a `notices` list field to the AuditEvent SDK
-- (observability/mcp-audit-logger/mcp_audit_logger/schema.py). It already
-- flows to the stdout/SIEM stream and Wazuh syslog, but was never persisted
-- to the audit_events index table, so it was not queryable via the
-- compliance/audit API.
--
-- `notices` are advisory-only messages that do NOT affect the outcome (e.g.
-- a taint-floor notify-only disclaimer) — distinct from `opa_reasons`, which
-- records reasons a request was actually denied. Mirrors the `opa_reasons`
-- column type (JSONB) since both are lists of short strings serialized the
-- same way by _emit_audit_event.
--
-- Column is nullable-safe via a DEFAULT so pre-V083 INSERT paths (if any
-- linger mid-deploy) keep working; the application always passes an
-- explicit (possibly empty) list.
--
-- INV-011: explicit GRANT/REVOKE per-role.
-- =============================================================================

ALTER TABLE audit_events
    ADD COLUMN IF NOT EXISTS notices JSONB NOT NULL DEFAULT '[]';

COMMENT ON COLUMN audit_events.notices IS
    'Advisory-only messages that do NOT affect outcome (e.g. a taint-floor '
    'notify-only disclaimer). Distinct from opa_reasons, which is reserved '
    'for reasons a request was actually denied. Empty JSONB array by default '
    '(PRD-0012/Fix-7).';

-- =============================================================================
-- GRANTs (INV-011: explicit grants, never wildcard)
-- =============================================================================

-- proxy_app: INSERT/SELECT already granted on audit_events by V028.
-- The new column inherits those grants automatically in PostgreSQL;
-- re-stating them here makes the per-column grant chain explicit and
-- verifiable by `make security-check`.
GRANT INSERT, SELECT ON audit_events TO proxy_app;

-- compliance_checker_app: SELECT only (read audit events for verification runs).
GRANT SELECT ON audit_events TO compliance_checker_app;

-- Revoke UPDATE/DELETE as an idempotent append-only invariant guard.
REVOKE UPDATE, DELETE ON audit_events FROM proxy_app;
