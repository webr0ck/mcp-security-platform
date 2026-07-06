-- =============================================================================
-- V037__audit_event_opa_decision_id.sql
-- MCP Security Platform — OPA decision-log correlation column
-- PostgreSQL 16
-- =============================================================================
-- Task 5.1 (LOG-F04): add opa_decision_id to audit_events so each DB row can
-- be cross-referenced with the corresponding OPA decision log line in Loki
-- (Promtail job: mcp-opa-decisions, container: mcp-opa).
--
-- OPA emits a "decision_id" (UUID string) in both:
--   1. The HTTP response body from POST /v1/data/* when decision logging is on
--      (--set=decision_logs.console=true in docker-compose.yml).
--   2. The structured JSON log line written to OPA stdout, which Promtail
--      scrapes and ships to Loki with INV-002 input.params redaction applied.
--
-- By storing this ID in audit_events, a security analyst can:
--   SELECT opa_decision_id FROM audit_events WHERE event_id = '<uuid>';
-- and then query Loki:
--   {job="mcp-opa-decisions"} | json | decision_id="<opa_decision_id>"
-- to retrieve the full OPA decision context (input, result, bundle details).
--
-- Column is nullable: pre-V036 rows and deployments without decision logging
-- will have NULL. The application falls back to a locally-generated placeholder
-- string (dec_<hex16>) only when OPA does not return a decision_id.
--
-- INV-011: explicit GRANT/REVOKE per-role.
-- =============================================================================

ALTER TABLE audit_events
    ADD COLUMN IF NOT EXISTS opa_decision_id TEXT;

COMMENT ON COLUMN audit_events.opa_decision_id IS
    'OPA-assigned decision_id from the /v1/data response body (UUID string). '
    'Correlates this audit row with the OPA decision log line in Loki '
    '(job=mcp-opa-decisions). NULL for rows written before V036 or when OPA '
    'decision logging is disabled. Non-null value may also be a locally-generated '
    'dec_<hex16> placeholder when OPA did not return a decision_id.';

-- Index for cross-stream lookups: given a decision_id from Loki, find the audit row.
CREATE INDEX IF NOT EXISTS idx_audit_events_opa_decision_id
    ON audit_events (opa_decision_id)
    WHERE opa_decision_id IS NOT NULL;

-- =============================================================================
-- GRANTs (INV-011: explicit grants, never wildcard)
-- =============================================================================

-- proxy_app: INSERT/SELECT already granted on audit_events by V028.
-- The new column inherits those grants automatically in PostgreSQL;
-- re-stating them here makes the per-column grant chain explicit and
-- verifiable by `make security-check`.
GRANT INSERT, SELECT ON audit_events TO proxy_app;

-- compliance_checker_app: SELECT only (read audit events for verification runs).
-- The compliance checker does not query opa_decision_id today but may in future.
GRANT SELECT ON audit_events TO compliance_checker_app;

-- Revoke UPDATE/DELETE as an idempotent append-only invariant guard.
REVOKE UPDATE, DELETE ON audit_events FROM proxy_app;
