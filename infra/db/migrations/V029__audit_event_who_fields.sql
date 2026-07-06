-- =============================================================================
-- V029__audit_event_who_fields.sql
-- MCP Security Platform — audit_events "who" enrichment columns
-- PostgreSQL 16
-- =============================================================================
-- Task 1.2: Enrich audit "who" fields (LOG-F04)
--
-- Background: the existing audit_events table records WHAT happened but lacks
-- the structured "who" context needed to answer:
--   - Was the caller a human, an agent, or a service?
--   - What roles did the caller hold at invocation time?
--   - Which OIDC session (JTI) was active?
--
-- source_ip (INET) already exists from V001:228.  This migration adds the
-- three remaining "who" columns.
--
-- New columns:
--   principal_type  — 'human' | 'agent' | 'service' from request.state.
--                     NULL for unauthenticated / auth-failure events.
--   caller_roles    — TEXT[] snapshot of the caller's roles at invocation time
--                     (e.g. ARRAY['agent','auditor']). NULL for pre-V029 rows.
--                     Stored as a snapshot: OPA may grant per-tool access that
--                     is broader or narrower than the full role set; this column
--                     records the role set that was evaluated.
--   session_jti     — OIDC session JWT ID (jti claim).  Present only for
--                     session-JWT callers (OIDC browser flow); NULL for mTLS /
--                     API-key callers that have no OIDC session.
--                     Used to correlate audit events with session revocation
--                     records in oidc_sessions (INV-014).
--
-- source_ip population:
--   invocation.py now passes source_ip to _emit_audit_event; the existing
--   V001 INET column is populated via CAST(:source_ip AS INET) in the INSERT.
--   Pre-V029 rows that were NULL remain NULL.
--
-- Historical rows: all three new columns are nullable.  Pre-V029 rows have
-- NULL in all three.  The compliance checker and audit API treat NULL as
-- "not recorded" (not a violation).
--
-- INV-002: caller_roles values are role-name strings, never bearer token
-- payloads.  INV-002 redaction runs over all logged string fields anyway.
--
-- INV-011: explicit GRANT/REVOKE per-role per table.
-- =============================================================================

-- Add "who" enrichment columns (all nullable for pre-V029 compatibility)
ALTER TABLE audit_events
    ADD COLUMN IF NOT EXISTS principal_type  TEXT,
    ADD COLUMN IF NOT EXISTS caller_roles    TEXT[],
    ADD COLUMN IF NOT EXISTS session_jti     TEXT;

-- CHECK constraint: principal_type must be one of the known values when present.
ALTER TABLE audit_events
    ADD CONSTRAINT chk_principal_type
        CHECK (
            principal_type IS NULL
            OR principal_type IN ('human', 'agent', 'service')
        );

-- Index: support queries filtering by principal type (e.g. "all human-origin
-- events in the last 24h") without a full scan.
CREATE INDEX IF NOT EXISTS idx_audit_events_principal_type
    ON audit_events (principal_type, event_ts DESC)
    WHERE principal_type IS NOT NULL;

-- Index: session JTI lookup — used when investigating a revoked session to
-- enumerate all invocations that occurred under that session.
CREATE INDEX IF NOT EXISTS idx_audit_events_session_jti
    ON audit_events (session_jti, event_ts DESC)
    WHERE session_jti IS NOT NULL;

-- =============================================================================
-- GRANTs (INV-011: explicit grants, never wildcard)
-- =============================================================================

-- proxy_app: INSERT + SELECT (same pattern as V028; no UPDATE/DELETE).
GRANT INSERT, SELECT ON audit_events TO proxy_app;
REVOKE UPDATE, DELETE ON audit_events FROM proxy_app;

-- compliance_checker: SELECT only.
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
-- Column comments
-- =============================================================================
COMMENT ON COLUMN audit_events.principal_type IS
    'Caller category at invocation time: human | agent | service. '
    'NULL for pre-V029 rows and unauthenticated/auth-failure events. '
    'Derived from request.state.principal_type set by auth middleware.';

COMMENT ON COLUMN audit_events.caller_roles IS
    'Snapshot of the caller''s roles at invocation time (TEXT[]). '
    'NULL for pre-V029 rows. Role-name strings only — never token values (INV-002). '
    'E.g. ARRAY[''agent'',''auditor''].';

COMMENT ON COLUMN audit_events.session_jti IS
    'OIDC session JWT jti claim. Present for browser/session-JWT callers; '
    'NULL for mTLS/API-key callers with no OIDC session. '
    'Used to correlate audit events with oidc_sessions revocation records (INV-014).';
