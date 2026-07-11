-- =============================================================================
-- V064__audit_event_principal_id.sql
-- MCP Security Platform — CR-10 (WP-A1) typed principal in audit events
-- PostgreSQL 16
-- =============================================================================
-- V029 added `principal_type` (human|agent|service) to audit_events. CR-10
-- additionally forwards the FULL typed principal id (e.g.
-- "human:kc-realm:alice", "agent:lab-ca:cn-123") and its issuer/CA component
-- so an auditor can distinguish two callers of the same principal_type and
-- bare subject (the exact collision CR-10 exists to prevent) directly from
-- the audit trail, without cross-referencing credential_store.
--
-- Both columns are advisory enrichment (like principal_type/tainted before
-- them) — NOT part of the canonical integrity hash computed in
-- mcp_audit_logger.schema.AuditEvent._compute_hash(), so this migration never
-- invalidates a previously-computed sha256_hash/HMAC value.
-- =============================================================================

ALTER TABLE audit_events
    ADD COLUMN IF NOT EXISTS principal_id     TEXT,
    ADD COLUMN IF NOT EXISTS principal_issuer TEXT;

-- Lookup index: "every invocation by this exact typed principal", the query
-- an auditor runs to confirm two same-bare-sub callers never shared a
-- credential/audit identity.
CREATE INDEX IF NOT EXISTS idx_audit_events_principal_id
    ON audit_events (principal_id, event_ts DESC)
    WHERE principal_id IS NOT NULL;

-- =============================================================================
-- GRANTs (INV-011: explicit grants, never wildcard) — same pattern as V029.
-- =============================================================================
GRANT INSERT, SELECT ON audit_events TO proxy_app;
REVOKE UPDATE, DELETE ON audit_events FROM proxy_app;
GRANT SELECT ON audit_events TO compliance_checker_app;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'audit_reader') THEN
        GRANT SELECT ON audit_events TO audit_reader;
    END IF;
END
$$;

COMMENT ON COLUMN audit_events.principal_id IS
    'CR-10 (WP-A1): full typed principal id (e.g. "human:kc-realm:alice", '
    '"agent:lab-ca:cn-123") — the collision-proof identity forwarded '
    'downstream as X-Principal-Id. NULL for pre-V064 rows and events where '
    'identity was not fully resolved (e.g. auth-failure rows).';

COMMENT ON COLUMN audit_events.principal_issuer IS
    'CR-10 (WP-A1): the issuer/CA component of the typed principal (OIDC '
    'issuer id, mTLS CA id, or "apikey"). NULL for pre-V064 rows.';
