-- =============================================================================
-- V028__audit_event_canonical_fields.sql
-- MCP Security Platform — audit_events canonical fields for hash integrity
-- PostgreSQL 16
-- =============================================================================
-- Task 0.2: Fix audit-event integrity verification (LOG-F08, HIGH)
--
-- Adds the columns required so the compliance checker can recompute the
-- SHA-256 integrity hash and verify the keyed HMAC independently of Loki.
--
-- Background: four canonicalization breaks prevented verify_hash_integrity()
-- from ever succeeding:
--   Break 1 — checker used wrong json.dumps separators (fixed in code).
--   Break 2 — SELECT omitted event_type and timestamp (added here).
--   Break 3 — platform_version missing from canonical form (added here).
--   Break 4 — invocation.py remapped outcome "error"→"deny" before INSERT;
--              original_outcome preserves the pre-remap value for hash
--              recomputation.
--
-- New columns:
--   event_type        — AuditEventType string (e.g. 'TOOL_INVOCATION').
--   platform_version  — Version string at emit time (e.g. '1.0.0').
--   original_outcome  — Pre-remap outcome ('allow' | 'deny' | 'error').
--                       The existing `outcome` column retains the DB-constraint-safe
--                       value ('allow'|'deny') for compliance queries; this column
--                       holds the semantic value used for hash computation.
--   hmac_signature    — HMAC-SHA-256 (keyed) over the canonical event JSON.
--                       Stored as 64-char hex digest. NULL for pre-V028 rows.
--   hmac_key_id       — Key identifier for key rotation. Default = 'default'
--                       (maps to AUDIT_LOG_HMAC_KEY env var in both proxy and
--                       compliance-checker). Retired keys stay available read-only
--                       for verification of historical rows.
--
-- Historical-row handling:
--   Pre-V028 rows will have NULL in all five new columns.  The compliance
--   checker's verify_hash_integrity() returns "legacy" for such rows and counts
--   them separately as `unverifiable_legacy`, not as mismatches.
--
-- Note on event_ts:
--   The existing event_ts column already stores the canonical timestamp;
--   the new SELECT in checker.py casts it as text via event_ts::text.
--   No new column needed for timestamp — just the SELECT alias.
--
-- INV-011: explicit GRANT/REVOKE per-role per table.
-- INV-001: every row written after this migration is fully verifiable.
-- =============================================================================

-- Add canonical fields (all nullable so pre-migration rows are valid)
ALTER TABLE audit_events
    ADD COLUMN IF NOT EXISTS event_type        TEXT,
    ADD COLUMN IF NOT EXISTS platform_version  TEXT,
    ADD COLUMN IF NOT EXISTS original_outcome  TEXT,
    ADD COLUMN IF NOT EXISTS hmac_signature    CHAR(64),
    ADD COLUMN IF NOT EXISTS hmac_key_id       TEXT DEFAULT 'default';

-- Add a CHECK on original_outcome matching the set of valid AuditOutcome values.
-- Nullable because pre-V028 rows are NULL; non-null rows must be valid.
ALTER TABLE audit_events
    ADD CONSTRAINT chk_original_outcome
        CHECK (original_outcome IS NULL OR original_outcome IN ('allow', 'deny', 'error'));

-- Index on hmac_key_id to support fast lookups when a key is being retired
-- and all rows signed under the old key need to be re-verified.
CREATE INDEX IF NOT EXISTS idx_audit_events_hmac_key_id
    ON audit_events (hmac_key_id)
    WHERE hmac_key_id IS NOT NULL;

-- Partial index: fast lookup of rows missing HMAC (pre-V028 legacy rows).
-- Used by the compliance checker to count unverifiable_legacy without a full scan.
CREATE INDEX IF NOT EXISTS idx_audit_events_legacy
    ON audit_events (event_id)
    WHERE hmac_signature IS NULL;

-- =============================================================================
-- GRANTs (INV-011: explicit grants, never wildcard)
-- =============================================================================

-- proxy_app: INSERT only (append-only table; no UPDATE/DELETE granted).
-- SELECT granted so the proxy can read back events for the compliance API.
GRANT INSERT, SELECT ON audit_events TO proxy_app;

-- compliance_checker_app: SELECT only (read audit events for verification runs).
GRANT SELECT ON audit_events TO compliance_checker_app;

-- audit_reader: SELECT only (for the GET /audit/events API).
-- This role may not exist in all deployments; wrapped in DO block to avoid
-- migration failure if the role is absent.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'audit_reader') THEN
        GRANT SELECT ON audit_events TO audit_reader;
    END IF;
END
$$;

-- Revoke any inadvertent UPDATE/DELETE from proxy_app (append-only invariant).
REVOKE UPDATE, DELETE ON audit_events FROM proxy_app;

-- =============================================================================
-- Comment: correct the misleading V001 comment
-- =============================================================================
-- The V001 DDL comment stated the SHA-256 hash covers "the full event payload
-- (stored in Loki)".  In reality it covers the canonical core identity fields
-- only (event_id, event_type, timestamp, client_id, tool_name, tool_id, outcome,
-- request_id, platform_version) — not the full payload.  This migration's
-- columns make that claim verifiable.  The V001 comment is corrected in-place
-- in a separate commit per the plan (Step 6).
COMMENT ON COLUMN audit_events.sha256_hash IS
    'SHA-256 of the canonical core identity fields (see mcp_audit_logger.hasher.canonical_audit_json). '
    'NOT a hash of the full payload. Use hmac_signature for tamper-evidence (keyed). '
    'Verified by compliance-checker verify_hash_integrity(). INV-001.';

COMMENT ON COLUMN audit_events.hmac_signature IS
    'HMAC-SHA-256 (keyed, key identified by hmac_key_id) over canonical_audit_json(). '
    'NULL for rows written before V028. Tamper-evident: a DB-writer cannot re-forge '
    'this without the key. Verified by compliance-checker verify_hash_integrity().';

COMMENT ON COLUMN audit_events.original_outcome IS
    'Pre-remap outcome value used for hash computation. '
    'The outcome column stores only the DB-constraint-safe values (allow|deny); '
    'this column stores the semantic value (allow|deny|error) that was used when '
    'computing sha256_hash and hmac_signature. NULL for pre-V028 rows.';
