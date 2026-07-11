-- =============================================================================
-- V062__credential_store_principal_type.sql
-- MCP Security Platform — CR-10 (WP-A1) typed-principal credential dual-read
-- PostgreSQL 16
-- =============================================================================
-- Problem: credential_store (V006/V011) keys every per-user row by a bare
-- Keycloak `user_sub`. An OIDC human, an API-key caller, and an mTLS agent
-- that happen to share the same subject string collide onto the same
-- credential set today — a real cross-principal-type credential bleed.
--
-- Fix (additive, NO big-bang rewrite of existing rows):
--   - Add a nullable `principal_type` column recording the caller category
--     ('human' | 'agent' | 'service') for rows written under the typed
--     namespace going forward.
--   - ALL NEW enrollments (proxy/app/routers/oauth.py::callback and any
--     future per-user credential write path) store user_sub = the FULL typed
--     principal_id (e.g. "human:kc-realm:alice", "agent:lab-ca:cn-123") and
--     set principal_type accordingly. Because the typed principal_id string
--     never collides with a bare subject, no unique-constraint conflict with
--     pre-existing bare-sub rows is possible.
--   - Existing (pre-V062) rows keep their bare `user_sub` and have
--     principal_type = NULL. The application layer
--     (app/credential_broker/principal_resolution.py) performs a DUAL-READ:
--       1. lookup by typed principal_id (the only key new writes use)
--       2. on miss, fall back to the bare-sub row — but ONLY if that row's
--          principal_type (or the inferred-legacy default of 'human', since
--          credential_store pre-CR-10 was only ever populated by OIDC/session
--          human enrollment flows) matches the caller's own principal_type.
--          A mismatch is a deny + audit event, never a silent match.
--   - Backfilling every legacy row's principal_type, or renaming legacy
--     user_sub values to the typed form, is explicitly OUT of scope for this
--     migration (tracked as a later, separate re-enrollment/cleanup step per
--     the WP-A1 sub-plan) — this migration only adds the column and its
--     constraint/index so the dual-read has something to read.
--
-- INV-011: explicit GRANT/REVOKE per-role per table (no wildcard grants).
-- =============================================================================

ALTER TABLE credential_store
    ADD COLUMN IF NOT EXISTS principal_type TEXT;

-- CHECK constraint: when present, must be one of the known caller categories.
-- Mirrors chk_principal_type on audit_events (V029) for consistency.
ALTER TABLE credential_store
    ADD CONSTRAINT chk_credential_store_principal_type
        CHECK (
            principal_type IS NULL
            OR principal_type IN ('human', 'agent', 'service')
        );

-- Supports the dual-read's bare-sub fallback lookup filtering by type
-- without a full scan (queries already filter by user_sub + service first;
-- this composite index covers the follow-on principal_type comparison).
CREATE INDEX IF NOT EXISTS idx_credential_store_principal_type
    ON credential_store (user_sub, service, principal_type);

COMMENT ON COLUMN credential_store.principal_type IS
    'CR-10 (WP-A1): caller category (human | agent | service) recorded for '
    'rows written under the typed principal_id namespace. NULL for pre-V062 '
    'rows (bare-sub legacy) — the dual-read treats NULL as inferred-legacy '
    '''human'' since credential_store pre-CR-10 was only ever populated by '
    'OIDC/session human enrollment flows. A caller whose principal_type does '
    'not match a legacy row''s (inferred or recorded) type is DENIED the '
    'fallback match, never silently granted it. '
    'See app/credential_broker/principal_resolution.py.';

-- INV-011: no new GRANT needed — V006's GRANT SELECT, INSERT, UPDATE, DELETE
-- ON credential_store TO proxy_app already covers this new column.
