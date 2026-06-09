-- V024__credential_store_scopes.sql
-- R-5: Add scopes column to credential_store for consent-time scope recording (D3, C6, C9).
--
-- Records the exact set of OAuth scopes the user consented to at enrollment time.
-- Space-separated, sorted-canonical (lowercase, sorted, deduped).
-- Existing rows predate consent tracking (R-5) and receive an empty string default;
-- they will be upgraded to a real scope set on the next enrollment (re-enrollment flow).
--
-- INV-011 (C9): V006's existing GRANT SELECT, INSERT, UPDATE, DELETE ON credential_store
-- TO proxy_app already covers this new column — no new GRANT is required.
-- The authoritative grant is in V006__credential_store.sql.

ALTER TABLE credential_store
    ADD COLUMN IF NOT EXISTS scopes TEXT NOT NULL DEFAULT '';

COMMENT ON COLUMN credential_store.scopes IS
    'Space-separated, sorted OAuth scopes consented at enrollment (R-5). '
    'Empty string for rows enrolled before R-5 (pre-consent-gate). '
    'INV-011: covered by the GRANT in V006__credential_store.sql.';
