-- =============================================================================
-- V039__oidc_sessions_pkce_method.sql
-- Add pkce_code_challenge_method column to enforce S256 at proxy layer.
-- Fixes: proxy-layer PKCE method validation (HIGH finding, callback path).
-- =============================================================================

ALTER TABLE oidc_sessions
    ADD COLUMN IF NOT EXISTS pkce_code_challenge_method TEXT NOT NULL DEFAULT 'S256';

COMMENT ON COLUMN oidc_sessions.pkce_code_challenge_method IS
    'PKCE method used at login time. Proxy enforces this is S256 at callback.';
