-- =============================================================================
-- V012__oidc_sessions.sql
-- MCP Security Platform — OIDC Browser Session Store
-- PostgreSQL 16
-- =============================================================================
-- Tracks PKCE-based Keycloak login sessions and the resulting internal JWTs.
-- Allows revocation (logout), replay detection (nonce used only once),
-- and session inspection in the admin UI.
-- =============================================================================

CREATE TABLE IF NOT EXISTS oidc_sessions (
    session_id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    -- PKCE / state parameters (pre-callback)
    state               TEXT        NOT NULL UNIQUE,
    pkce_code_verifier  TEXT        NOT NULL,
    nonce               TEXT        NOT NULL,
    redirect_uri        TEXT        NOT NULL,
    -- Identity (post-callback)
    subject             TEXT,                           -- Keycloak sub
    client_id_resolved  TEXT,                           -- proxy client_id (sub)
    kc_access_token     TEXT,                           -- server-side only; never returned to caller
    kc_refresh_token    TEXT,                           -- for refresh
    -- Internal session JWT (what callers hold as Bearer)
    session_jwt_jti     UUID        UNIQUE,             -- JWT ID for revocation
    -- Lifecycle
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at          TIMESTAMPTZ,                    -- set after callback
    revoked_at          TIMESTAMPTZ,
    user_agent          TEXT,
    ip_address          INET
);

-- Clean up expired sessions (retention policy hook-in)
CREATE INDEX IF NOT EXISTS idx_oidc_sessions_subject
    ON oidc_sessions (subject)
    WHERE revoked_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_oidc_sessions_expires
    ON oidc_sessions (expires_at)
    WHERE revoked_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_oidc_sessions_jti
    ON oidc_sessions (session_jwt_jti)
    WHERE session_jwt_jti IS NOT NULL;

GRANT SELECT, INSERT, UPDATE ON oidc_sessions TO proxy_app;
