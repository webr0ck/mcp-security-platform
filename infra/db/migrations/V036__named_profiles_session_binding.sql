-- =============================================================================
-- V036__named_profiles_session_binding.sql — Task 4.3 (SELF-F5/F8)
--
-- Named profiles: a user-visible, named set of MCP entitlements + restrictions
-- that scopes a login session's tool visibility.
--
-- A user logs in as "read-only analyst" or "deployment engineer" via
-- ?profile=<name> and gets different tool visibility for that session.
--
-- Design:
--   profiles              — named profiles (platform-level, created by admins)
--   profile_mcp_bindings  — which MCPs (+ function restrictions) apply to a profile
--   oidc_sessions         — gains profile_uuid FK to bind a session to a profile
--   mcp_profiles          — gains profile_uuid FK to repoint per-profile rows
--
-- V019 profile_tokens: unused by any proxy code (no references in proxy/).
-- Dropped here to eliminate dead schema.
--
-- Backward compatibility: profile_uuid IS NULL in oidc_sessions = "no profile" →
-- tool visibility falls back to legacy mcp_profiles / entitlement-only path.
--
-- INV-011: explicit GRANT/REVOKE on every new table.
-- =============================================================================

-- ---------------------------------------------------------------------------
-- 1. Named profiles table
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS profiles (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    name            TEXT        NOT NULL UNIQUE,
    display_name    TEXT,
    description     TEXT,
    created_by      TEXT        NOT NULL DEFAULT 'system',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    is_active       BOOLEAN     NOT NULL DEFAULT TRUE
);

CREATE INDEX IF NOT EXISTS idx_profiles_name
    ON profiles (name)
    WHERE is_active = TRUE;

-- ---------------------------------------------------------------------------
-- 2. Profile-MCP bindings
--    Controls which MCPs + functions are enabled for a named profile.
--    NULL allowed_functions means all functions for that MCP are permitted.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS profile_mcp_bindings (
    id              SERIAL      PRIMARY KEY,
    profile_id      UUID        NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
    mcp_name        TEXT        NOT NULL,
    enabled         BOOLEAN     NOT NULL DEFAULT TRUE,
    allowed_functions TEXT[],   -- NULL = all functions; non-null = restricted set
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (profile_id, mcp_name)
);

CREATE INDEX IF NOT EXISTS idx_profile_mcp_bindings_profile_id
    ON profile_mcp_bindings (profile_id);

-- ---------------------------------------------------------------------------
-- 3. Bind oidc_sessions to a named profile (nullable — NULL = no profile)
-- ---------------------------------------------------------------------------
ALTER TABLE oidc_sessions
    ADD COLUMN IF NOT EXISTS profile_uuid UUID REFERENCES profiles(id);

CREATE INDEX IF NOT EXISTS idx_oidc_sessions_profile_uuid
    ON oidc_sessions (profile_uuid)
    WHERE profile_uuid IS NOT NULL;

-- ---------------------------------------------------------------------------
-- 4. Repoint mcp_profiles at named profiles
--    Existing per-identity rows keep profile_uuid = NULL (legacy path).
--    New rows created under a named profile carry profile_uuid.
-- ---------------------------------------------------------------------------
ALTER TABLE mcp_profiles
    ADD COLUMN IF NOT EXISTS profile_uuid UUID REFERENCES profiles(id);

CREATE INDEX IF NOT EXISTS idx_mcp_profiles_profile_uuid
    ON mcp_profiles (profile_uuid)
    WHERE profile_uuid IS NOT NULL;

-- ---------------------------------------------------------------------------
-- 5. Drop V019 profile_tokens — unused dead schema (no proxy code references it)
-- ---------------------------------------------------------------------------
DROP TABLE IF EXISTS profile_tokens;

-- ---------------------------------------------------------------------------
-- 6. INV-011: explicit GRANT/REVOKE
-- ---------------------------------------------------------------------------
GRANT SELECT, INSERT, UPDATE ON profiles TO proxy_app;
REVOKE TRUNCATE ON profiles FROM proxy_app;

GRANT SELECT, INSERT, UPDATE, DELETE ON profile_mcp_bindings TO proxy_app;
REVOKE TRUNCATE ON profile_mcp_bindings FROM proxy_app;
GRANT USAGE, SELECT ON SEQUENCE profile_mcp_bindings_id_seq TO proxy_app;

-- oidc_sessions already has GRANT in V012; ALTER TABLE ADD COLUMN inherits it.
-- mcp_profiles already has GRANT in V020; ALTER TABLE ADD COLUMN inherits it.

-- Also grant to mcp_proxy role (used by V034 client_grants path)
GRANT SELECT, INSERT, UPDATE ON profiles TO mcp_proxy;
GRANT SELECT, INSERT, UPDATE, DELETE ON profile_mcp_bindings TO mcp_proxy;
GRANT USAGE, SELECT ON SEQUENCE profile_mcp_bindings_id_seq TO mcp_proxy;

COMMENT ON TABLE profiles IS
    'Named profile definitions. Each profile is a named set of MCP entitlements. '
    'Users bind a named profile at login time via ?profile=<name>. '
    'profile_uuid=NULL in oidc_sessions means no profile (legacy path, backward compatible).';

COMMENT ON TABLE profile_mcp_bindings IS
    'MCP bindings for a named profile. Rows control which MCPs and functions are '
    'enabled for the profile. Absence of a row = platform default (enabled=true, all functions).';
