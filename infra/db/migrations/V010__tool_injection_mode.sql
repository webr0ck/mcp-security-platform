-- =============================================================================
-- V010__tool_injection_mode.sql
-- MCP Security Platform — Credential Injection Mode per Tool
-- PostgreSQL 16
-- =============================================================================
-- Adds injection_mode to tool_registry (replaces the binary A/B approach).
-- Also adds Keycloak service-account columns for kc_service_account and
-- entra_user_token modes.
--
-- injection_mode values:
--   none              — no credential injection (default, backward-compatible)
--   service           — one shared credential per tool/service (Approach B)
--   user              — per-user credential keyed by Keycloak sub claim
--   service_account   — Keycloak service-account token (client_credentials)
--   oauth_user_token  — user's OAuth2 access token forwarded to upstream
--
-- Old credential_approach (A/B) is preserved for backward compatibility.
-- =============================================================================

CREATE TYPE injection_mode_enum AS ENUM (
    'none',
    'service',
    'user',
    'service_account',
    'oauth_user_token'
);

ALTER TABLE tool_registry
    ADD COLUMN IF NOT EXISTS injection_mode          injection_mode_enum  NOT NULL DEFAULT 'none',
    ADD COLUMN IF NOT EXISTS kc_client_id            VARCHAR(128),   -- Keycloak client for service-account token
    ADD COLUMN IF NOT EXISTS kc_token_audience       VARCHAR(256),   -- audience for KC token exchange
    ADD COLUMN IF NOT EXISTS entra_tenant_id         VARCHAR(64),    -- Azure AD tenant UUID
    ADD COLUMN IF NOT EXISTS entra_client_id         VARCHAR(64),    -- Azure AD app registration client_id
    ADD COLUMN IF NOT EXISTS entra_scope             VARCHAR(512);   -- space-separated MS Graph scopes

-- Migrate existing credential_approach='B' rows to injection_mode='service'
-- and credential_approach='A' rows to injection_mode='user'
UPDATE tool_registry
SET injection_mode = CASE
    WHEN credential_approach = 'B' THEN 'service'::injection_mode_enum
    WHEN credential_approach = 'A' THEN 'user'::injection_mode_enum
    ELSE 'none'::injection_mode_enum
END
WHERE credential_approach IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_tool_registry_injection_mode
    ON tool_registry (injection_mode)
    WHERE deleted_at IS NULL AND injection_mode != 'none';

GRANT SELECT, INSERT, UPDATE ON tool_registry TO proxy_app;
