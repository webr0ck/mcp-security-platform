-- =============================================================================
-- V011__credential_store_user_mode.sql
-- MCP Security Platform — Credential Store User-Mode Extensions
-- PostgreSQL 16
-- =============================================================================
-- Extends credential_store to support:
--   - owner_type: 'service' (shared) | 'user' (per-Keycloak-sub)
--   - tool_id FK: ties a service-mode credential to a specific tool
--   - credential_type: api_key | oauth2_refresh | entra_client_secret | service_account_jwt
--   - expires_at, rotated_at: lifecycle tracking
-- Existing rows default to owner_type='user' (original Approach A semantics).
-- =============================================================================

CREATE TYPE credential_owner_type AS ENUM ('service', 'user');
CREATE TYPE credential_type_enum AS ENUM (
    'api_key',
    'oauth2_refresh',
    'entra_client_secret',
    'service_account_jwt',
    'basic_auth'
);

ALTER TABLE credential_store
    ADD COLUMN IF NOT EXISTS owner_type       credential_owner_type  NOT NULL DEFAULT 'user',
    ADD COLUMN IF NOT EXISTS tool_id          UUID  REFERENCES tool_registry(tool_id),
    ADD COLUMN IF NOT EXISTS credential_type  credential_type_enum   NOT NULL DEFAULT 'oauth2_refresh',
    ADD COLUMN IF NOT EXISTS expires_at       TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS rotated_at       TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS description      VARCHAR(256);

-- For service-mode: one credential per tool (tool_id, owner_type='service')
-- Drop and recreate the unique constraint to accommodate both modes
ALTER TABLE credential_store DROP CONSTRAINT IF EXISTS uq_credential_store_user_service;

-- Service-mode uniqueness: one active credential per tool per service
CREATE UNIQUE INDEX IF NOT EXISTS uq_credential_service_mode
    ON credential_store (tool_id, service)
    WHERE owner_type = 'service' AND tool_id IS NOT NULL;

-- User-mode uniqueness: one credential per user per service (original behaviour)
CREATE UNIQUE INDEX IF NOT EXISTS uq_credential_user_mode
    ON credential_store (user_sub, service)
    WHERE owner_type = 'user';

-- Lookup index: fetch by tool + user sub (user-mode injection)
CREATE INDEX IF NOT EXISTS idx_credential_store_tool_user
    ON credential_store (tool_id, user_sub)
    WHERE owner_type = 'user' AND tool_id IS NOT NULL;

GRANT SELECT, INSERT, UPDATE, DELETE ON credential_store TO proxy_app;
