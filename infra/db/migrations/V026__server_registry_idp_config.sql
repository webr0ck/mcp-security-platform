-- no-txn
-- =============================================================================
-- V026__server_registry_idp_config.sql
-- MCP Security Platform — Add IdP and owner approval columns to server_registry
-- PostgreSQL 16
-- =============================================================================
-- Enables self-service server onboarding with 4 integration modes:
-- (a) oauth_user_token: same IdP as gateway (Keycloak)
-- (b) entra_user_token / entra_client_credentials: Azure IdP
-- (c) user mode: per-user credentials
-- (d) service / service_account: service account credentials
--
-- New columns:
--   upstream_idp_type TEXT: 'gateway_idp', 'entra', 'custom_oidc', or NULL (legacy)
--   upstream_idp_config JSONB: issuer, client_id, scopes; never secrets
--   credential_approach TEXT: 'a' (direct user token) or 'b' (broker mediates)
--   adapter_name TEXT: 'keycloak', 'entra', 'custom_oidc', 'user', 'service', etc.
--   owner_max_risk_level TEXT: admin-approved ceiling for owner invocations
--
-- Also adds 'entra_client_credentials' to injection_mode_enum (requires -- no-txn)
-- =============================================================================

ALTER TABLE server_registry ADD COLUMN IF NOT EXISTS
  upstream_idp_type TEXT
    CHECK (upstream_idp_type IN ('gateway_idp', 'entra', 'custom_oidc'))
    DEFAULT NULL;

ALTER TABLE server_registry ADD COLUMN IF NOT EXISTS
  upstream_idp_config JSONB DEFAULT NULL;

COMMENT ON COLUMN server_registry.upstream_idp_config IS
  'IdP configuration: {issuer, client_id, scopes}. Secrets stored separately in credential_store.';

ALTER TABLE server_registry ADD COLUMN IF NOT EXISTS
  credential_approach TEXT
    CHECK (credential_approach IN ('a', 'b'))
    DEFAULT NULL;

COMMENT ON COLUMN server_registry.credential_approach IS
  'a: direct user token to upstream; b: broker mediates (client credentials or user-on-behalf-of)';

ALTER TABLE server_registry ADD COLUMN IF NOT EXISTS
  adapter_name TEXT DEFAULT NULL;

COMMENT ON COLUMN server_registry.adapter_name IS
  'Upstream adapter: keycloak, entra, custom_oidc, user, service, grafana, netbox, m365, bitbucket, etc.';

ALTER TABLE server_registry ADD COLUMN IF NOT EXISTS
  owner_max_risk_level TEXT NOT NULL DEFAULT 'medium';

COMMENT ON COLUMN server_registry.owner_max_risk_level IS
  'Admin-approved risk ceiling for this server owner invocations (Phase 2 default: medium)';

-- Add entra_client_credentials to injection_mode_enum
-- This requires -- no-txn header since ALTER TYPE ... ADD VALUE cannot run in a transaction
ALTER TYPE injection_mode_enum ADD VALUE IF NOT EXISTS 'entra_client_credentials';

-- INV-011: explicit grants for new columns
GRANT SELECT, INSERT, UPDATE ON server_registry TO proxy_app;
