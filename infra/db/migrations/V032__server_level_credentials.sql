-- V032__server_level_credentials.sql
-- MCP Security Platform — Server-level credential attachment (Plan Task 3.2)
--
-- Adds server_registry.default_credential_id and default_injection_mode so
-- an entire server's tools can share one credential without per-tool columns.
--
-- Resolution order in dispatcher.py:
--   1. tool_registry.credential_id (per-tool override)
--   2. server_registry.default_credential_id + default_injection_mode (server default)
--   3. fail-closed (CredentialInjectionError)
--
-- INV-011: explicit GRANTs on every object touched.

ALTER TABLE server_registry
    ADD COLUMN IF NOT EXISTS default_credential_id UUID
        REFERENCES credential_store(id)
        ON DELETE SET NULL;

COMMENT ON COLUMN server_registry.default_credential_id IS
    'Default credential for all tools on this server. Per-tool credential_id overrides this.';

ALTER TABLE server_registry
    ADD COLUMN IF NOT EXISTS default_injection_mode injection_mode_enum
        DEFAULT NULL;

COMMENT ON COLUMN server_registry.default_injection_mode IS
    'Default injection mode for all tools on this server. NULL = fall back to tool-level injection_mode.';

CREATE INDEX IF NOT EXISTS idx_server_registry_default_credential
    ON server_registry (default_credential_id) WHERE default_credential_id IS NOT NULL;

-- INV-011: proxy_app needs SELECT (reads default credential) and UPDATE (admin sets it)
GRANT SELECT, INSERT, UPDATE ON server_registry TO proxy_app;
