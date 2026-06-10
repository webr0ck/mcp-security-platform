-- no-txn
-- =============================================================================
-- V027__tool_registry_credential_id.sql
-- MCP Security Platform — add credential_id to tool_registry
-- PostgreSQL 16
-- =============================================================================
-- Adds credential_id column to tool_registry to link tools to vault-backed
-- credentials stored in credential_store.
--
-- When a tool has injection_mode='entra_client_credentials', 'service', or 'user',
-- the credential_id points to the encrypted credential in credential_store.
-- The dispatcher reads the credential_id from tool_record and calls
-- retrieve_credential() to decrypt and use it.
--
-- credential_id is nullable: tools without credential-based injection leave it NULL.
-- =============================================================================

ALTER TABLE tool_registry
    ADD COLUMN IF NOT EXISTS credential_id UUID;

-- Foreign key constraint is NOT added because credential_store and tool_registry
-- are independent entities with different retention policies. Tools may be
-- deleted without removing their credentials (for audit trail), and credentials
-- may be rotated without changing tool_id. The constraint would be too rigid.

-- Index for lookups by credential_id during injection dispatch
CREATE INDEX IF NOT EXISTS idx_tool_registry_credential_id
    ON tool_registry (credential_id)
    WHERE deleted_at IS NULL AND credential_id IS NOT NULL;

GRANT SELECT, UPDATE ON tool_registry TO proxy_app;
