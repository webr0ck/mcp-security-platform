-- =============================================================================
-- V007__tool_credential_columns.sql
-- MCP Security Platform — Credential Broker Configuration Columns
-- PostgreSQL 16
-- =============================================================================
-- Adds credential broker configuration columns to tool_registry.
-- These columns let the invocation service look up which broker approach
-- and injection header to use when forwarding calls to upstream MCP servers.
--
-- Approach A: Vault-issued token (dynamic, short-lived) — injected as-is.
-- Approach B: Static service credential fetched from Vault KV by service_name.
--
-- All columns are nullable: existing rows without credential config remain valid
-- (tools that do not require credential injection have NULL values here).
-- =============================================================================

ALTER TABLE tool_registry
    ADD COLUMN IF NOT EXISTS service_name          VARCHAR(64),
    ADD COLUMN IF NOT EXISTS credential_approach   CHAR(1)
        CHECK (credential_approach IN ('A', 'B')),
    ADD COLUMN IF NOT EXISTS inject_header         VARCHAR(128),
    ADD COLUMN IF NOT EXISTS inject_prefix         VARCHAR(64);

-- Partial index: service_name lookups during credential resolution skip soft-deleted
-- rows and skip tools with no credential config (service_name IS NOT NULL guard).
CREATE INDEX IF NOT EXISTS idx_tool_registry_service_name
    ON tool_registry (service_name)
    WHERE deleted_at IS NULL AND service_name IS NOT NULL;
