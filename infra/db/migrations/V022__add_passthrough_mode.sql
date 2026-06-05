-- =============================================================================
-- V022__add_passthrough_mode.sql
-- MCP Security Platform — Case-3 (3b) native passthrough injection mode
-- PostgreSQL 16
-- =============================================================================
-- Adds 'passthrough' to injection_mode_enum.
--
-- passthrough: for downstream MCP servers that use a DIFFERENT IDP than the
-- gateway (e.g. M365/Entra). The gateway performs its OWN Keycloak authz (OPA)
-- but injects no credential of its own; it forwards the client's downstream
-- token (if present) and RELAYS the upstream's 401 + WWW-Authenticate challenge
-- back to the client so the client performs the downstream OAuth itself
-- (the "original mcp-server flow"). Idempotent.
-- =============================================================================

ALTER TYPE injection_mode_enum ADD VALUE IF NOT EXISTS 'passthrough';
