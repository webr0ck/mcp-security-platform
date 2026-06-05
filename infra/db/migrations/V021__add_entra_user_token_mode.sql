-- =============================================================================
-- V021__add_entra_user_token_mode.sql
-- MCP Security Platform — add delegated per-user Entra injection mode
-- PostgreSQL 16
-- =============================================================================
-- Adds 'entra_user_token' to injection_mode_enum.
--
-- entra_user_token: per-user DELEGATED Microsoft Graph token. The broker
-- (approach A) decrypts the caller's Entra refresh_token — stored at
-- /auth/callback/m365 under the authenticated Keycloak sub — and refreshes it
-- per call to mint a fresh delegated access_token. The downstream M365 MCP
-- server then acts AS THE SIGNED-IN USER (/me has meaning), in contrast to
-- entra_client_credentials (app-only, acts as the application).
--
-- ALTER TYPE ... ADD VALUE runs in autocommit (cannot be used in the same
-- transaction that then references the new label). IF NOT EXISTS makes the
-- migration idempotent / safe to re-run.
-- =============================================================================

ALTER TYPE injection_mode_enum ADD VALUE IF NOT EXISTS 'entra_user_token';
