-- V071__external_oauth_client_secret_credential_type.sql
-- MCP Security Platform — Add 'external_oauth_client_secret' to credential_type_enum
-- (WP-A3/Task-12: CR-04 remainder — Dex-as-second-external-IdP live proof)
--
-- The generic dynamic external_oauth_user_token adapter path
-- (credential_broker/adapters/dynamic_external_oauth.py) provisions a
-- service-owned OAuth 2.0 client_secret per onboarded server (looked up via
-- tool_registry.credential_id, distinct from every other static adapter's
-- (service, tool_id) lookup). None of the existing credential_type_enum
-- labels fit: 'entra_client_secret' is Microsoft-specific and would
-- mislabel a Dex/generic-IdP secret; 'api_key' is the wrong shape entirely.
--
-- ADD VALUE cannot run inside a transaction block (Postgres restriction).
-- Flyway: annotate with @nonTransactional. psql: run outside a BEGIN/COMMIT.

ALTER TYPE credential_type_enum ADD VALUE IF NOT EXISTS 'external_oauth_client_secret';

-- No new object → no additional GRANT required (see V061 precedent).
