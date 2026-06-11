-- V033__add_kc_token_exchange_mode.sql
-- MCP Security Platform — Add kc_token_exchange to injection_mode_enum (Tasks 3.5)
--
-- AUTH-F11 / AUTH-R4: kc_token_exchange is the canonical name for RFC 8693
-- within-Keycloak-realm token exchange. The existing "oauth_user_token" enum
-- value is retained for backwards compatibility with existing DB rows; the
-- dispatcher normalises it at runtime.
--
-- ADD VALUE cannot run inside a transaction block (Postgres restriction).
-- Flyway: annotate with @nonTransactional. psql: run outside a BEGIN/COMMIT.

ALTER TYPE injection_mode_enum ADD VALUE IF NOT EXISTS 'kc_token_exchange';

-- INV-011: proxy_app already has SELECT/INSERT/UPDATE on tool_registry and
-- server_registry from prior migrations. No new object → no additional GRANT
-- required; the enum extension is visible automatically to existing tables.
