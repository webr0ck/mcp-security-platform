-- V061__add_basic_auth_mode.sql
-- MCP Security Platform — Add basic_auth to injection_mode_enum (Codex review CR-05)
--
-- RFC 7617 HTTP Basic auth. The credential is stored in credential_store as
-- structured JSON {"username","secret"} (shared owner_type='service' or
-- per-user owner_type='user', keyed on service_name); the dispatcher's
-- _inject_basic_auth builds "Authorization: Basic <b64>" at injection time.
--
-- ADD VALUE cannot run inside a transaction block (Postgres restriction).
-- Flyway: annotate with @nonTransactional. psql: run outside a BEGIN/COMMIT.

ALTER TYPE injection_mode_enum ADD VALUE IF NOT EXISTS 'basic_auth';

-- No new object → no additional GRANT required (see V033 precedent).
