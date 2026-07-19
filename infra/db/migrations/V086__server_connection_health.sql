-- V086__server_connection_health.sql
-- Auto-flag a server as broken after repeated connection-class failures
-- (upstream unreachable, DNS/SSRF revalidation failure, MCP initialize
-- handshake failure, or the upstream MCP tool itself reporting
-- isError:true) — never a single blip, a run of consecutive failures.
-- Reuses the existing debug_mode/debug_enabled_at/debug_enabled_by columns
-- (PRD-0012) as the "in maintenance" signal; debug_enabled_by is set to the
-- sentinel 'system:auto-health-check' so the UI can distinguish "an admin
-- put this in maintenance" from "the platform detected it's broken" and
-- show a distinct, clearly-labeled marker for the latter.

ALTER TABLE server_registry
    ADD COLUMN IF NOT EXISTS connection_failure_count INT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS last_connection_error TEXT,
    ADD COLUMN IF NOT EXISTS last_connection_error_at TIMESTAMPTZ;
