-- V047__anomaly_alert_attribution.sql
-- PRD-0003 R-7 — anomaly_alerts currently persists with invocation_ids always
-- '{}' and no tool reference, so a detection can never be traced back to the
-- MCP server it fired on. Adds the missing attribution columns; services/anomaly.py
-- is updated in the same change to populate them.
--
-- Nullable + ON DELETE SET NULL, same pattern as V023 (tool_registry.server_id):
-- existing/historical alert rows stay NULL and are displayed as "unattributed" —
-- no backfill guessing (PRD F-8).

ALTER TABLE anomaly_alerts
    ADD COLUMN IF NOT EXISTS tool_name TEXT,
    ADD COLUMN IF NOT EXISTS tool_id UUID
        REFERENCES tool_registry(tool_id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_anomaly_alerts_tool_id
    ON anomaly_alerts (tool_id) WHERE tool_id IS NOT NULL;

-- INV-011: proxy_app already holds INSERT/UPDATE on anomaly_alerts (V001);
-- re-assert SELECT idempotently so this migration is self-documenting.
DO $$
BEGIN
    IF EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'proxy_app') THEN
        GRANT SELECT ON anomaly_alerts TO proxy_app;
    END IF;
END
$$;
