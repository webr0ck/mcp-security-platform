-- V040__client_limits.sql — per-client request-limit overrides (admin-managed).
-- rate_limit NULL = use the per-role default. anomaly_sensitivity maps to an OPA cutoff
-- (normal=0.85, lenient=0.95, off=2.0). No row = all defaults.
CREATE TABLE IF NOT EXISTS client_limits (
    client_id            TEXT        PRIMARY KEY,
    rate_limit           INTEGER     CHECK (rate_limit IS NULL OR rate_limit BETWEEN 1 AND 100000),
    anomaly_sensitivity  TEXT        NOT NULL DEFAULT 'normal'
                             CHECK (anomaly_sensitivity IN ('normal','lenient','off')),
    updated_by           TEXT,
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
