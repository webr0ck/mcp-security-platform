-- 0005_ui_support.up.sql — tables needed only to back `mcphub-ui`'s
-- `UiData` trait (component 5's read/write seam for the portal). None of
-- these are on the tool-invocation hot path; they exist purely for the
-- admin/employee/owner UI views (access requests, anomaly alerts, and the
-- single global rate-limit/anomaly-cutoff default row).

-- ---------------------------------------------------------------------------
-- access_requests — an employee's "I'd like access to X" request, shown to
-- admins/owners for approval. Distinct from `grants` (the enforcement
-- table): a request becomes a grant only once approved (application-level
-- workflow, not enforced here).
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS access_requests (
    request_id      UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    requester_sub   TEXT        NOT NULL,
    server_id       UUID        NOT NULL REFERENCES servers (server_id) ON DELETE CASCADE,
    tool_name       TEXT        NOT NULL,
    justification   TEXT        NOT NULL,
    status          TEXT        NOT NULL DEFAULT 'pending'
                        CHECK (status IN ('pending', 'approved', 'rejected')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- UI query: "my pending requests" / "requests awaiting my review".
CREATE INDEX IF NOT EXISTS idx_access_requests_requester
    ON access_requests (requester_sub, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_access_requests_server_status
    ON access_requests (server_id, status);

CREATE TRIGGER trg_access_requests_updated_at
    BEFORE UPDATE ON access_requests
    FOR EACH ROW EXECUTE FUNCTION fn_set_updated_at();

-- ---------------------------------------------------------------------------
-- anomaly_alerts — surfaced in the security team's UI. Populated by
-- whichever component runs anomaly scoring against the audit stream (not
-- this crate); this table is the read model.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS anomaly_alerts (
    alert_id        UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    detected_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    principal_id    TEXT        NOT NULL,
    kind            TEXT        NOT NULL,
    severity        TEXT        NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    summary         TEXT        NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- UI query: "recent anomalies", newest first.
CREATE INDEX IF NOT EXISTS idx_anomaly_alerts_detected_at
    ON anomaly_alerts (detected_at DESC);

-- ---------------------------------------------------------------------------
-- global_limits — single-row table (rate limiter's role-level defaults +
-- anomaly cutoff + the dedicated-port allocation range shown/edited in the
-- admin UI). `id` is fixed at 1 so there is exactly one row, ever.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS global_limits (
    id                          SMALLINT    PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    default_rate_limit_per_min  INTEGER     NOT NULL DEFAULT 120 CHECK (default_rate_limit_per_min > 0),
    anomaly_cutoff_threshold    DOUBLE PRECISION NOT NULL DEFAULT 0.85,
    dedicated_port_range_start  INTEGER     NOT NULL DEFAULT 9000,
    dedicated_port_range_end    INTEGER     NOT NULL DEFAULT 9100,
    updated_by                  TEXT,
    updated_at                  TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT ck_global_limits_port_range CHECK (dedicated_port_range_end > dedicated_port_range_start)
);

INSERT INTO global_limits (id) VALUES (1) ON CONFLICT (id) DO NOTHING;

CREATE TRIGGER trg_global_limits_updated_at
    BEFORE UPDATE ON global_limits
    FOR EACH ROW EXECUTE FUNCTION fn_set_updated_at();

GRANT SELECT, INSERT, UPDATE ON access_requests TO mcphub_app;
GRANT SELECT, INSERT ON anomaly_alerts TO mcphub_app;
GRANT SELECT, UPDATE ON global_limits TO mcphub_app;
