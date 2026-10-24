-- 0004_ops.up.sql — mcphub-store consolidated schema, part 4/4
--
-- Quarantine history, per-principal rate-limit/anomaly overrides, and the
-- application role's least-privilege grants (INV-011-equivalent for the
-- Rust rewrite).

-- ---------------------------------------------------------------------------
-- quarantine_events — history of quarantine/release actions against a
-- server or tool. `target_id` is polymorphic (server_id or tool_id
-- depending on target_type) so a single FK is not possible; the gate that
-- reads this table always knows which type it is asking about.
--
-- Query pattern (HOT — quarantine gate, every invoke):
--   SELECT 1 FROM quarantine_events
--   WHERE target_type = $1 AND target_id = $2 AND released_at IS NULL
--   LIMIT 1
-- ---------------------------------------------------------------------------
CREATE TYPE quarantine_target_enum AS ENUM ('server', 'tool');

CREATE TABLE IF NOT EXISTS quarantine_events (
    quarantine_id   UUID                    PRIMARY KEY DEFAULT gen_random_uuid(),
    target_type     quarantine_target_enum  NOT NULL,
    target_id       UUID                    NOT NULL,
    reason          TEXT                    NOT NULL,
    quarantined_by  TEXT                    NOT NULL,
    quarantined_at  TIMESTAMPTZ             NOT NULL DEFAULT now(),
    released_at     TIMESTAMPTZ,
    released_by     TEXT,
    created_at      TIMESTAMPTZ             NOT NULL DEFAULT now(),

    CONSTRAINT ck_quarantine_release_requires_releaser
        CHECK (released_at IS NULL OR released_by IS NOT NULL)
);

-- Partial index: the quarantine gate only ever asks "is there an OPEN
-- quarantine for this target", never the full history.
CREATE INDEX IF NOT EXISTS idx_quarantine_events_open
    ON quarantine_events (target_type, target_id)
    WHERE released_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_quarantine_events_target_history
    ON quarantine_events (target_type, target_id, quarantined_at DESC);

-- ---------------------------------------------------------------------------
-- rate_limit_config — per-principal overrides. Absence of a row means "use
-- the role default" (resolved in mcphub-policy, not here).
--
-- Query pattern (HOT — rate-limit / anomaly-cutoff gate, every invoke):
--   SELECT rate_limit_rpm, anomaly_sensitivity FROM rate_limit_config
--   WHERE principal_id = $1
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS rate_limit_config (
    principal_id         TEXT        PRIMARY KEY,
    rate_limit_rpm       INTEGER     CHECK (rate_limit_rpm IS NULL OR rate_limit_rpm BETWEEN 1 AND 1000000),
    anomaly_sensitivity  TEXT        NOT NULL DEFAULT 'normal'
                             CHECK (anomaly_sensitivity IN ('normal', 'lenient', 'off')),
    updated_by           TEXT,
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TRIGGER trg_rate_limit_config_updated_at
    BEFORE UPDATE ON rate_limit_config
    FOR EACH ROW EXECUTE FUNCTION fn_set_updated_at();

-- ---------------------------------------------------------------------------
-- Application role: least-privilege grants for the single service account
-- the gateway binary connects as. Mirrors the Python platform's INV-011
-- pattern (proxy_app): explicit per-table GRANT/REVOKE, audit_events never
-- gets UPDATE/DELETE from any application role.
--
-- The role is created here with NOLOGIN by default; deployment tooling
-- (ansible / the installer) sets LOGIN + a real password out of band. This
-- mirrors the Python platform's infra/scripts/init-db-roles.sh split
-- between "role exists" (migration-owned) and "role has a real password"
-- (deploy-time secret, never checked in).
-- ---------------------------------------------------------------------------
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'mcphub_app') THEN
        CREATE ROLE mcphub_app NOLOGIN;
    END IF;
END
$$;

GRANT SELECT, INSERT, UPDATE ON role_grants TO mcphub_app;
GRANT SELECT, INSERT, UPDATE ON idp_configs TO mcphub_app;
GRANT SELECT, INSERT, UPDATE ON servers TO mcphub_app;
-- tool_registry: no DELETE grant needed — the trigger blocks hard delete
-- unconditionally regardless of role, but omitting the grant keeps the
-- privilege model self-documenting.
GRANT SELECT, INSERT, UPDATE ON tool_registry TO mcphub_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON grants TO mcphub_app;
-- credentials permits hard DELETE (full revocation) — see 0002's comment.
GRANT SELECT, INSERT, UPDATE, DELETE ON credentials TO mcphub_app;
-- audit_events: INSERT + SELECT only. UPDATE/DELETE are never granted.
GRANT SELECT, INSERT ON audit_events TO mcphub_app;
REVOKE UPDATE, DELETE ON audit_events FROM mcphub_app;
GRANT SELECT, INSERT, UPDATE ON quarantine_events TO mcphub_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON rate_limit_config TO mcphub_app;
