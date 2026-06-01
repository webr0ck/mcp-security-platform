-- V014__server_registry.sql
-- Server registry: approved MCP server endpoints with custody metadata
CREATE TABLE IF NOT EXISTS server_registry (
    server_id               UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    name                    VARCHAR(128) NOT NULL UNIQUE,
    upstream_url            TEXT        NOT NULL,
    status                  VARCHAR(32) NOT NULL DEFAULT 'pending'
                                CHECK (status IN ('pending', 'approved', 'suspended')),
    owner_sub               TEXT        NOT NULL,
    injection_mode          injection_mode_enum NOT NULL DEFAULT 'none',
    service_name            VARCHAR(128),
    mode_locked_at_approval BOOLEAN     NOT NULL DEFAULT FALSE,
    pending_mode_change     JSONB,
    approved_oauth_scopes   TEXT[],
    url_allowlist_checked   BOOLEAN     NOT NULL DEFAULT FALSE,
    approved_at             TIMESTAMPTZ,
    approved_by             TEXT,
    CONSTRAINT server_registry_approval_consistency
        CHECK (
            (approved_at IS NULL AND approved_by IS NULL) OR
            (approved_at IS NOT NULL AND approved_by IS NOT NULL)
        ),
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at              TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_server_registry_status
    ON server_registry (status) WHERE deleted_at IS NULL;

CREATE TRIGGER trg_server_registry_updated_at
    BEFORE UPDATE ON server_registry
    FOR EACH ROW EXECUTE FUNCTION fn_set_updated_at();

GRANT SELECT, INSERT, UPDATE ON server_registry TO proxy_app;
