-- V015__server_role_grant_entitlement.sql
-- server_role_grant: who owns/manages each registered server
-- entitlement: which principals may use each server (with version for invalidation)
CREATE TABLE IF NOT EXISTS server_role_grant (
    grant_id        UUID    PRIMARY KEY DEFAULT gen_random_uuid(),
    server_id       UUID    NOT NULL REFERENCES server_registry(server_id) ON DELETE CASCADE,
    principal_id    TEXT    NOT NULL,
    principal_type  principal_type_enum NOT NULL,
    role            VARCHAR(32) NOT NULL CHECK (role IN ('server_owner', 'manager')),
    granted_by      TEXT    NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (server_id, principal_id, principal_type, role)
);

CREATE INDEX IF NOT EXISTS idx_server_role_grant_principal
    ON server_role_grant (principal_id, principal_type);

GRANT SELECT, INSERT, UPDATE, DELETE ON server_role_grant TO proxy_app;

CREATE TABLE IF NOT EXISTS entitlement (
    entitlement_id      UUID    PRIMARY KEY DEFAULT gen_random_uuid(),
    server_id           UUID    NOT NULL REFERENCES server_registry(server_id) ON DELETE CASCADE,
    principal_id        TEXT    NOT NULL,
    principal_type      principal_type_enum NOT NULL,
    entitlement_version BIGINT  NOT NULL DEFAULT 1,
    granted_by          TEXT    NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at          TIMESTAMPTZ,
    UNIQUE (server_id, principal_id, principal_type)
);

CREATE INDEX IF NOT EXISTS idx_entitlement_principal
    ON entitlement (principal_id, principal_type) WHERE revoked_at IS NULL;

GRANT SELECT, INSERT, UPDATE, DELETE ON entitlement TO proxy_app;
