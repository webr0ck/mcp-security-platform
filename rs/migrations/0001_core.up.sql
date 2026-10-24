-- 0001_core.up.sql — mcphub-store consolidated schema, part 1/4
--
-- This is a REWRITE, not a port: the Python platform accreted this shape
-- across 88 incremental migrations (infra/db/migrations/V001..V088). We
-- start from the *resulting* shape, not the history. See rs/ARCHITECTURE.md
-- for the invariants this schema enforces.
--
-- Part 1 covers: shared helpers, role/identity grants, IdP config, the
-- server registry, and the tool registry (one row per tool — the old
-- per-server-alias shape in the Python platform was a bug; see
-- docs/db.md §Architect Deviations in the Python tree for the incident).

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ---------------------------------------------------------------------------
-- Shared: updated_at maintenance trigger
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION fn_set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Shared: generic "this table is append-only / soft-delete-only" guard.
-- Used by tool_registry (blocks hard DELETE only; UPDATE is allowed for
-- soft-delete/status changes) and by audit_events (blocks both, see 0003).
CREATE OR REPLACE FUNCTION fn_block_hard_delete()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'hard delete blocked on %: use soft delete (deleted_at) instead', TG_TABLE_NAME
        USING ERRCODE = 'restrict_violation';
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

-- ---------------------------------------------------------------------------
-- role_grants — principal -> Role mapping (mirrors mcphub_types::Role
-- exactly: SuperAdmin, ServerOwner, SecurityAnalyst, Employee).
--
-- Query pattern (hot, every authenticated request):
--   SELECT role FROM role_grants
--   WHERE principal_id = $1 AND issuer = $2
--     AND (expires_at IS NULL OR expires_at > now())
-- ---------------------------------------------------------------------------
CREATE TYPE role_enum AS ENUM ('super_admin', 'server_owner', 'security_analyst', 'employee');

CREATE TABLE IF NOT EXISTS role_grants (
    role_grant_id   UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    -- Identity.sub — scoped by issuer below, never trusted alone (two IDPs
    -- can mint the same `sub` value independently).
    principal_id    TEXT        NOT NULL,
    issuer          TEXT        NOT NULL,
    role            role_enum   NOT NULL,
    granted_by      TEXT        NOT NULL,
    expires_at      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT uq_role_grants_principal_issuer_role UNIQUE (principal_id, issuer, role)
);

-- Serves the hot per-request role resolution query above.
CREATE INDEX IF NOT EXISTS idx_role_grants_principal
    ON role_grants (principal_id, issuer);

-- ---------------------------------------------------------------------------
-- idp_configs — runtime-settable IDP configuration (ARCHITECTURE.md
-- "Multi-IDP architecture"). Populated at install time from file config
-- and/or at runtime via POST /api/v1/admin/idps (super-admin only).
--
-- client_secret_credential_id points at `credentials` (created in 0002);
-- the FK is added there once that table exists — never store the raw
-- secret in this table.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS idp_configs (
    idp_id                      UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    name                        TEXT        NOT NULL,
    issuer                      TEXT        NOT NULL,
    discovery_url               TEXT,
    client_id                   TEXT        NOT NULL,
    client_secret_credential_id UUID,
    scopes                      TEXT[]      NOT NULL DEFAULT '{}',
    -- RFC 8693 token exchange support gates shared_exchange auth_mode
    -- eligibility for servers pointing at this IDP.
    supports_token_exchange     BOOLEAN     NOT NULL DEFAULT FALSE,
    is_platform_idp             BOOLEAN     NOT NULL DEFAULT FALSE,
    created_at                  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at                  TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at                  TIMESTAMPTZ
);

-- Startup / admin-API lookup by human-assigned name; one active config per name.
CREATE UNIQUE INDEX IF NOT EXISTS uq_idp_configs_name_active
    ON idp_configs (name) WHERE deleted_at IS NULL;

CREATE TRIGGER trg_idp_configs_updated_at
    BEFORE UPDATE ON idp_configs
    FOR EACH ROW EXECUTE FUNCTION fn_set_updated_at();

-- ---------------------------------------------------------------------------
-- servers — the MCP server registry. Every server declares an auth_mode
-- per ARCHITECTURE.md's multi-IDP table.
-- ---------------------------------------------------------------------------
CREATE TYPE server_status_enum AS ENUM ('pending', 'approved', 'suspended', 'quarantined', 'rejected');
CREATE TYPE auth_mode_enum AS ENUM ('shared_passthrough', 'shared_exchange', 'dedicated_port');

CREATE TABLE IF NOT EXISTS servers (
    server_id           UUID                PRIMARY KEY DEFAULT gen_random_uuid(),
    name                TEXT                NOT NULL,
    upstream_url        TEXT                NOT NULL,
    status              server_status_enum  NOT NULL DEFAULT 'pending',
    owner_principal_id  TEXT                NOT NULL,
    auth_mode           auth_mode_enum      NOT NULL DEFAULT 'shared_passthrough',
    -- Only set when auth_mode = 'dedicated_port'; allocated from
    -- listeners.dedicated_range (9000..9100) by the admin API, not by the DB.
    dedicated_port      INTEGER             CHECK (dedicated_port IS NULL OR dedicated_port BETWEEN 9000 AND 9100),
    idp_id               UUID               REFERENCES idp_configs (idp_id) ON DELETE SET NULL,
    approved_at          TIMESTAMPTZ,
    approved_by          TEXT,
    created_at           TIMESTAMPTZ        NOT NULL DEFAULT now(),
    updated_at           TIMESTAMPTZ        NOT NULL DEFAULT now(),
    deleted_at            TIMESTAMPTZ,

    CONSTRAINT ck_servers_approval_consistency CHECK (
        (approved_at IS NULL AND approved_by IS NULL) OR
        (approved_at IS NOT NULL AND approved_by IS NOT NULL)
    ),
    CONSTRAINT ck_servers_dedicated_port_matches_mode CHECK (
        (auth_mode = 'dedicated_port' AND dedicated_port IS NOT NULL) OR
        (auth_mode <> 'dedicated_port' AND dedicated_port IS NULL)
    )
);

-- Name and port are unique only among non-deleted rows (soft-delete allows reuse).
CREATE UNIQUE INDEX IF NOT EXISTS uq_servers_name_active
    ON servers (name) WHERE deleted_at IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS uq_servers_dedicated_port_active
    ON servers (dedicated_port) WHERE deleted_at IS NULL AND dedicated_port IS NOT NULL;

-- Hot query: ingress gate ("is this server enabled?") on every invoke.
CREATE INDEX IF NOT EXISTS idx_servers_status
    ON servers (status) WHERE deleted_at IS NULL;

CREATE TRIGGER trg_servers_updated_at
    BEFORE UPDATE ON servers
    FOR EACH ROW EXECUTE FUNCTION fn_set_updated_at();

-- ---------------------------------------------------------------------------
-- tool_registry — ONE ROW PER TOOL (name, version), not per server-alias.
-- The Python platform's per-server-alias shape produced a -32602 direct-call
-- bug (see the platform's per-tool-registry-migration notes); we start
-- correct here.
--
-- Non-negotiable: artifacts are referenced by immutable id (tool_id UUID
-- surrogate key) or content digest — never by name/path, which are mutable.
-- `digest` is the sha256 of the canonical (name, version, schema,
-- description) tuple and is what a caller can use to verify they invoked
-- the tool they expected, independent of any later metadata edits.
-- ---------------------------------------------------------------------------
CREATE TYPE tool_status_enum AS ENUM ('active', 'quarantined', 'deprecated', 'disabled');

CREATE TABLE IF NOT EXISTS tool_registry (
    tool_id         UUID                PRIMARY KEY DEFAULT gen_random_uuid(),
    server_id       UUID                NOT NULL REFERENCES servers (server_id) ON DELETE RESTRICT,
    name            TEXT                NOT NULL,
    version         TEXT                NOT NULL,
    description     TEXT                NOT NULL DEFAULT '',
    schema          JSONB               NOT NULL DEFAULT '{}',
    -- sha256 hex digest over the canonical (name, version, schema,
    -- description) tuple — the stable, content-addressable reference.
    digest          CHAR(64)            NOT NULL,
    status          tool_status_enum    NOT NULL DEFAULT 'active',
    risk_score      SMALLINT            CHECK (risk_score BETWEEN 0 AND 100),
    risk_level      TEXT                CHECK (risk_level IN ('low', 'medium', 'high', 'critical')),
    registered_by   TEXT                NOT NULL,
    created_at      TIMESTAMPTZ         NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ         NOT NULL DEFAULT now(),
    deleted_at      TIMESTAMPTZ,

    CONSTRAINT uq_tool_registry_name_version UNIQUE (name, version)
);

-- Hot query: tools/list for a server (discovery==invoke — invocation.rs
-- must use the identical WHERE clause for tools/call as this index serves
-- for tools/list; see ARCHITECTURE.md invariant 3).
CREATE INDEX IF NOT EXISTS idx_tool_registry_server_active
    ON tool_registry (server_id) WHERE deleted_at IS NULL AND status = 'active';

CREATE INDEX IF NOT EXISTS idx_tool_registry_digest
    ON tool_registry (digest);

CREATE TRIGGER trg_tool_registry_updated_at
    BEFORE UPDATE ON tool_registry
    FOR EACH ROW EXECUTE FUNCTION fn_set_updated_at();

-- Immutability guard: hard DELETE is always rejected. The only deletion
-- path is UPDATE ... SET deleted_at = now(), status = 'disabled'.
CREATE TRIGGER trg_tool_registry_block_delete
    BEFORE DELETE ON tool_registry
    FOR EACH ROW EXECUTE FUNCTION fn_block_hard_delete();
