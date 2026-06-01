-- V020: MCP Profiles — per-identity permission sets for self-service MCP management.
--
-- A profile controls which MCP servers (tools) a specific identity can invoke
-- and which functions within each MCP are enabled for that identity.
--
-- Design:
--   profile_id    — the caller's identity (KC sub UUID or service account sub)
--   mcp_name      — name column from tool_registry (not tool_id — names are stable)
--   enabled       — whether this identity can invoke this MCP at all
--   allowed_functions — NULL means all functions allowed; non-null restricts to listed names
--   updated_by    — who last changed this profile row (audit trail)
--   updated_at    — timestamp of last change

CREATE TABLE IF NOT EXISTS mcp_profiles (
    profile_id          TEXT        NOT NULL,
    mcp_name            TEXT        NOT NULL,
    enabled             BOOLEAN     NOT NULL DEFAULT true,
    allowed_functions   JSONB,                           -- null = all; ["fn1","fn2"] = restricted
    updated_by          TEXT        NOT NULL DEFAULT 'system',
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (profile_id, mcp_name)
);

-- Audit log for profile changes (append-only, never delete)
CREATE TABLE IF NOT EXISTS mcp_profile_events (
    event_id    UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    profile_id  TEXT        NOT NULL,
    mcp_name    TEXT        NOT NULL,
    event_type  TEXT        NOT NULL,  -- MCP_ENABLED | MCP_DISABLED | FUNCTION_ENABLED | FUNCTION_DISABLED | PROFILE_RESET
    old_state   JSONB,
    new_state   JSONB,
    changed_by  TEXT        NOT NULL,
    changed_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_mcp_profiles_profile_id ON mcp_profiles (profile_id);
CREATE INDEX IF NOT EXISTS idx_mcp_profile_events_profile_id ON mcp_profile_events (profile_id);
CREATE INDEX IF NOT EXISTS idx_mcp_profile_events_changed_at ON mcp_profile_events (changed_at DESC);

-- Default grants: grant proxy app user permissions
GRANT SELECT, INSERT, UPDATE ON mcp_profiles TO mcp_app;
GRANT SELECT, INSERT ON mcp_profile_events TO mcp_app;

COMMENT ON TABLE mcp_profiles IS
    'Per-identity MCP permissions. profile_id is the KC sub (or service account sub). '
    'NULL allowed_functions means all functions on that MCP are permitted. '
    'Rows are created on first enable/disable action; absence means platform default (enabled=true, all functions).';

COMMENT ON TABLE mcp_profile_events IS
    'Append-only audit trail for every profile change. Never delete rows.';
