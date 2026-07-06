-- =============================================================================
-- V034__client_grants.sql — Task 4.4b (SELF-F6, SELF rec 6)
--
-- Converges tool-level grants into the database.
-- Previously grants lived in policies/rego/data.json (mcp.grants), requiring
-- a whole-file edit and bundle re-sign for every grant change.
--
-- This table is the authoritative source for per-client tool grants.
-- The proxy's OPADataSync service reads this table at startup and on a 60s
-- reconcile loop, pushing to OPA via PUT /v1/data/mcp_grants (NOT owned by
-- the signed bundle — see policies/rego/.manifest for the carve-out).
--
-- Schema:
--   client_id        — the principal / client identity (matches input.client_id in OPA)
--   allowed_tools    — JSON array of tool names the client may invoke
--   allowed_tags     — JSON array of tag names; tools tagged with any of these are allowed
--   max_risk_level   — the highest risk level this client may invoke
--   granted_by       — identity of the admin who created this grant (audit trail)
--   created_at       — immutable creation timestamp
--   updated_at       — last modification timestamp (for reconcile change detection)
--
-- INV-011: explicit GRANT/REVOKE for proxy_app role.
-- The proxy reads grants (SELECT) and the admin endpoints insert/delete them.
-- No UPDATE — mutations create a new row after deleting the old one (UNIQUE enforces).
-- =============================================================================

CREATE TABLE IF NOT EXISTS client_grants (
    id              SERIAL          PRIMARY KEY,
    client_id       TEXT            NOT NULL,
    allowed_tools   JSONB           NOT NULL DEFAULT '[]',
    allowed_tags    JSONB           NOT NULL DEFAULT '[]',
    max_risk_level  TEXT            NOT NULL DEFAULT 'low',
    granted_by      TEXT            NOT NULL DEFAULT 'system',
    created_at      TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ     NOT NULL DEFAULT NOW(),

    CONSTRAINT uq_client_grants_client_id UNIQUE (client_id),
    CONSTRAINT chk_client_grants_max_risk_level
        CHECK (max_risk_level IN ('low', 'medium', 'high', 'critical'))
);

-- Index for the proxy's lookup by client_id (startup + reconcile query)
CREATE INDEX IF NOT EXISTS idx_client_grants_client_id
    ON client_grants (client_id);

-- updated_at auto-bump trigger (change detection for reconcile loop)
CREATE OR REPLACE FUNCTION update_client_grants_updated_at()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger
        WHERE tgname = 'trg_client_grants_updated_at'
    ) THEN
        CREATE TRIGGER trg_client_grants_updated_at
        BEFORE UPDATE ON client_grants
        FOR EACH ROW EXECUTE FUNCTION update_client_grants_updated_at();
    END IF;
END;
$$;

-- INV-011: explicit GRANT/REVOKE for proxy_app role
-- SELECT: proxy reads grants at startup and in reconcile loop
-- INSERT, UPDATE, DELETE: admin endpoints (grant, update, revoke)
GRANT SELECT, INSERT, UPDATE, DELETE ON client_grants TO proxy_app;
REVOKE TRUNCATE ON client_grants FROM proxy_app;
GRANT USAGE, SELECT ON SEQUENCE client_grants_id_seq TO proxy_app;

-- Seed from data.json grants so startup behaves identically to pre-migration.
-- These are the static dev/lab clients. Production grants are managed via the
-- admin API (POST /api/v1/admin/grants) after migration.
-- Remove or replace this block in production before running this migration.
INSERT INTO client_grants (client_id, allowed_tools, allowed_tags, max_risk_level, granted_by)
VALUES
    ('alice@corp',
     '["grafana-query","netbox-query","dex-calendar","m365-graph","gitea-repos","echo-ping","notes-store","search-kb","self-service-mcp","rag-assistant","ping","echo_args","whoami","slow_tool","bulk_compute","create_note","list_notes","get_note","delete_note","search","get_document","list_categories","search_by_category","list_available_mcps","get_profile","list_functions","netbox_get_objects","netbox_get_object_by_id","netbox_get_changelogs","netbox_search_objects","list_repos","get_repo","list_issues","create_issue","list_pull_requests","get_file_contents","list_branches","get_me","list_emails","get_email","send_email","list_calendar_events","create_calendar_event","list_files","list_teams","list_team_channels"]'::jsonb,
     '["lab","testing","grafana","monitoring"]'::jsonb,
     'medium',
     'seed-migration'),
    ('bob@corp',
     '["grafana-query","netbox-query","echo-ping","search-kb","notes-store","ping","echo_args","whoami","create_note","list_notes","get_note","delete_note","search","get_document","list_categories","search_by_category"]'::jsonb,
     '["lab","testing"]'::jsonb,
     'low',
     'seed-migration'),
    ('carol@corp',
     '["echo-ping","notes-store","search-kb","ping","echo_args","create_note","list_notes","get_note","delete_note","search","list_categories"]'::jsonb,
     '["lab","testing"]'::jsonb,
     'low',
     'seed-migration'),
    ('c2358c21-ed42-45bd-af3f-7d2efebb2943',
     '["echo-ping","search-kb","ping","echo_args","whoami","search","get_document","list_categories","search_by_category"]'::jsonb,
     '["lab","testing"]'::jsonb,
     'medium',
     'seed-migration'),
    ('test-agent-client',
     '["active-low-risk-tool"]'::jsonb,
     '[]'::jsonb,
     'low',
     'seed-migration'),
    ('agent:step-ca:test-agent-client',
     '["active-low-risk-tool"]'::jsonb,
     '[]'::jsonb,
     'low',
     'seed-migration'),
    ('platform_internal',
     '["platform_info","security_pulse_summary","list_registered_tools"]'::jsonb,
     '[]'::jsonb,
     'low',
     'seed-migration'),
    ('bob',
     '["ping","echo_args","whoami","slow_tool","notes_read","notes_write","notes_delete"]'::jsonb,
     '["echo","read-only","notes"]'::jsonb,
     'medium',
     'seed-migration'),
    ('carol',
     '["ping","echo_args","whoami","slow_tool","notes_read","notes_write","notes_delete","search","fetch_url","summarize"]'::jsonb,
     '["echo","read-only","notes","search"]'::jsonb,
     'medium',
     'seed-migration')
ON CONFLICT (client_id) DO NOTHING;

COMMENT ON TABLE client_grants IS
    'Per-client tool grants pushed to OPA at /v1/data/mcp_grants. '
    'Replaces static mcp.grants in data.json (Task 4.4b). '
    'Updated via admin API; synced to OPA by OPADataSync service on startup and every 60s.';
