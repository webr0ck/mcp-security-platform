-- =============================================================================
-- lab/seeder/sql/demo_named_profile.sql
-- PRD-0011: ship a working named profile so "working profiles" is demonstrable
-- on a fresh boot without any manual setup. Named profiles (profiles +
-- profile_mcp_bindings) are what ?profile=<guid> scopes against on the bearer
-- path (see middleware/auth.py::_resolve_active_profile_uuid and
-- routers/mcp_server.py's profile_mcp_bindings filter). Before this the lab
-- shipped zero named profiles, so there was nothing to connect a scoped MCP
-- client to.
--
-- 'readonly-demo' hides the reviewer WRITE tools (approve/reject submission), so
-- an MCP client connecting with ?profile=<this-guid> sees the catalogue minus
-- those tools — a clear, safe demonstration of profile narrowing. A profile only
-- ever NARROWS visibility on top of entitlements; it never grants.
--
-- Discover its GUID from an authenticated client via GET /api/v1/profiles/named
-- (or the get_profile self-service tool), then connect with
--   .../mcp?profile=<guid>
-- Idempotent: safe to re-run.
-- =============================================================================
BEGIN;

INSERT INTO profiles (name, display_name, description, created_by)
VALUES ('readonly-demo', 'Read-only demo',
        'Demo named profile: hides the reviewer approve/reject tools. Connect an '
        'MCP client with ?profile=<this profile id> to see profile scoping.',
        'lab-seeder')
ON CONFLICT (name) DO UPDATE SET
    display_name = EXCLUDED.display_name,
    description  = EXCLUDED.description,
    is_active    = TRUE;

-- Disable the reviewer write tools for this profile (binding mcp_name matches the
-- tool name the tools/list filter checks). Absence of a row = enabled by default.
INSERT INTO profile_mcp_bindings (profile_id, mcp_name, enabled)
SELECT p.id, t.mcp_name, FALSE
FROM profiles p
CROSS JOIN (VALUES ('approve_submission'), ('reject_submission')) AS t(mcp_name)
WHERE p.name = 'readonly-demo'
ON CONFLICT (profile_id, mcp_name) DO UPDATE SET enabled = EXCLUDED.enabled;

COMMIT;
