-- deployments/poc/seed/poc-seed.sql
-- Demo role assignments and server registrations for the POC tier.
-- Idempotent: ON CONFLICT DO NOTHING on all inserts.
-- Schema: role_assignments(client_id, role, granted_by) — V008
--         server_registry(name, upstream_url, status, owner_sub) — V014

-- ── Demo user role assignments ─────────────────────────────────────────────

-- alice — viewer (echo only)
INSERT INTO role_assignments (client_id, role, granted_by)
VALUES ('alice', 'viewer', 'poc-seeder')
ON CONFLICT ON CONSTRAINT idx_role_assignments_client_role DO NOTHING;

-- bob — editor (echo + notes)
INSERT INTO role_assignments (client_id, role, granted_by)
VALUES ('bob', 'editor', 'poc-seeder')
ON CONFLICT ON CONSTRAINT idx_role_assignments_client_role DO NOTHING;

-- carol — agent (echo + notes + search + tool invocation)
-- 'agent' role is required by the /api/v1/tools/{tool_id}/invoke endpoint
-- (see proxy/app/routers/tools.py line 1115). 'analyst' is not in the allowed
-- invoke set and would return HTTP 403 at the role gate before the taint floor.
INSERT INTO role_assignments (client_id, role, granted_by)
VALUES ('carol', 'agent', 'poc-seeder')
ON CONFLICT ON CONSTRAINT idx_role_assignments_client_role DO NOTHING;

-- ── POC MCP server registrations ──────────────────────────────────────────
-- status 'approved' skips the manual approval step for demo purposes.
-- owner_sub 'poc-seeder' is the bootstrap identity; update via admin panel.

INSERT INTO server_registry (name, upstream_url, status, owner_sub, injection_mode)
VALUES ('poc-echo-server', 'http://mcp-echo:8000', 'approved', 'poc-seeder', 'none')
ON CONFLICT (name) DO NOTHING;

-- INVARIANT: notes-store tools must have required_integrity >= 1 (the V038 schema DEFAULT 1
-- applies when required_integrity is NULL). If an admin reclassifies notes-store tools to
-- required_integrity=0, the taint floor will stop blocking tainted principals from calling
-- delete_note, silently breaking the demo's core security guarantee. Verify with:
--   SELECT name, required_integrity FROM tool_registry WHERE server_id =
--     (SELECT server_id FROM server_registry WHERE name='poc-notes-server');
INSERT INTO server_registry (name, upstream_url, status, owner_sub, injection_mode)
VALUES ('poc-notes-server', 'http://mcp-notes:8000', 'approved', 'poc-seeder', 'user')
ON CONFLICT (name) DO NOTHING;

-- trust_tier=0 is set explicitly (not relying on V038 DEFAULT 0) so that a schema
-- default change cannot silently promote poc-search-server to a trusted source and
-- break the demo's core taint-floor invariant. If this value is changed, the red team
-- demo (sandbox/tests/red_team/test_prompt_injection_wazuh.sh) will fail to demonstrate
-- indirect prompt injection via taint propagation.
INSERT INTO server_registry (name, upstream_url, status, owner_sub, injection_mode, trust_tier)
VALUES ('poc-search-server', 'http://mcp-search:8000', 'approved', 'poc-seeder', 'service', 0)
ON CONFLICT (name) DO NOTHING;
