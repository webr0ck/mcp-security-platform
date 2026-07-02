-- =============================================================================
-- lab/seeder/sql/servers.sql
-- Onboards each lab MCP server into server_registry and links its tool_registry
-- row + grants the lab principal an entitlement.
--
-- WHY: the invoke-time DNS-rebind / TOCTOU guard (invocation.py Step 3c) treats a
-- tool whose server_id is NULL as a PUBLIC upstream. Lab containers resolve to
-- private podman IPs (10.89.0.0/16), so such tools are denied with
-- `upstream_revalidation_failed`. A linked, approved server_registry row carrying
-- an upstream_allowlist_entry of 10.89.0.0/16 permits the private upstream.
-- Mirrors the pre-existing lab-echo entry.
--
-- Requires tools.sql to have run first (tool_registry rows must exist to link).
-- Idempotent: safe to re-run (ON CONFLICT / NULL-guarded UPDATE / DO NOTHING).
-- =============================================================================
BEGIN;

INSERT INTO server_registry
    (name, upstream_url, status, owner_sub, injection_mode, custody_mode,
     trust_tier, trust_tier_label, upstream_allowlist_entry, url_allowlist_checked, platform_managed_creds)
SELECT v.name, v.upstream_url, 'approved', 'alice@corp', v.imode::injection_mode_enum, 'session_suk',
       2, 'internal', '10.89.0.0/16', false, v.platform_creds
FROM (VALUES
    ('lab-echo',         'http://lab-mcp-echo:8000/mcp',          'none',                     false),
    ('lab-gitea',        'http://lab-mcp-gitea:8000/mcp',         'service',                  true),
    ('lab-grafana-mcp',  'http://lab-mcp-grafana:8000/mcp',       'service',                  true),
    ('lab-search',       'http://lab-mcp-search:8000/mcp',        'none',                     false),
    ('lab-notes',        'http://lab-mcp-notes:8000/mcp',         'none',                     false),
    ('lab-m365',         'http://lab-mcp-m365:8000/mcp',          'entra_client_credentials', false),
    ('lab-dex-cal',      'http://lab-dex:5556/mcp',               'user',                     true),
    ('lab-rag',          'http://lab-rag-assistant:8000/mcp',     'none',                     false),
    ('lab-self-service', 'http://lab-mcp-self-service:8000/mcp',  'none',                     false),
    ('lab-netbox-mcp',   'http://mcp-netbox:8000/mcp',            'user',                     true),
    ('lab-wazuh',        'http://lab-mcp-wazuh:8000/mcp',         'service',                  true)
) AS v(name, upstream_url, imode, platform_creds)
ON CONFLICT (name) DO UPDATE
    SET status                   = 'approved',
        owner_sub                = EXCLUDED.owner_sub,
        injection_mode           = EXCLUDED.injection_mode,
        platform_managed_creds   = EXCLUDED.platform_managed_creds,
        upstream_allowlist_entry = EXCLUDED.upstream_allowlist_entry,
        trust_tier               = EXCLUDED.trust_tier,
        trust_tier_label         = EXCLUDED.trust_tier_label,
        updated_at               = now();

-- Link each tool to its server by matching upstream_url (only fills NULLs)
UPDATE tool_registry t
SET server_id = s.server_id, updated_at = now()
FROM server_registry s
WHERE t.server_id IS NULL
  AND t.deleted_at IS NULL
  AND t.upstream_url = s.upstream_url;

-- Grant the lab Keycloak user an entitlement on each onboarded server
INSERT INTO entitlement (server_id, principal_id, principal_type, granted_by, entitlement_version)
SELECT s.server_id, 'human:keycloak:alice@corp', 'human', 'lab-seeder', 1
FROM server_registry s
WHERE s.upstream_allowlist_entry = '10.89.0.0/16'
ON CONFLICT (server_id, principal_id, principal_type) DO NOTHING;

-- Grant the lab API key (Claude Code SELF_SERVICE_API_KEY) an entitlement on each onboarded server
INSERT INTO entitlement (server_id, principal_id, principal_type, granted_by, entitlement_version)
SELECT s.server_id, 'human:apikey:lab-self-service', 'human', 'lab-seeder', 1
FROM server_registry s
WHERE s.upstream_allowlist_entry = '10.89.0.0/16'
ON CONFLICT (server_id, principal_id, principal_type) DO NOTHING;

COMMIT;
