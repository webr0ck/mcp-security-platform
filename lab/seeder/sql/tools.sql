-- =============================================================================
-- lab/seeder/sql/tools.sql
-- Inserts test tool records into tool_registry for the lab environment.
-- Idempotent: ON CONFLICT updates mutable fields so re-running the seeder
-- does not fail and keeps upstream URLs / credential config current.
--
-- Requires V007 (service_name, credential_approach, inject_header, inject_prefix)
-- and V010 (injection_mode) migrations to have run.
-- =============================================================================

-- ── Grafana — dynamic per-user token via GrafanaAdapter (Approach B) ──────────
INSERT INTO tool_registry (
    tool_id, name, version, description, schema, upstream_url,
    status, risk_level, risk_score, risk_reasons,
    registered_by, service_name, credential_approach, injection_mode, inject_header, inject_prefix
) VALUES
(
    gen_random_uuid(),
    'grafana-query', '1.0.0',
    'Query Grafana dashboards and panels via MCP',
    '{"type":"object","properties":{"query":{"type":"string"}}}'::jsonb,
    'http://lab-mcp-grafana:8000/mcp',
    'active', 'low', 10, '[]'::jsonb,
    'lab-seeder', 'grafana', 'B', 'service', 'Authorization', 'Bearer '
),
-- ── NetBox — dynamic per-user token via NetboxAdapter (Approach B) ────────────
(
    gen_random_uuid(),
    'netbox-query', '1.0.0',
    'Query NetBox DCIM/IPAM via MCP',
    '{"type":"object","properties":{"resource":{"type":"string"}}}'::jsonb,
    'http://mcp-netbox:8000/mcp',
    'active', 'low', 10, '[]'::jsonb,
    'lab-seeder', 'netbox', 'B', 'service', 'Authorization', 'Token '
),
-- ── Dex — per-user OAuth2 token (Approach A) ──────────────────────────────────
(
    gen_random_uuid(),
    'dex-calendar', '1.0.0',
    'Access user calendar via Dex-issued token',
    '{"type":"object","properties":{"user":{"type":"string"}}}'::jsonb,
    'http://lab-dex:5556/mcp',
    'active', 'low', 15, '[]'::jsonb,
    'lab-seeder', 'dex', 'A', 'user', 'Authorization', 'Bearer '
),
-- ── Gitea — shared admin token via GiteaAdapter (Approach B) ─────────────────
(
    gen_random_uuid(),
    'gitea-repos', '1.0.0',
    'Browse and manage Gitea repositories (lab Bitbucket equivalent) via MCP',
    '{"type":"object","properties":{"owner":{"type":"string"},"repo":{"type":"string"}}}'::jsonb,
    'http://lab-mcp-gitea:8000/mcp',
    'active', 'low', 10, '[]'::jsonb,
    'lab-seeder', 'gitea', 'B', 'service', 'Authorization', 'token '
),
-- ── M365 lab mock — no real auth (mock server, Approach B stub) ───────────────
(
    gen_random_uuid(),
    'm365-graph', '1.0.0',
    'Microsoft 365 / Entra ID tools via Graph API — list users, groups, mail, Teams',
    '{"type":"object","properties":{"tool":{"type":"string"},"arguments":{"type":"object"}}}'::jsonb,
    'http://lab-mcp-m365:8000/mcp',
    'active', 'medium', 35,
    '["Accesses M365 tenant data via app-only token","Mail.Read scope can read all mailboxes"]'::jsonb,
    'lab-seeder', null, null, 'none', null, null
)
ON CONFLICT (name, version) DO UPDATE SET
    upstream_url        = EXCLUDED.upstream_url,
    service_name        = EXCLUDED.service_name,
    credential_approach = EXCLUDED.credential_approach,
    injection_mode      = EXCLUDED.injection_mode,
    inject_header       = EXCLUDED.inject_header,
    inject_prefix       = EXCLUDED.inject_prefix,
    updated_at          = NOW();

-- ── RAG Assistant — no credentials (read-only public docs) ────────────────────
INSERT INTO tool_registry (
    tool_id, name, version, description, schema, upstream_url,
    status, risk_level, risk_score, risk_reasons,
    registered_by, service_name, credential_approach, injection_mode, inject_header, inject_prefix
) VALUES
(
    gen_random_uuid(),
    'rag-assistant', '1.0.0',
    'Search platform documentation and return code examples for MCP server developers. Read-only. No credentials required.',
    '{"type":"object","properties":{"query":{"type":"string","description":"Keywords to search for in platform docs","maxLength":200},"limit":{"type":"integer","description":"Maximum results (1-10)","minimum":1,"maximum":10}},"required":["query"],"additionalProperties":false}'::jsonb,
    'http://lab-rag-assistant:8000/mcp',
    'active', 'medium', 30, '["Accepts free-text queries (potential prompt-injection surface)","Returns document snippets containing code and configuration examples"]'::jsonb,
    'lab-seeder', null, null, 'none', null, null
)
ON CONFLICT (name, version) DO UPDATE SET
    upstream_url   = EXCLUDED.upstream_url,
    injection_mode = EXCLUDED.injection_mode,
    updated_at     = NOW();

-- ── Echo MCP — liveness and auth-verification (no credentials) ───────────────
INSERT INTO tool_registry (
    tool_id, name, version, description, schema, upstream_url,
    status, risk_level, risk_score, risk_reasons,
    registered_by, service_name, credential_approach, injection_mode, inject_header, inject_prefix
) VALUES
(
    gen_random_uuid(),
    'echo-ping', '1.0.0',
    'Liveness and auth-verification tools for the echo MCP server.',
    '{"type":"object","properties":{"message":{"type":"string"},"count":{"type":"integer"},"tag":{"type":"string"}},"additionalProperties":false}'::jsonb,
    'http://lab-mcp-echo:8000/mcp',
    'active', 'low', 5, '[]'::jsonb,
    'lab-seeder', null, null, 'none', null, null
)
ON CONFLICT (name, version) DO UPDATE SET
    upstream_url   = EXCLUDED.upstream_url,
    injection_mode = EXCLUDED.injection_mode,
    updated_at     = NOW();

-- ── Notes MCP — per-user isolation via X-User-Sub header (injected by proxy) ──
-- injection_mode='none': X-User-Sub comes from forward_base_headers, not broker.
INSERT INTO tool_registry (
    tool_id, name, version, description, schema, upstream_url,
    status, risk_level, risk_score, risk_reasons,
    registered_by, service_name, credential_approach, injection_mode, inject_header, inject_prefix
) VALUES
(
    gen_random_uuid(),
    'notes-store', '1.0.0',
    'Create and retrieve user-isolated notes. User identity injected as X-User-Sub header by proxy.',
    '{"type":"object","properties":{"title":{"type":"string"},"body":{"type":"string"},"note_id":{"type":"string"}},"additionalProperties":false}'::jsonb,
    'http://lab-mcp-notes:8000/mcp',
    'active', 'low', 15, '["Stores user-supplied text in Redis","Per-user isolation relies on proxy injecting X-User-Sub"]'::jsonb,
    'lab-seeder', null, 'A', 'none', null, null
)
ON CONFLICT (name, version) DO UPDATE SET
    upstream_url   = EXCLUDED.upstream_url,
    injection_mode = EXCLUDED.injection_mode,
    updated_at     = NOW();

-- ── Search MCP — no per-request credentials (mock search service) ─────────────
INSERT INTO tool_registry (
    tool_id, name, version, description, schema, upstream_url,
    status, risk_level, risk_score, risk_reasons,
    registered_by, service_name, credential_approach, injection_mode, inject_header, inject_prefix
) VALUES
(
    gen_random_uuid(),
    'search-kb', '1.0.0',
    'Full-text search over MCP security knowledge base. All authenticated users share the same search index.',
    '{"type":"object","properties":{"query":{"type":"string"},"limit":{"type":"integer"},"category":{"type":"string"}},"required":["query"],"additionalProperties":false}'::jsonb,
    'http://lab-mcp-search:8000/mcp',
    'active', 'low', 10, '["Returns internal documentation snippets"]'::jsonb,
    'lab-seeder', null, 'B', 'none', null, null
)
ON CONFLICT (name, version) DO UPDATE SET
    upstream_url   = EXCLUDED.upstream_url,
    injection_mode = EXCLUDED.injection_mode,
    updated_at     = NOW();

-- ── Self-Service MCP — per-identity permission management via X-User-Sub ──────
-- injection_mode='none': X-User-Sub + X-User-Role come from forward_base_headers.
INSERT INTO tool_registry (
    tool_id, name, version, description, schema, upstream_url,
    status, risk_level, risk_score, risk_reasons,
    registered_by, service_name, credential_approach, injection_mode, inject_header, inject_prefix
) VALUES
(
    gen_random_uuid(),
    'self-service-mcp', '1.0.0',
    'Per-identity MCP permission management: list, enable/disable MCPs and functions per profile.',
    '{"type":"object","properties":{"mcp_name":{"type":"string"},"function_name":{"type":"string"},"target_profile":{"type":"string"}},"additionalProperties":false}'::jsonb,
    'http://lab-mcp-self-service:8000/mcp',
    'active', 'low', 10, '["Manages per-user access grants","Writes to mcp_profiles table"]'::jsonb,
    'lab-seeder', null, 'A', 'none', null, null
)
ON CONFLICT (name, version) DO UPDATE SET
    upstream_url   = EXCLUDED.upstream_url,
    injection_mode = EXCLUDED.injection_mode,
    updated_at     = NOW();
