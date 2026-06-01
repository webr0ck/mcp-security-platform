-- =============================================================================
-- lab/seeder/sql/tools.sql
-- Inserts test tool records into tool_registry for the lab environment.
-- Idempotent: ON CONFLICT updates mutable fields so re-running the seeder
-- does not fail and keeps upstream URLs / credential config current.
--
-- Requires V007 migration to have run (service_name, credential_approach,
-- inject_header, inject_prefix columns must exist).
-- =============================================================================

INSERT INTO tool_registry (
    tool_id, name, version, description, schema, upstream_url,
    status, risk_level, risk_score, risk_reasons,
    registered_by, service_name, credential_approach, inject_header, inject_prefix
) VALUES
(
    gen_random_uuid(),
    'grafana-query', '1.0.0',
    'Query Grafana dashboards and panels via MCP',
    '{"type":"object","properties":{"query":{"type":"string"}}}'::jsonb,
    'http://lab-grafana:3000/mcp',
    'active', 'low', 10, '[]'::jsonb,
    'lab-seeder', 'grafana', 'B', 'Authorization', 'Bearer '
),
(
    gen_random_uuid(),
    'netbox-query', '1.0.0',
    'Query NetBox DCIM/IPAM via MCP',
    '{"type":"object","properties":{"resource":{"type":"string"}}}'::jsonb,
    'http://lab-netbox:8080/mcp',
    'active', 'low', 10, '[]'::jsonb,
    'lab-seeder', 'netbox', 'B', 'Authorization', 'Token '
),
(
    gen_random_uuid(),
    'dex-calendar', '1.0.0',
    'Access user calendar via Dex-issued token',
    '{"type":"object","properties":{"user":{"type":"string"}}}'::jsonb,
    'http://lab-dex:5556/mcp',
    'active', 'low', 15, '[]'::jsonb,
    'lab-seeder', 'dex', 'A', 'Authorization', 'Bearer '
),
(
    gen_random_uuid(),
    'gitea-repos', '1.0.0',
    'Browse and manage Gitea repositories (lab Bitbucket equivalent) via MCP',
    '{"type":"object","properties":{"owner":{"type":"string"},"repo":{"type":"string"}}}'::jsonb,
    'http://lab-mcp-gitea:8000/mcp',
    'active', 'low', 10, '[]'::jsonb,
    'lab-seeder', 'gitea', 'B', 'Authorization', 'token '
),
(
    gen_random_uuid(),
    'm365-graph', '1.0.0',
    'Microsoft 365 / Entra ID tools via Graph API — list users, groups, mail, Teams',
    '{"type":"object","properties":{"tool":{"type":"string"},"arguments":{"type":"object"}}}'::jsonb,
    'http://lab-mcp-m365:8000/mcp',
    'active', 'medium', 35,
    '["Accesses M365 tenant data via app-only token","Mail.Read scope can read all mailboxes"]'::jsonb,
    'lab-seeder', 'm365', 'B', 'Authorization', 'Bearer '
)
ON CONFLICT (name, version) DO UPDATE SET
    upstream_url        = EXCLUDED.upstream_url,
    service_name        = EXCLUDED.service_name,
    credential_approach = EXCLUDED.credential_approach,
    inject_header       = EXCLUDED.inject_header,
    inject_prefix       = EXCLUDED.inject_prefix,
    updated_at          = NOW();

-- ── RAG Assistant — developer onboarding doc search ──────────────────────
INSERT INTO tool_registry (
    tool_id, name, version, description, schema, upstream_url,
    status, risk_level, risk_score, risk_reasons,
    registered_by, service_name, credential_approach, inject_header, inject_prefix
) VALUES
(
    gen_random_uuid(),
    'rag-assistant', '1.0.0',
    'Search platform documentation and return code examples for MCP server developers. Read-only. No credentials required.',
    '{"type":"object","properties":{"query":{"type":"string","description":"Keywords to search for in platform docs","maxLength":200},"limit":{"type":"integer","description":"Maximum results (1-10)","minimum":1,"maximum":10}},"required":["query"],"additionalProperties":false}'::jsonb,
    'http://lab-rag-assistant:8000/mcp',
    'active', 'medium', 30, '["Accepts free-text queries (potential prompt-injection surface)","Returns document snippets containing code and configuration examples"]'::jsonb,
    'lab-seeder', null, null, null, null
)
ON CONFLICT (name, version) DO UPDATE SET
    upstream_url = EXCLUDED.upstream_url,
    updated_at   = NOW();

-- ── Echo MCP — stress-test / auth-verification (no credentials needed) ───────
INSERT INTO tool_registry (
    tool_id, name, version, description, schema, upstream_url,
    status, risk_level, risk_score, risk_reasons,
    registered_by, service_name, credential_approach, inject_header, inject_prefix
) VALUES
(
    gen_random_uuid(),
    'echo-ping', '1.0.0',
    'Liveness and auth-verification tools for the echo MCP server.',
    '{"type":"object","properties":{"message":{"type":"string"},"count":{"type":"integer"},"tag":{"type":"string"}},"additionalProperties":false}'::jsonb,
    'http://lab-mcp-echo:8000/mcp',
    'active', 'low', 5, '[]'::jsonb,
    'lab-seeder', null, null, null, null
)
ON CONFLICT (name, version) DO UPDATE SET
    upstream_url = EXCLUDED.upstream_url,
    updated_at   = NOW();

-- ── Notes MCP — per-user isolated storage (approach A — per-user credential) ─
INSERT INTO tool_registry (
    tool_id, name, version, description, schema, upstream_url,
    status, risk_level, risk_score, risk_reasons,
    registered_by, service_name, credential_approach, inject_header, inject_prefix
) VALUES
(
    gen_random_uuid(),
    'notes-store', '1.0.0',
    'Create and retrieve user-isolated notes. Credential approach A: per-user JWT injected as X-User-Sub.',
    '{"type":"object","properties":{"title":{"type":"string"},"body":{"type":"string"},"user_sub":{"type":"string"},"note_id":{"type":"string"}},"additionalProperties":false}'::jsonb,
    'http://lab-mcp-notes:8000/mcp',
    'active', 'low', 15, '["Stores user-supplied text in Redis","Per-user isolation relies on proxy injecting correct user_sub"]'::jsonb,
    'lab-seeder', 'notes', 'A', 'X-User-Sub', ''
)
ON CONFLICT (name, version) DO UPDATE SET
    upstream_url        = EXCLUDED.upstream_url,
    service_name        = EXCLUDED.service_name,
    credential_approach = EXCLUDED.credential_approach,
    inject_header       = EXCLUDED.inject_header,
    inject_prefix       = EXCLUDED.inject_prefix,
    updated_at          = NOW();

-- ── Search MCP — shared service account (approach B — shared SA token) ────────
INSERT INTO tool_registry (
    tool_id, name, version, description, schema, upstream_url,
    status, risk_level, risk_score, risk_reasons,
    registered_by, service_name, credential_approach, inject_header, inject_prefix
) VALUES
(
    gen_random_uuid(),
    'search-kb', '1.0.0',
    'Full-text search over MCP security knowledge base. Shared service account: all users share one backend token.',
    '{"type":"object","properties":{"query":{"type":"string"},"limit":{"type":"integer"},"category":{"type":"string"}},"required":["query"],"additionalProperties":false}'::jsonb,
    'http://lab-mcp-search:8000/mcp',
    'active', 'low', 10, '["Returns internal documentation snippets"]'::jsonb,
    'lab-seeder', 'search', 'B', 'Authorization', 'Bearer '
)
ON CONFLICT (name, version) DO UPDATE SET
    upstream_url        = EXCLUDED.upstream_url,
    service_name        = EXCLUDED.service_name,
    credential_approach = EXCLUDED.credential_approach,
    inject_header       = EXCLUDED.inject_header,
    inject_prefix       = EXCLUDED.inject_prefix,
    updated_at          = NOW();

-- ── Self-Service MCP — per-identity permission management ────────────────────
INSERT INTO tool_registry (
    tool_id, name, version, description, schema, upstream_url,
    status, risk_level, risk_score, risk_reasons,
    registered_by, service_name, credential_approach, inject_header, inject_prefix
) VALUES
(
    gen_random_uuid(),
    'self-service-mcp', '1.0.0',
    'Per-identity MCP permission management: list, enable/disable MCPs and functions per profile.',
    '{"type":"object","properties":{"caller_sub":{"type":"string"},"mcp_name":{"type":"string"},"function_name":{"type":"string"},"target_profile":{"type":"string"},"caller_role":{"type":"string"}},"additionalProperties":false}'::jsonb,
    'http://lab-mcp-self-service:8000/mcp',
    'active', 'low', 10, '["Manages per-user access grants","Writes to mcp_profiles table"]'::jsonb,
    'lab-seeder', null, 'A', 'X-User-Sub', ''
)
ON CONFLICT (name, version) DO UPDATE SET
    upstream_url        = EXCLUDED.upstream_url,
    updated_at          = NOW();
