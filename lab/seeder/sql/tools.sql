-- =============================================================================
-- lab/seeder/sql/tools.sql
-- Inserts test tool records into tool_registry for the lab environment.
-- Idempotent: ON CONFLICT updates mutable fields so re-running the seeder
-- does not fail and keeps upstream URLs / credential config current.
--
-- Requires V007 (service_name, credential_approach, inject_header, inject_prefix)
-- and V010 (injection_mode) migrations to have run.
-- =============================================================================

-- ── Grafana — broker injects SA token via Authorization header (Case 2, service mode) ──
-- Our own mcp-servers/grafana/server.py reads the Authorization header injected
-- by the broker at call time. Token is stored in credential_store, not in compose env.
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
    'lab-seeder', 'grafana', null, 'service', 'Authorization', 'Bearer'
),
-- ── NetBox — per-user broker-injected token (Case 3, PRD-0002, user mode) ────────────────────
-- Our own mcp-servers/netbox/server.py reads the Authorization header injected
-- by the broker at call time. Each user's token is stored in credential_store (owner_type='user').
(
    gen_random_uuid(),
    'netbox-query', '1.0.0',
    'Query NetBox DCIM/IPAM via MCP',
    '{"type":"object","properties":{"resource":{"type":"string"}}}'::jsonb,
    'http://mcp-netbox:8000/mcp',
    'active', 'low', 10, '[]'::jsonb,
    'lab-seeder', 'netbox', null, 'user', 'Authorization', 'Token'
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
    'lab-seeder', 'm365', 'A', 'entra_client_credentials', 'Authorization', 'Bearer '
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
    'ping', '1.0.0',
    'Liveness check — returns server identity, caller, and current timestamp.',
    '{"type":"object","properties":{},"additionalProperties":false}'::jsonb,
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

-- ── MCP server onboarding tools (on lab-self-service container) ──────────────
-- injection_mode='passthrough': proxy forwards the caller's OAuth bearer token to
-- the upstream. The self-service server re-uses that token when calling back to the
-- proxy submission API — so submissions are owned by the real authenticated user,
-- not the service account. This is the correct OAuth-native flow.
--
-- plan_mcp_server and get_auth_mode_recommendation are read-only guidance; they
-- don't call the proxy API at all, so passthrough vs none doesn't matter for them —
-- but keeping them consistent means the token is available if needed.
INSERT INTO tool_registry (
    tool_id, name, version, description, schema, upstream_url,
    status, risk_level, risk_score, risk_reasons,
    registered_by, service_name, credential_approach, injection_mode, inject_header, inject_prefix
) VALUES
(
    gen_random_uuid(),
    'plan_mcp_server', '1.0.0',
    'Start the MCP server onboarding flow. Describe what you want to build and get guided questions.',
    '{"type":"object","properties":{"intent":{"type":"string","description":"What should the MCP server do?"}},"required":["intent"]}'::jsonb,
    'http://lab-mcp-self-service:8000/mcp',
    'active', 'low', 5, '["Read-only guidance, no data written"]'::jsonb,
    'lab-seeder', null, null, 'passthrough', null, null
),
(
    gen_random_uuid(),
    'get_auth_mode_recommendation', '1.0.0',
    'Get a recommended authentication injection mode based on answers about the upstream system.',
    '{"type":"object","properties":{"has_upstream_auth":{"type":"boolean"},"same_keycloak":{"type":"boolean"},"upstream_idp_type":{"type":"string","enum":["entra","api_key","oauth"]},"per_user":{"type":"boolean"}},"required":["has_upstream_auth"]}'::jsonb,
    'http://lab-mcp-self-service:8000/mcp',
    'active', 'low', 5, '[]'::jsonb,
    'lab-seeder', null, null, 'passthrough', null, null
),
(
    gen_random_uuid(),
    'submit_mcp_server', '1.0.0',
    'Create and submit an MCP server for automated scan and security team review.',
    '{"type":"object","properties":{"name":{"type":"string"},"description":{"type":"string"},"injection_mode":{"type":"string"},"data_categories":{"type":"array","items":{"type":"string"}},"has_write_ops":{"type":"boolean"},"github_repo_url":{"type":"string"}},"required":["name","description","injection_mode","data_categories","has_write_ops"]}'::jsonb,
    'http://lab-mcp-self-service:8000/mcp',
    'active', 'medium', 30, '["Creates records in server_registry","Triggers git clone and security scan of provided repo"]'::jsonb,
    'lab-seeder', null, null, 'passthrough', null, null
),
(
    gen_random_uuid(),
    'check_submission_status', '1.0.0',
    'Poll the status of an MCP server submission including scan results and reviewer notes.',
    '{"type":"object","properties":{"server_id":{"type":"string","description":"UUID returned by submit_mcp_server"}},"required":["server_id"]}'::jsonb,
    'http://lab-mcp-self-service:8000/mcp',
    'active', 'low', 5, '[]'::jsonb,
    'lab-seeder', null, null, 'passthrough', null, null
),
(
    gen_random_uuid(),
    'get_server_scaffold', '1.0.0',
    'Get starter scaffold code (server.py, requirements.txt, Dockerfile, README) for an MCP server auth mode.',
    '{"type":"object","properties":{"injection_mode":{"type":"string","description":"Auth mode for the scaffold"}},"required":["injection_mode"]}'::jsonb,
    'http://lab-mcp-self-service:8000/mcp',
    'active', 'low', 5, '[]'::jsonb,
    'lab-seeder', null, null, 'passthrough', null, null
)
ON CONFLICT (name, version) DO UPDATE SET
    upstream_url   = EXCLUDED.upstream_url,
    description    = EXCLUDED.description,
    injection_mode = EXCLUDED.injection_mode,
    updated_at     = NOW();

-- ── lab-tickets — KC token exchange to custom RS (Case 4, PRD-0002) ──────────
-- proxy exchanges the user's KC bearer for an aud=lab-tickets exchanged token,
-- then injects it as Authorization: Bearer <exchanged> to lab-mcp-lab-tickets.
-- kc_token_audience drives the exchange audience; the RS validates azp=mcp-proxy.
INSERT INTO tool_registry (
    tool_id, name, version, description, schema, upstream_url,
    status, risk_level, risk_score, risk_reasons,
    registered_by, service_name, credential_approach, injection_mode,
    inject_header, inject_prefix, kc_token_audience
) VALUES (
    gen_random_uuid(),
    'lab-tickets-query', '1.0.0',
    'Lab ticket management via RFC 8693 token exchange (PRD-0002 Case 4). '
    'Proxy exchanges caller''s KC token for aud=lab-tickets; RS validates azp=mcp-proxy.',
    '{"type":"object","properties":{"title":{"type":"string"},"description":{"type":"string"}},"additionalProperties":false}'::jsonb,
    'http://lab-mcp-lab-tickets:8000/mcp',
    'active', 'medium', 30,
    '["Uses RFC 8693 token exchange — proxy acquires a fresh aud=lab-tickets JWT per call","Attribution preserved: sub=caller in the exchanged token"]'::jsonb,
    'lab-seeder', 'lab-tickets', null, 'kc_token_exchange', 'Authorization', 'Bearer', 'lab-tickets'
)
ON CONFLICT (name, version) DO UPDATE SET
    upstream_url        = EXCLUDED.upstream_url,
    service_name        = EXCLUDED.service_name,
    injection_mode      = EXCLUDED.injection_mode,
    inject_header       = EXCLUDED.inject_header,
    inject_prefix       = EXCLUDED.inject_prefix,
    kc_token_audience   = EXCLUDED.kc_token_audience,
    updated_at          = NOW();

-- ── Wazuh MCP — service-account Wazuh API JWT (compose.wazuh.yml overlay) ────
-- Seeded as status='disabled' (overlay not running = service unavailable, not a security block).
-- 'make lab-up' activates it automatically when compose.wazuh.yml is included.
-- injection_mode='service': broker injects Wazuh API JWT as Authorization header.
INSERT INTO tool_registry (
    tool_id, name, version, description, schema, upstream_url,
    status, risk_level, risk_score, risk_reasons,
    registered_by, service_name, credential_approach, injection_mode, inject_header, inject_prefix
) VALUES
(
    gen_random_uuid(),
    'wazuh-siem', '1.0.0',
    'Wazuh SIEM: list alerts, agents, rules, and trigger active responses. Service-account auth (Wazuh API JWT).',
    '{"type":"object","properties":{"tool_name":{"type":"string","enum":["wazuh_cluster_health","wazuh_list_agents","wazuh_get_agent_detail","wazuh_list_alerts","wazuh_search_alerts","wazuh_get_rules","wazuh_list_decoders","wazuh_run_active_response","wazuh_list_ai_alerts"]},"arguments":{"type":"object"}},"required":["tool_name"],"additionalProperties":false}'::jsonb,
    'http://lab-mcp-wazuh:8000/mcp',
    'disabled', 'high', 75,
    '["Direct access to security event data","wazuh_run_active_response can modify system state","Requires admin Wazuh API credentials","Active response disabled by default (ALLOW_ACTIVE_RESPONSE=false)"]'::jsonb,
    'lab-seeder', 'wazuh', 'B', 'service', 'Authorization', 'Bearer '
)
ON CONFLICT (name, version) DO UPDATE SET
    upstream_url        = EXCLUDED.upstream_url,
    service_name        = EXCLUDED.service_name,
    credential_approach = EXCLUDED.credential_approach,
    injection_mode      = EXCLUDED.injection_mode,
    inject_header       = EXCLUDED.inject_header,
    inject_prefix       = EXCLUDED.inject_prefix,
    updated_at          = NOW();
