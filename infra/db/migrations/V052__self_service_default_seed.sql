-- =============================================================================
-- V052__self_service_default_seed.sql
-- Promotes self-service from a lab-only demo backend to a default platform
-- server: seeds its server_registry row and all ten tool_registry rows
-- (six existing submitter tools + four new reviewer tools), idempotently.
--
-- DEPLOY-TIME ACTION REQUIRED: upstream_allowlist_entry below is a placeholder
-- (matches the __OIDC_ISSUER_PLACEHOLDER__ convention in V002__rbac_seed.sql).
-- The invoke-time DNS-rebind/TOCTOU guard (proxy/app/services/invocation.py)
-- treats a server-linked tool's upstream as "public" unless its server_registry
-- row has an upstream_allowlist_entry covering the actual Docker bridge subnet
-- the self-service container resolves to. Find it after `docker compose up`:
--   docker network inspect mcp-security-platform_proxy-self-service-net \
--     --format '{{range .IPAM.Config}}{{.Subnet}}{{end}}'
-- then:
--   UPDATE server_registry SET upstream_allowlist_entry = '<that subnet>'
--   WHERE name = 'self-service';
-- Self-service tools will 403 with upstream_revalidation_failed until this is
-- set correctly for your deployment's actual network.
-- =============================================================================
BEGIN;

INSERT INTO server_registry
    (name, upstream_url, status, owner_sub, injection_mode, custody_mode,
     trust_tier, trust_tier_label, upstream_allowlist_entry, url_allowlist_checked,
     platform_managed_creds)
VALUES
    ('self-service', 'http://self-service:8000/mcp', 'approved', 'system:default-seed',
     'none', 'session_suk', 2, 'internal',
     '__SELF_SERVICE_UPSTREAM_CIDR_PLACEHOLDER__', false, false)
ON CONFLICT (name) DO UPDATE
    SET status = 'approved', updated_at = now();

INSERT INTO tool_registry (
    tool_id, name, version, description, schema, upstream_url,
    status, risk_level, risk_score, risk_reasons,
    registered_by, service_name, credential_approach, injection_mode,
    inject_header, inject_prefix, metadata
) VALUES
(
    gen_random_uuid(), 'self-service-mcp', '1.0.0',
    'Per-identity MCP permission management: list, enable/disable MCPs and functions per profile.',
    '{"type":"object","properties":{"mcp_name":{"type":"string"},"function_name":{"type":"string"},"target_profile":{"type":"string"}},"additionalProperties":false}'::jsonb,
    'http://self-service:8000/mcp',
    'active', 'low', 10, '["Manages per-user access grants","Writes to mcp_profiles table"]'::jsonb,
    'system:default-seed', null, 'A', 'none', null, null, '{}'::jsonb
),
(
    gen_random_uuid(), 'plan_mcp_server', '1.0.0',
    'Start the MCP server onboarding flow. Describe what you want to build and get guided questions.',
    '{"type":"object","properties":{"intent":{"type":"string","description":"What should the MCP server do?"}},"required":["intent"]}'::jsonb,
    'http://self-service:8000/mcp',
    'active', 'low', 5, '["Read-only guidance, no data written"]'::jsonb,
    'system:default-seed', null, null, 'passthrough', null, null, '{}'::jsonb
),
(
    gen_random_uuid(), 'get_auth_mode_recommendation', '1.0.0',
    'Get a recommended authentication injection mode based on answers about the upstream system.',
    '{"type":"object","properties":{"has_upstream_auth":{"type":"boolean"},"same_keycloak":{"type":"boolean"},"upstream_idp_type":{"type":"string","enum":["entra","api_key","oauth"]},"per_user":{"type":"boolean"}},"required":["has_upstream_auth"]}'::jsonb,
    'http://self-service:8000/mcp',
    'active', 'low', 5, '[]'::jsonb,
    'system:default-seed', null, null, 'passthrough', null, null, '{}'::jsonb
),
(
    gen_random_uuid(), 'submit_mcp_server', '1.0.0',
    'Create and submit an MCP server for automated scan and security team review.',
    '{"type":"object","properties":{"name":{"type":"string"},"description":{"type":"string"},"injection_mode":{"type":"string"},"data_categories":{"type":"array","items":{"type":"string"}},"has_write_ops":{"type":"boolean"},"github_repo_url":{"type":"string"}},"required":["name","description","injection_mode","data_categories","has_write_ops"]}'::jsonb,
    'http://self-service:8000/mcp',
    'active', 'medium', 30, '["Creates records in server_registry","Triggers git clone and security scan of provided repo"]'::jsonb,
    'system:default-seed', null, null, 'passthrough', null, null, '{}'::jsonb
),
(
    gen_random_uuid(), 'check_submission_status', '1.0.0',
    'Poll the status of an MCP server submission including scan results and reviewer notes.',
    '{"type":"object","properties":{"server_id":{"type":"string","description":"UUID returned by submit_mcp_server"}},"required":["server_id"]}'::jsonb,
    'http://self-service:8000/mcp',
    'active', 'low', 5, '[]'::jsonb,
    'system:default-seed', null, null, 'passthrough', null, null, '{}'::jsonb
),
(
    gen_random_uuid(), 'get_server_scaffold', '1.0.0',
    'Get starter scaffold code (server.py, requirements.txt, Dockerfile, README) for an MCP server auth mode.',
    '{"type":"object","properties":{"injection_mode":{"type":"string","description":"Auth mode for the scaffold"}},"required":["injection_mode"]}'::jsonb,
    'http://self-service:8000/mcp',
    'active', 'low', 5, '[]'::jsonb,
    'system:default-seed', null, null, 'passthrough', null, null, '{}'::jsonb
),
-- ── Reviewer tools — required_roles restricts tools/list visibility ─────────
(
    gen_random_uuid(), 'list_pending_reviews', '1.0.0',
    'List MCP server submissions awaiting security review.',
    '{"type":"object","properties":{},"additionalProperties":false}'::jsonb,
    'http://self-service:8000/mcp',
    'active', 'low', 5, '[]'::jsonb,
    'system:default-seed', null, null, 'passthrough', null, null,
    '{"required_roles": ["admin", "platform_admin", "security_auditor", "auditor", "security_reviewer"]}'::jsonb
),
(
    gen_random_uuid(), 'review_submission', '1.0.0',
    'Full review detail for one submission: config, scan/SBOM report, and source code file tree/contents.',
    '{"type":"object","properties":{"server_id":{"type":"string"}},"required":["server_id"]}'::jsonb,
    'http://self-service:8000/mcp',
    'active', 'low', 10, '["Clones and reads submitted source code"]'::jsonb,
    'system:default-seed', null, null, 'passthrough', null, null,
    '{"required_roles": ["admin", "platform_admin", "security_auditor", "auditor", "security_reviewer"]}'::jsonb
),
(
    gen_random_uuid(), 'approve_submission', '1.0.0',
    'Approve an MCP server submission that has passed scan and is awaiting review.',
    '{"type":"object","properties":{"server_id":{"type":"string"},"notes":{"type":"string"}},"required":["server_id"]}'::jsonb,
    'http://self-service:8000/mcp',
    'active', 'medium', 20, '["Mutates server_registry.submission_status"]'::jsonb,
    'system:default-seed', null, null, 'passthrough', null, null,
    '{"required_roles": ["admin", "platform_admin", "security_reviewer"]}'::jsonb
),
(
    gen_random_uuid(), 'reject_submission', '1.0.0',
    'Permanently reject an MCP server submission.',
    '{"type":"object","properties":{"server_id":{"type":"string"},"notes":{"type":"string"}},"required":["server_id"]}'::jsonb,
    'http://self-service:8000/mcp',
    'active', 'medium', 20, '["Mutates server_registry.submission_status"]'::jsonb,
    'system:default-seed', null, null, 'passthrough', null, null,
    '{"required_roles": ["admin", "platform_admin", "security_reviewer"]}'::jsonb
)
ON CONFLICT (name, version) DO UPDATE SET
    upstream_url   = EXCLUDED.upstream_url,
    description    = EXCLUDED.description,
    injection_mode = EXCLUDED.injection_mode,
    metadata       = EXCLUDED.metadata,
    updated_at     = now();

-- Link each tool to the self-service server by matching upstream_url. Not
-- gated on t.server_id IS NULL: the preceding INSERT...ON CONFLICT DO UPDATE
-- rewrites upstream_url to this exact value for all ten tool_registry rows
-- this migration owns (the six pre-existing self-service tools included),
-- so this re-links any row already pointing at a stale server_registry row
-- (e.g. the legacy lab-only 'lab-self-service' row) as well as brand-new
-- rows. Safe and idempotent to re-run.
UPDATE tool_registry t
SET server_id = s.server_id, updated_at = now()
FROM server_registry s
WHERE t.deleted_at IS NULL
  AND t.upstream_url = s.upstream_url
  AND s.name = 'self-service';

COMMIT;
