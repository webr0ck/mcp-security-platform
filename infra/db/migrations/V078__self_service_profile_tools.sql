-- =============================================================================
-- V078__self_service_profile_tools.sql
-- The single 'self-service-mcp' tool_registry row seeded by V052 is unroutable:
-- invoke_tool dispatches by exact tool name, but the self-service MCP server
-- only exposes get_profile / enable_mcp / disable_mcp / enable_function /
-- disable_function (see lab/tests/test_self_service_mcp.py). This migration
-- SOFT-DELETES the broken catch-all row and registers the 5 real function names
-- as individual, routable tool_registry rows. Idempotent and safe to re-run.
--
-- NOTE: hard DELETE is impossible here — audit_events.tool_id has an ON DELETE
-- SET NULL FK to tool_registry, and the append-only audit_events immutability
-- guard (fn_audit_events_immutability_guard) rejects the implied UPDATE. So we
-- soft-delete via deleted_at, which every discovery/invoke query already
-- filters on (deleted_at IS NULL). The unique constraint is (name, version).
-- =============================================================================
BEGIN;

-- Soft-delete the unroutable catch-all row (audit-safe; hard DELETE is blocked
-- by the audit-events immutability guard).
UPDATE tool_registry
SET deleted_at = now(), status = 'disabled', updated_at = now()
WHERE name = 'self-service-mcp' AND deleted_at IS NULL;

INSERT INTO tool_registry
  (tool_id, name, version, description, schema, upstream_url, status, risk_level,
   risk_score, risk_reasons, registered_by, service_name, credential_approach,
   injection_mode, inject_header, inject_prefix, metadata)
VALUES
  (gen_random_uuid(), 'get_profile', '1.0.0',
   'List a profile''s MCP/function permissions.',
   '{"type":"object","properties":{"mcp_name":{"type":"string"},"target_profile":{"type":"string"}},"additionalProperties":false}'::jsonb,
   'http://self-service:8000/mcp', 'active', 'low', 10, '["Reads mcp_profiles"]'::jsonb,
   'system:default-seed', null, 'A', 'none', null, null, '{}'::jsonb),
  (gen_random_uuid(), 'enable_mcp', '1.0.0',
   'Enable an MCP for a profile.',
   '{"type":"object","properties":{"mcp_name":{"type":"string"},"target_profile":{"type":"string"}},"required":["mcp_name"],"additionalProperties":false}'::jsonb,
   'http://self-service:8000/mcp', 'active', 'low', 10, '["Writes mcp_profiles"]'::jsonb,
   'system:default-seed', null, 'A', 'none', null, null, '{}'::jsonb),
  (gen_random_uuid(), 'disable_mcp', '1.0.0',
   'Disable an MCP for a profile.',
   '{"type":"object","properties":{"mcp_name":{"type":"string"},"target_profile":{"type":"string"}},"required":["mcp_name"],"additionalProperties":false}'::jsonb,
   'http://self-service:8000/mcp', 'active', 'low', 10, '["Writes mcp_profiles"]'::jsonb,
   'system:default-seed', null, 'A', 'none', null, null, '{}'::jsonb),
  (gen_random_uuid(), 'enable_function', '1.0.0',
   'Enable a specific function of an MCP for a profile.',
   '{"type":"object","properties":{"mcp_name":{"type":"string"},"function_name":{"type":"string"},"target_profile":{"type":"string"}},"required":["mcp_name","function_name"],"additionalProperties":false}'::jsonb,
   'http://self-service:8000/mcp', 'active', 'low', 10, '["Writes mcp_profiles"]'::jsonb,
   'system:default-seed', null, 'A', 'none', null, null, '{}'::jsonb),
  (gen_random_uuid(), 'disable_function', '1.0.0',
   'Disable a specific function of an MCP for a profile.',
   '{"type":"object","properties":{"mcp_name":{"type":"string"},"function_name":{"type":"string"},"target_profile":{"type":"string"}},"required":["mcp_name","function_name"],"additionalProperties":false}'::jsonb,
   'http://self-service:8000/mcp', 'active', 'low', 10, '["Writes mcp_profiles"]'::jsonb,
   'system:default-seed', null, 'A', 'none', null, null, '{}'::jsonb)
ON CONFLICT (name, version) DO NOTHING;

-- Link the 5 new rows to the self-service server_registry row (upstream_url match).
UPDATE tool_registry t
SET server_id = s.server_id, updated_at = now()
FROM server_registry s
WHERE t.deleted_at IS NULL
  AND t.upstream_url = s.upstream_url
  AND s.name = 'self-service'
  AND t.name IN ('get_profile', 'enable_mcp', 'disable_mcp', 'enable_function', 'disable_function');

COMMIT;

-- =============================================================================
-- Down migration (irreversible by design, documented):
-- Re-inserting the original 'self-service-mcp' catch-all row would resurrect
-- the unroutable state this migration fixes, and any real profile_mcp_bindings
-- / audit history referencing the 5 new tool_ids would be orphaned by a blind
-- delete. If a rollback is genuinely needed, restore from a pre-V078 backup
-- rather than reversing forward — DELETE FROM tool_registry WHERE name IN
-- ('get_profile','enable_mcp','disable_mcp','enable_function','disable_function');
-- is available as a manual, reviewed action but is not run automatically here.
-- =============================================================================
