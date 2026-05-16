-- =============================================================================
-- integration_seed.sql — fixture data for the integration test suite.
--
-- Referenced by ci/test-jobs/integration-tests.yml ("Seed integration test
-- fixtures" step). Previously MISSING, which made the integration CI job fail
-- at the psql seed step (REVIEW-2026-05-16.md P1.4).
--
-- Idempotent: safe to run repeatedly after migrations V001..V009.
-- Tools / clients match the constants in:
--   proxy/tests/integration/test_invoke.py
--   proxy/tests/integration/test_audit_completeness.py
-- OPA grants for these identities live in policies/rego/data.json.
-- =============================================================================

-- Tools ----------------------------------------------------------------------
INSERT INTO tool_registry
    (tool_id, name, version, description, schema, upstream_url,
     status, risk_score, risk_level, registered_by)
VALUES
    ('00000000-0000-0000-0000-000000000010', 'active-low-risk-tool', '1.0.0',
     'Integration fixture: active low-risk tool.',
     '{"type":"object","properties":{"path":{"type":"string"}}}'::jsonb,
     'http://upstream-mock:9000/active-low-risk-tool',
     'active', 5, 'low', 'integration-seed'),
    ('00000000-0000-0000-0000-000000000020', 'quarantined-tool', '1.0.0',
     'Integration fixture: quarantined tool (INV-005).',
     '{"type":"object","properties":{"path":{"type":"string"}}}'::jsonb,
     'http://upstream-mock:9000/quarantined-tool',
     'quarantined', 95, 'critical', 'integration-seed')
ON CONFLICT (name, version) DO UPDATE
    SET status = EXCLUDED.status,
        risk_level = EXCLUDED.risk_level,
        deleted_at = NULL;

-- Role assignments (mTLS CN == client_id for these test clients) --------------
INSERT INTO role_assignments (client_id, role, granted_by) VALUES
    ('test-agent-client',   'agent',   'integration-seed'),
    ('test-agent-no-grant', 'agent',   'integration-seed'),
    ('test-admin-client',   'admin',   'integration-seed'),
    ('test-auditor-client', 'auditor', 'integration-seed')
ON CONFLICT (client_id, role) DO NOTHING;
