-- =============================================================================
-- lab/seeder/sql/roles.sql
-- Inserts test RBAC assignments for lab users.
--
-- SCHEMA NOTE: The current migration set (V001–V007) does not define a
-- standalone `client_roles` table. RBAC role membership is currently stored
-- in the `roles` TEXT[] column of the `api_keys` table (V001).
--
-- If a dedicated client_roles table is added in a future migration, replace
-- the INSERT below with the appropriate statement targeting that table.
-- Until then, this file serves as a placeholder that the seeder loads; the
-- seed.py script skips it gracefully if the table does not exist.
-- =============================================================================

-- Placeholder: insert lab client API key role assignments into api_keys.
-- The seeder creates real key rows via seed.py; this SQL is advisory only.
--
-- INSERT INTO client_roles (client_id, role)
-- VALUES
--     ('alice@corp', 'agent'),
--     ('bob@corp',   'auditor')
-- ON CONFLICT DO NOTHING;

-- Actual idempotent role seed using api_keys (existing schema):
-- Inserts placeholder-hash keys for alice and bob with appropriate roles.
-- key_hash values are 64-char hex strings that satisfy the CHECK constraint.
-- These are test credentials only — not valid for production use.
INSERT INTO api_keys (
    key_id,
    key_hash,
    client_id,
    roles,
    rate_limit_rpm,
    created_by
)
VALUES
(
    '00000000-0000-0000-0001-000000000001',
    'a1ce0000000000000000000000000000000000000000000000000000000000a1',
    'alice@corp',
    '{"agent"}',
    120,
    'lab-seeder'
),
(
    '00000000-0000-0000-0002-000000000002',
    'b0b00000000000000000000000000000000000000000000000000000000000b0',
    'bob@corp',
    '{"agent"}',
    120,
    'lab-seeder'
)
ON CONFLICT (key_id) DO NOTHING;

-- Lab user role assignments. Table DDL is owned by V008 migration.
-- V050 made role_assignments append-only (grant/revoke are both INSERT-only
-- event rows; the RBAC admin panel needs to re-grant a role after a revoke,
-- which the old UNIQUE(client_id, role) constraint would have blocked) — so
-- there's no longer a matching constraint for ON CONFLICT. Guard with
-- NOT EXISTS instead: only seed a role if this client has no event row for
-- it yet at all (first run), never overwrite/duplicate on reseed.
INSERT INTO role_assignments (client_id, role, granted_by)
SELECT v.client_id, v.role, 'lab-seeder'
FROM (VALUES
    ('alice@corp', 'agent'),
    ('bob@corp',   'agent'),
    ('bootstrap',  'admin')
) AS v(client_id, role)
WHERE NOT EXISTS (
    SELECT 1 FROM role_assignments r
    WHERE r.client_id = v.client_id AND r.role = v.role
);

-- OPA client grants — max_risk_level drives the risk_level_within_threshold gate.
-- alice gets 'critical' so all lab tools are reachable; add per-user rows for
-- tighter lab scenarios.
INSERT INTO client_grants (client_id, max_risk_level, allowed_tools, allowed_tags, granted_by)
VALUES
    ('alice@corp', 'critical', '[]'::jsonb, '[]'::jsonb, 'lab-seeder'),
    ('bob@corp',   'medium',   '[]'::jsonb, '[]'::jsonb, 'lab-seeder')
ON CONFLICT (client_id) DO UPDATE
    SET max_risk_level = EXCLUDED.max_risk_level,
        updated_at     = now();
