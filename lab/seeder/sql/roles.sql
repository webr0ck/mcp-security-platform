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
    '{"auditor"}',
    120,
    'lab-seeder'
)
ON CONFLICT (key_id) DO NOTHING;

-- Lab user role assignments. Table DDL is owned by V008 migration.
INSERT INTO role_assignments (client_id, role, granted_by)
VALUES
    ('alice@corp', 'agent',   'lab-seeder'),
    ('bob@corp',   'auditor', 'lab-seeder'),
    ('bootstrap',  'admin',   'lab-seeder')
ON CONFLICT (client_id, role) DO NOTHING;
