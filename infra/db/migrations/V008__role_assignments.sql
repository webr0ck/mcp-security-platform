-- =============================================================================
-- V008__role_assignments.sql
--
-- Adds the `role_assignments` table queried by the proxy auth middleware
-- (`_load_roles` in proxy/app/middleware/auth.py).
--
-- Previously this table was created opportunistically by the lab seeder, which
-- meant fresh non-lab deployments were silently broken: every authenticated
-- request fell through the `except` in `_load_roles`, returning an empty role
-- list and producing 403 on every protected endpoint.
--
-- Schema notes:
--   - One row per (client_id, role) pair; UNIQUE INDEX enforces no duplicates.
--   - `granted_by` is intentionally TEXT (not FK) so external auditors / IdPs
--     can be referenced without a prior row.
--   - `expires_at` NULL == permanent; the auth middleware honours it.
-- =============================================================================

CREATE TABLE IF NOT EXISTS role_assignments (
    assignment_id   UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id       TEXT         NOT NULL,
    role            TEXT         NOT NULL,
    granted_by      TEXT         NOT NULL DEFAULT 'system',
    expires_at      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_role_assignments_client_role
    ON role_assignments (client_id, role);

CREATE INDEX IF NOT EXISTS idx_role_assignments_client_id
    ON role_assignments (client_id);
