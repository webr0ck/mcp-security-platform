-- V017__role_assignments_new_roles.sql
-- Add new v3 roles to the allowed values for role_assignments.role.
-- Existing check constraint must be replaced to include new roles.
-- Backward compat: 'admin', 'agent', 'readonly', 'auditor' remain valid.
ALTER TABLE role_assignments
    DROP CONSTRAINT IF EXISTS role_assignments_role_check;

ALTER TABLE role_assignments
    ADD CONSTRAINT role_assignments_role_check
    CHECK (role IN (
        -- legacy roles (kept for backward compat)
        'admin', 'agent', 'readonly', 'auditor',
        -- v3 roles
        'platform_admin', 'server_owner', 'manager', 'user'
    ));
