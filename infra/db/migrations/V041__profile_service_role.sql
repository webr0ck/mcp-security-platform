-- V041__profile_service_role.sql
-- Add 'profile_service' role for service accounts that proxy MCP profile
-- reads/writes on behalf of users (e.g. lab-self-service).
-- Narrower than 'admin': allows cross-user profile CRUD only;
-- no access to named-profile management or other admin capabilities.
-- See proxy/app/routers/profiles.py:_PROFILE_SERVICE_ROLES.
ALTER TABLE role_assignments
    DROP CONSTRAINT IF EXISTS role_assignments_role_check;

ALTER TABLE role_assignments
    ADD CONSTRAINT role_assignments_role_check
    CHECK (role IN (
        -- legacy roles (kept for backward compat)
        'admin', 'agent', 'readonly', 'auditor',
        -- v3 roles
        'platform_admin', 'server_owner', 'manager', 'user',
        -- service-account roles
        'profile_service'
    ));
