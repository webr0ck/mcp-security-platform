-- V051__role_assignments_security_reviewer.sql
-- Add 'security_reviewer' to the allowed values for role_assignments.role.
--
-- Gap: security_reviewer was added to Keycloak, oidc_browser.py::_ROLE_MAP,
-- and admin_grants.py::_VALID_RBAC_ROLES in a prior change, but the DB-level
-- CHECK constraint (role_assignments_role_check, V017) was never widened to
-- match — so granting it via the RBAC panel or KC-login sync always failed
-- with CheckViolationError, even though every application-layer check
-- already accepted it.
ALTER TABLE role_assignments
    DROP CONSTRAINT IF EXISTS role_assignments_role_check;

ALTER TABLE role_assignments
    ADD CONSTRAINT role_assignments_role_check
    CHECK (role IN (
        -- legacy roles (kept for backward compat)
        'admin', 'agent', 'readonly', 'auditor',
        -- v3 roles
        'platform_admin', 'server_owner', 'manager', 'user',
        'profile_service',
        -- narrow, submission-review-only role (this migration)
        'security_reviewer'
    ));
