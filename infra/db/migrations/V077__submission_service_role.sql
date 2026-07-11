-- V077__submission_service_role.sql
-- Add 'submission_service' role for service accounts that submit MCP server
-- registrations on behalf of a real user (e.g. lab-self-service, via the
-- submit_mcp_server tool). Grants only the ability to present a trusted
-- X-On-Behalf-Of: <sub> header to the submissions API for owner_sub
-- attribution — narrower than 'admin', mirrors 'profile_service' (V041) for
-- the identical cross-principal delegation problem.
-- See proxy/app/routers/submission.py:_ON_BEHALF_OF_ROLES, ARCHITECTURE.md §5.5.
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
        -- narrow, submission-review-only role (V051)
        'security_reviewer',
        -- narrow, on-behalf-of-submission-only role (this migration)
        'submission_service'
    ));
