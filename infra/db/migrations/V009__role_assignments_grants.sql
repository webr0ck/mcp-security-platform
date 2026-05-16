-- =============================================================================
-- V009__role_assignments_grants.sql
--
-- CB-005 fix. V008 created `role_assignments` but added NO grants. V003's
-- grants only cover tables that existed when V003 ran; PostgreSQL does not
-- propagate grants to tables created by later migrations. As a result
-- `proxy_app` had no privilege on `role_assignments`, every call to
-- `_load_roles()` (proxy/app/middleware/auth.py) hit `permission denied`,
-- the broad `except` swallowed it, and EVERY authenticated client resolved
-- to zero roles -> 403 on every protected endpoint in a fresh deployment.
--
-- This migration grants the least privilege the proxy actually needs and
-- explicitly revokes the rest, keeping `role_assignments` consistent with
-- the INV-011 single-writer / no-hard-delete model.
--
-- Idempotent: GRANT/REVOKE are idempotent in PostgreSQL; the role-existence
-- guard mirrors V003's DO-block style.
-- =============================================================================

DO $$
BEGIN
    IF EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'proxy_app') THEN
        -- proxy_app reads roles on every authenticated request and may seed
        -- initial assignments; it must never mutate or hard-delete them.
        GRANT SELECT, INSERT ON role_assignments TO proxy_app;
        REVOKE UPDATE, DELETE ON role_assignments FROM proxy_app;
    END IF;
END
$$;
