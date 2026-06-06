-- V023__tool_server_fk.sql
-- 6.2 — discovery==invoke enforcement.
-- Link tools to the server they belong to so the invoke path can enforce
-- per-server entitlement (services/entitlement.py:enforce_tool_entitlement),
-- the same resolver the catalog uses for discovery.
--
-- Nullable + ON DELETE SET NULL: existing/unlinked tools keep server_id = NULL
-- and remain governed by OPA only (backward compatible). Once a tool is linked
-- to a server, invocation requires the caller to be entitled to that server,
-- with NO role exception (admin included).

ALTER TABLE tool_registry
    ADD COLUMN IF NOT EXISTS server_id UUID
        REFERENCES server_registry(server_id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_tool_registry_server_id
    ON tool_registry (server_id) WHERE server_id IS NOT NULL;

-- INV-011: proxy_app may read the new column (it already holds SELECT on
-- tool_registry from V001/V003; re-assert idempotently). It must NOT gain new
-- write privileges from this migration — linking tools to servers is an admin
-- registration action, not a runtime-proxy write.
DO $$
BEGIN
    IF EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'proxy_app') THEN
        GRANT SELECT ON tool_registry TO proxy_app;
    END IF;
END
$$;
