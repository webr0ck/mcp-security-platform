-- V053__server_public_to_authenticated.sql
-- PRD-0005 R-3: opt-in, per-server "reachable by any authenticated principal".
--
-- This is NOT a global/wildcard entitlement and NOT an admin role bypass. It is
-- a per-row property an admin explicitly sets; access is still granted per-server
-- by an audited admin action, so deny-by-default and audit honesty are preserved
-- (a public-server invoke is logged with entitlement_reason='public_server').
--
-- Write-op safety (3-critic F-4): a write-capable server can NEVER be public.
-- Enforced at the DB with a CHECK, in addition to the resolver gate, so a UI bug
-- or a compromised admin session still cannot expose a write-op server to everyone.
-- has_write_ops is NOT NULL DEFAULT false (verified), so the CHECK is total.

ALTER TABLE server_registry
    ADD COLUMN IF NOT EXISTS public_to_authenticated BOOLEAN NOT NULL DEFAULT false;

ALTER TABLE server_registry
    DROP CONSTRAINT IF EXISTS ck_public_not_write_ops;
ALTER TABLE server_registry
    ADD CONSTRAINT ck_public_not_write_ops
    CHECK (public_to_authenticated = false OR has_write_ops = false);

COMMENT ON COLUMN server_registry.public_to_authenticated IS
    'PRD-0005 R-3: any authenticated principal may invoke this server (read-only servers only; CHECK forbids write-op). Not a global grant — per-row admin opt-in, audited as entitlement_reason=public_server.';

-- Seed: the self-service MCP is the one server intended to be reachable by all
-- authenticated users. Guarded by has_write_ops=false so the CHECK cannot fail.
UPDATE server_registry
   SET public_to_authenticated = true
 WHERE name = 'lab-self-service'
   AND has_write_ops = false
   AND deleted_at IS NULL;
