-- V048__server_debug_mode_maintainers.sql
-- Server debug/maintenance mode + maintainers list.
--
-- Debug mode: an owner or maintainer can lock a server down to
-- debug/troubleshooting so ONLY the owner and maintainers may invoke its
-- tools. Every other caller is denied (SERVER_IN_MAINTENANCE), not just
-- rate-limited or warned — this is a hard access gate, enforced in
-- services/invocation.py alongside the existing INV-005 quarantine gate.
--
-- Maintainers: up to 2 additional principals (besides owner_sub) who may
-- also toggle debug mode. Capped at 2 by CHECK constraint (defense in depth
-- — the API layer also enforces this).

ALTER TABLE server_registry
    ADD COLUMN IF NOT EXISTS maintainers TEXT[] NOT NULL DEFAULT '{}',
    ADD COLUMN IF NOT EXISTS debug_mode BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS debug_enabled_by TEXT,
    ADD COLUMN IF NOT EXISTS debug_enabled_at TIMESTAMPTZ;

ALTER TABLE server_registry
    ADD CONSTRAINT server_registry_maintainers_max_2
        CHECK (array_length(maintainers, 1) IS NULL OR array_length(maintainers, 1) <= 2);

-- Consistency: debug_mode=true always has an actor + timestamp attached
-- (who put this server into maintenance, and when) so the audit trail is
-- never ambiguous; debug_mode=false always clears both.
ALTER TABLE server_registry
    ADD CONSTRAINT server_registry_debug_consistency
        CHECK (
            (debug_mode = FALSE AND debug_enabled_by IS NULL AND debug_enabled_at IS NULL) OR
            (debug_mode = TRUE  AND debug_enabled_by IS NOT NULL AND debug_enabled_at IS NOT NULL)
        );

CREATE INDEX IF NOT EXISTS idx_server_registry_debug_mode
    ON server_registry (debug_mode) WHERE debug_mode = TRUE;

-- INV-011: proxy_app already holds SELECT/INSERT/UPDATE on server_registry (V014).
DO $$
BEGIN
    IF EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'proxy_app') THEN
        GRANT SELECT, UPDATE ON server_registry TO proxy_app;
    END IF;
END
$$;
