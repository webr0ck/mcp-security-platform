-- 0009_dedicated_port_to_idp.up.sql — move `dedicated_port` from `servers`
-- to `idp_configs`.
--
-- Resolved model (rs/ARCHITECTURE.md, in mcphub-identity's favour): the
-- port's only job is to publish ONE IDP's RFC 9728 + RFC 8414 metadata, so
-- servers sharing an awkward IDP share that IDP's listener rather than each
-- allocating (and each advertising identical metadata on) their own port.
-- `servers.auth_mode` and `servers.idp_id` are unaffected — a server with
-- `auth_mode = 'dedicated_port'` is reached on the port belonging to its
-- `idp_id`'s `idp_configs` row.

-- ---------------------------------------------------------------------------
-- 1. Drop the old per-server column and the constraints that referenced it.
-- ---------------------------------------------------------------------------
ALTER TABLE servers DROP CONSTRAINT IF EXISTS ck_servers_dedicated_port_matches_mode;
DROP INDEX IF EXISTS uq_servers_dedicated_port_active;
ALTER TABLE servers DROP COLUMN IF EXISTS dedicated_port;

-- ---------------------------------------------------------------------------
-- 2. Add it to idp_configs, with the same range check plus a UNIQUENESS
--    constraint the review specifically asked for: two IDPs must never be
--    assigned the same port, and the database enforces that (not the
--    allocator) now that allocation runs from Ansible, outside this
--    binary's control.
-- ---------------------------------------------------------------------------
ALTER TABLE idp_configs
    ADD COLUMN dedicated_port INTEGER CHECK (dedicated_port IS NULL OR dedicated_port BETWEEN 9000 AND 9100);

-- Partial + unique: only non-deleted rows compete for a port, and NULL
-- (no dedicated port assigned) is allowed on arbitrarily many rows.
CREATE UNIQUE INDEX IF NOT EXISTS uq_idp_configs_dedicated_port_active
    ON idp_configs (dedicated_port) WHERE deleted_at IS NULL AND dedicated_port IS NOT NULL;

-- ---------------------------------------------------------------------------
-- 3. Cross-table invariant: a server declaring `auth_mode = 'dedicated_port'`
--    must resolve to an IDP that actually HAS a port. Neither Postgres CHECK
--    constraints nor a single-table trigger can express "the column on
--    row A must be non-null" as a function of "a different row B, in a
--    different table" — so this needs a trigger function that queries the
--    other table, installed on BOTH tables (whichever side changes last is
--    what must be validated):
--
--    (a) servers BEFORE INSERT/UPDATE: if the new/updated row claims
--        dedicated_port auth, its idp_id must point at a non-deleted
--        idp_configs row that itself has a non-null dedicated_port.
--    (b) idp_configs BEFORE UPDATE: if an update would clear
--        dedicated_port (or soft-delete the row) on an IDP that some
--        active server still depends on for dedicated_port auth, reject
--        it — the whole point of the isolation valve is that removing an
--        IDP's dedicated port must never silently fall a server back to
--        the shared listener.
--
--    Together these make the bad state unreachable through normal SQL
--    (INSERT/UPDATE), which is a strictly stronger guarantee than a
--    startup-time check alone — see repo::servers::
--    find_dedicated_port_misconfigurations for a defense-in-depth
--    auditor/startup-check query on top, for the case a privileged
--    connection bypasses these triggers directly (same threat model as
--    the audit_events append-only guard).
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION fn_check_server_dedicated_port_has_idp_port()
RETURNS TRIGGER AS $$
DECLARE
    idp_port INTEGER;
    idp_deleted TIMESTAMPTZ;
BEGIN
    IF NEW.auth_mode = 'dedicated_port' THEN
        IF NEW.idp_id IS NULL THEN
            RAISE EXCEPTION 'server % declares auth_mode=dedicated_port but has no idp_id', NEW.server_id
                USING ERRCODE = 'check_violation';
        END IF;

        SELECT dedicated_port, deleted_at INTO idp_port, idp_deleted
        FROM idp_configs WHERE idp_id = NEW.idp_id;

        IF NOT FOUND OR idp_deleted IS NOT NULL THEN
            RAISE EXCEPTION 'server % declares auth_mode=dedicated_port but idp_id % does not resolve to an active idp_configs row',
                NEW.server_id, NEW.idp_id
                USING ERRCODE = 'foreign_key_violation';
        END IF;

        IF idp_port IS NULL THEN
            RAISE EXCEPTION 'server % declares auth_mode=dedicated_port but its idp (%) has no dedicated_port assigned — '
                'a dedicated_port server must never silently fall back to the shared listener',
                NEW.server_id, NEW.idp_id
                USING ERRCODE = 'check_violation';
        END IF;
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_servers_check_dedicated_port_has_idp_port
    BEFORE INSERT OR UPDATE ON servers
    FOR EACH ROW EXECUTE FUNCTION fn_check_server_dedicated_port_has_idp_port();

CREATE OR REPLACE FUNCTION fn_check_idp_dedicated_port_still_referenced()
RETURNS TRIGGER AS $$
DECLARE
    dependent_count INTEGER;
BEGIN
    -- Only relevant when a port that WAS set is being cleared, or the row
    -- is being soft-deleted while it still has a port. Nothing to check on
    -- an IDP that never had a dedicated port.
    IF OLD.dedicated_port IS NOT NULL
       AND ((NEW.dedicated_port IS NULL) OR (NEW.deleted_at IS NOT NULL AND OLD.deleted_at IS NULL))
    THEN
        SELECT count(*) INTO dependent_count
        FROM servers
        WHERE idp_id = OLD.idp_id AND auth_mode = 'dedicated_port' AND deleted_at IS NULL;

        IF dependent_count > 0 THEN
            RAISE EXCEPTION 'cannot clear/remove dedicated_port on idp_config % — % active server(s) with '
                'auth_mode=dedicated_port still depend on it (release/reassign them first)',
                OLD.idp_id, dependent_count
                USING ERRCODE = 'foreign_key_violation';
        END IF;
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_idp_configs_check_dedicated_port_still_referenced
    BEFORE UPDATE ON idp_configs
    FOR EACH ROW EXECUTE FUNCTION fn_check_idp_dedicated_port_still_referenced();
