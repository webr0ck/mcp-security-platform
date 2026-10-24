-- 0009_dedicated_port_to_idp.down.sql — reverse of
-- 0009_dedicated_port_to_idp.up.sql.
--
-- NOTE: this is a schema-only revert, not a data-preserving one (unlike
-- 0003_audit's down-script, `servers` is not an append-only compliance
-- artifact). Any `dedicated_port` values assigned on `idp_configs` are
-- lost; `servers.dedicated_port` comes back NULL for every row, and any
-- server left in `auth_mode = 'dedicated_port'` will need its port
-- reassigned manually post-revert.

DROP TRIGGER IF EXISTS trg_idp_configs_check_dedicated_port_still_referenced ON idp_configs;
DROP FUNCTION IF EXISTS fn_check_idp_dedicated_port_still_referenced();

DROP TRIGGER IF EXISTS trg_servers_check_dedicated_port_has_idp_port ON servers;
DROP FUNCTION IF EXISTS fn_check_server_dedicated_port_has_idp_port();

DROP INDEX IF EXISTS uq_idp_configs_dedicated_port_active;
ALTER TABLE idp_configs DROP COLUMN IF EXISTS dedicated_port;

ALTER TABLE servers ADD COLUMN dedicated_port INTEGER
    CHECK (dedicated_port IS NULL OR dedicated_port BETWEEN 9000 AND 9100);

CREATE UNIQUE INDEX IF NOT EXISTS uq_servers_dedicated_port_active
    ON servers (dedicated_port) WHERE deleted_at IS NULL AND dedicated_port IS NOT NULL;

ALTER TABLE servers
    ADD CONSTRAINT ck_servers_dedicated_port_matches_mode CHECK (
        (auth_mode = 'dedicated_port' AND dedicated_port IS NOT NULL) OR
        (auth_mode <> 'dedicated_port' AND dedicated_port IS NULL)
    );
