-- 0001_core.down.sql — reverse of 0001_core.up.sql

DROP TRIGGER IF EXISTS trg_tool_registry_block_delete ON tool_registry;
DROP TRIGGER IF EXISTS trg_tool_registry_updated_at ON tool_registry;
DROP TABLE IF EXISTS tool_registry;
DROP TYPE IF EXISTS tool_status_enum;

DROP TRIGGER IF EXISTS trg_servers_updated_at ON servers;
DROP TABLE IF EXISTS servers;
DROP TYPE IF EXISTS auth_mode_enum;
DROP TYPE IF EXISTS server_status_enum;

DROP TRIGGER IF EXISTS trg_idp_configs_updated_at ON idp_configs;
DROP TABLE IF EXISTS idp_configs;

DROP TABLE IF EXISTS role_grants;
DROP TYPE IF EXISTS role_enum;

DROP FUNCTION IF EXISTS fn_block_hard_delete();
DROP FUNCTION IF EXISTS fn_set_updated_at();
