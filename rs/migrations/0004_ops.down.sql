-- 0004_ops.down.sql — reverse of 0004_ops.up.sql
--
-- Role grants/revokes are not reversed individually; dropping the role
-- (if unused elsewhere) is sufficient and avoids partial-privilege states.

DROP TRIGGER IF EXISTS trg_rate_limit_config_updated_at ON rate_limit_config;
DROP TABLE IF EXISTS rate_limit_config;

DROP TABLE IF EXISTS quarantine_events;
DROP TYPE IF EXISTS quarantine_target_enum;

DO $$
BEGIN
    IF EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'mcphub_app') THEN
        DROP OWNED BY mcphub_app;
        DROP ROLE mcphub_app;
    END IF;
END
$$;
