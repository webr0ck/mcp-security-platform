-- 0007_drop_redundant_grants_index.down.sql — reverse of
-- 0007_drop_redundant_grants_index.up.sql: recreate the (redundant but
-- harmless to have back) index, for symmetry with this project's
-- every-migration-has-a-down-script convention.
CREATE INDEX IF NOT EXISTS idx_grants_principal
    ON grants (principal_id);
