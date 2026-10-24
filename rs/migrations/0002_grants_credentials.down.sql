-- 0002_grants_credentials.down.sql — reverse of 0002_grants_credentials.up.sql

ALTER TABLE idp_configs DROP CONSTRAINT IF EXISTS fk_idp_configs_client_secret_credential;

DROP TRIGGER IF EXISTS trg_credentials_updated_at ON credentials;
DROP TABLE IF EXISTS credentials;

DROP TRIGGER IF EXISTS trg_grants_updated_at ON grants;
DROP TABLE IF EXISTS grants;
