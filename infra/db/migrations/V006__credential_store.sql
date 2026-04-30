-- V006__credential_store.sql
-- Stores Approach A encrypted refresh tokens (one row per user+service).
-- Approach B tokens are never persisted — in-memory only.
-- encrypted_blob = nonce(12B) || AES-256-GCM ciphertext of refresh_token.
-- KEK is derived at runtime from KMS; never stored here.

CREATE TABLE IF NOT EXISTS credential_store (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_sub        TEXT        NOT NULL,
    service         TEXT        NOT NULL,
    encrypted_blob  BYTEA       NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_credential_store_user_service UNIQUE (user_sub, service)
);

CREATE TRIGGER trg_credential_store_updated_at
    BEFORE UPDATE ON credential_store
    FOR EACH ROW EXECUTE FUNCTION fn_set_updated_at();

GRANT SELECT, INSERT, UPDATE, DELETE ON credential_store TO proxy_app;
