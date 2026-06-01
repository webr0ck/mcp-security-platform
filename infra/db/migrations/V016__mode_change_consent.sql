-- V016__mode_change_consent.sql
-- Owner consent tokens for mode/credential changes (D3 dual-control)
-- Crypto binding added in Plan 7; this migration creates the structure.
CREATE TABLE IF NOT EXISTS mode_change_consent (
    jti             TEXT        PRIMARY KEY,
    server_id       UUID        NOT NULL REFERENCES server_registry(server_id) ON DELETE CASCADE,
    old_mode        TEXT        NOT NULL,
    new_mode        TEXT        NOT NULL,
    old_cred_ref    TEXT,
    new_cred_ref    TEXT,
    owner_sub       TEXT        NOT NULL,
    payload_hash    TEXT        NOT NULL,
    issued_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at      TIMESTAMPTZ NOT NULL,
    consumed_at     TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_consent_server_unconsumed
    ON mode_change_consent (server_id, consumed_at)
    WHERE consumed_at IS NULL;

GRANT SELECT, INSERT, UPDATE ON mode_change_consent TO proxy_app;
