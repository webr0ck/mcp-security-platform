-- V019: Profile tokens — typed, bound, short-lived selectors for principal→server binding.
-- A profile token is a signed (server-key) claim set that lets a client prove:
--   "I am <typed_principal> and I am entitled to reach <server_id> with role <role>"
-- without re-doing full auth/entitlement checks on every MCP sub-request.

CREATE TABLE IF NOT EXISTS profile_tokens (
    token_id        UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    jti             TEXT        NOT NULL UNIQUE,   -- JWT ID (sha256 of the signed token)
    principal_type  TEXT        NOT NULL REFERENCES principal_type_enum (value),
    principal_id    TEXT        NOT NULL,          -- typed namespaced id
    server_id       UUID        NOT NULL REFERENCES server_registry (server_id) ON DELETE CASCADE,
    audience        TEXT        NOT NULL,          -- server upstream_url (bound)
    role            TEXT        NOT NULL,
    issued_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at      TIMESTAMPTZ NOT NULL,
    revocation_epoch BIGINT     NOT NULL DEFAULT 0,
    consumed_at     TIMESTAMPTZ,                  -- set on first use (single-use tokens)
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_profile_tokens_principal
    ON profile_tokens (principal_type, principal_id, expires_at DESC);

CREATE INDEX IF NOT EXISTS idx_profile_tokens_server
    ON profile_tokens (server_id, expires_at DESC);

COMMENT ON TABLE profile_tokens IS
    'Short-lived typed principal→server binding tokens. Never store plaintext credentials here.';
