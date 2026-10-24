-- 0002_grants_credentials.up.sql — mcphub-store consolidated schema, part 2/4
--
-- Per-principal tool grants and the credential broker's ciphertext store.

-- ---------------------------------------------------------------------------
-- grants — per-principal tool/tag entitlements, optionally scoped to one
-- server (server_id NULL = platform-wide grant, e.g. super-admin tooling).
--
-- Query pattern (HOT — the second of the two hottest queries at 3000
-- concurrent agents, per rs/ARCHITECTURE.md's enforcement order "rbac"
-- step):
--   SELECT allowed_tools, allowed_tags, max_risk_level FROM grants
--   WHERE principal_id = $1 AND (server_id = $2 OR server_id IS NULL)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS grants (
    grant_id        UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    principal_id    TEXT        NOT NULL,
    server_id       UUID        REFERENCES servers (server_id) ON DELETE CASCADE,
    allowed_tools   TEXT[]      NOT NULL DEFAULT '{}',
    allowed_tags    TEXT[]      NOT NULL DEFAULT '{}',
    max_risk_level  TEXT        NOT NULL DEFAULT 'low'
                        CHECK (max_risk_level IN ('low', 'medium', 'high', 'critical')),
    granted_by      TEXT        NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT uq_grants_principal_server UNIQUE (principal_id, server_id)
);

-- Serves the hot lookup above; principal_id is the leading (most selective)
-- column since one principal's grants are read every invoke, while a given
-- server_id is shared across many principals.
CREATE INDEX IF NOT EXISTS idx_grants_principal
    ON grants (principal_id);

CREATE TRIGGER trg_grants_updated_at
    BEFORE UPDATE ON grants
    FOR EACH ROW EXECUTE FUNCTION fn_set_updated_at();

-- ---------------------------------------------------------------------------
-- credentials — AES-256-GCM sealed credential material for the broker
-- (mcphub-creds). Ciphertext, AAD, and key_version are stored; the KEK
-- itself never touches this table (Vault-derived at runtime, per
-- ARCHITECTURE.md / the Python platform's KEK persistence decision).
--
-- AAD binds each ciphertext to (principal_id, server_id, purpose) so a
-- sealed blob cannot be replayed against a different owner or purpose even
-- if copied between rows.
--
-- Hard DELETE is intentionally permitted here (unlike tool_registry /
-- audit_events) — full credential revocation must be able to physically
-- erase key material. This mirrors the Python platform's credential_store,
-- which is the one proxy_app-writable table that permits hard delete.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS credentials (
    credential_id   UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    principal_id    TEXT        NOT NULL,
    server_id       UUID        REFERENCES servers (server_id) ON DELETE CASCADE,
    purpose         TEXT        NOT NULL DEFAULT 'upstream_token',
    key_version     INTEGER     NOT NULL,
    nonce           BYTEA       NOT NULL,
    ciphertext      BYTEA       NOT NULL,
    aad             BYTEA       NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at      TIMESTAMPTZ,

    CONSTRAINT uq_credentials_principal_server_purpose UNIQUE (principal_id, server_id, purpose)
);

-- Hot query: credential injection dispatch step reads the active credential
-- for (principal_id, server_id) on every invoke that needs injection.
CREATE INDEX IF NOT EXISTS idx_credentials_active
    ON credentials (principal_id, server_id) WHERE revoked_at IS NULL;

CREATE TRIGGER trg_credentials_updated_at
    BEFORE UPDATE ON credentials
    FOR EACH ROW EXECUTE FUNCTION fn_set_updated_at();

-- Now that credentials exists, bind idp_configs' client secret reference to it.
ALTER TABLE idp_configs
    ADD CONSTRAINT fk_idp_configs_client_secret_credential
    FOREIGN KEY (client_secret_credential_id) REFERENCES credentials (credential_id) ON DELETE SET NULL;
