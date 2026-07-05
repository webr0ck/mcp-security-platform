-- V054__platform_secrets_and_llm_config.sql
-- PRD-0005 R-1: admin-configurable LLM provider.
--
-- Two tables, per the "each surface keeps its own purpose-built table" convention:
--   * platform_secrets — encrypted platform-level (non-user, non-tool) secrets.
--     This is NEW plumbing (3-critic F-1): the existing credential_store path is
--     tool-bound (ON CONFLICT (tool_id, service), owner_type='service'); a
--     platform config secret has no tool_id. We reuse ONLY the KEK/AES-256-GCM
--     crypto primitive (credential_broker/approaches/approach_a.py) — the blob is
--     salt(32)||nonce(12)||ciphertext+tag, KEK from Vault (spec §2.1), derived for
--     a fixed non-user platform key-domain. Never a plaintext column.
--   * llm_config — non-secret LLM settings (base_url/model/timeout/enabled);
--     singleton row (id=1). Absent row => env defaults (fail-closed to today's behaviour).

CREATE TABLE IF NOT EXISTS platform_secrets (
    name        TEXT PRIMARY KEY,          -- e.g. 'llm-api', 'git-bitbucket'
    blob        BYTEA NOT NULL,            -- salt||nonce||AES-256-GCM(ciphertext+tag)
    updated_by  TEXT,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE platform_secrets IS
    'Encrypted platform-level secrets (LLM token, git service-account token). blob = KEK-wrapped AES-256-GCM; never plaintext. Reuses approach_a crypto, NOT the tool-bound credential_store path.';

CREATE TABLE IF NOT EXISTS llm_config (
    id              SMALLINT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    base_url        TEXT,
    model           TEXT,
    timeout_seconds INTEGER CHECK (timeout_seconds IS NULL OR timeout_seconds BETWEEN 1 AND 600),
    enabled         BOOLEAN NOT NULL DEFAULT true,
    updated_by      TEXT,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE llm_config IS
    'Non-secret LLM provider settings (singleton id=1). Absent row = env defaults. Token lives in platform_secrets under name=llm-api.';
