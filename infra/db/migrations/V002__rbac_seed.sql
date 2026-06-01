-- =============================================================================
-- V002__rbac_seed.sql
-- MCP Security Platform — RBAC Seed Data
-- =============================================================================
-- Seeds:
--   1. Default OIDC claim-to-role mappings (per-issuer, per the Architect spec §8.1)
--   2. Bootstrap admin API key (hash placeholder — MUST be replaced at deploy time)
--
-- IMPORTANT — INV-008: No real secrets are stored here. The key_hash value
-- is a placeholder of 64 zeroes. The bootstrap script
-- infra/scripts/create-bootstrap-key.sh generates a real key, computes its
-- SHA-256, and UPDATEs this row (matching on client_id = 'bootstrap').
-- The placeholder ensures the row exists so the script can UPDATE rather than
-- INSERT (idempotent first-run behaviour).
-- =============================================================================

-- ---------------------------------------------------------------------------
-- 1. Default OIDC role mappings
-- ---------------------------------------------------------------------------
-- Issuer placeholder: replace OIDC_ISSUER_URL with the actual issuer URL
-- at deploy time (or manage via the API). These seeds cover the common case
-- of a single provider using a 'roles' claim.
--
-- ON CONFLICT DO NOTHING makes this idempotent if re-applied.

-- NOTE: The __OIDC_ISSUER_PLACEHOLDER__ string must be replaced at deploy time.
-- The lab seeder (lab/seeder/seed.py) runs a post-migration UPDATE to substitute
-- the real OIDC_ISSUER_URL value. For production, use the deploy script or
-- infra/scripts/fix-oidc-issuer.sh.
INSERT INTO oidc_role_mappings (oidc_issuer, claim_key, claim_value, roles)
VALUES
    -- Admin: full read/write platform access
    ('__OIDC_ISSUER_PLACEHOLDER__', 'roles', 'mcp-admin',   '{"admin"}'),
    -- Agent: tool invocation only
    ('__OIDC_ISSUER_PLACEHOLDER__', 'roles', 'mcp-agent',   '{"agent"}'),
    -- Auditor: read-only access to audit logs, tools, compliance reports
    ('__OIDC_ISSUER_PLACEHOLDER__', 'roles', 'mcp-auditor', '{"auditor"}'),
    -- Readonly: list tools, view compliance summary; no audit log access
    ('__OIDC_ISSUER_PLACEHOLDER__', 'roles', 'mcp-readonly','{"readonly"}')
ON CONFLICT (oidc_issuer, claim_key, claim_value) DO NOTHING;


-- ---------------------------------------------------------------------------
-- 2. Bootstrap admin API key (placeholder hash)
-- ---------------------------------------------------------------------------
-- key_hash: 64 zeroes = placeholder. MUST be overridden by
-- infra/scripts/create-bootstrap-key.sh before any production use.
--
-- The CHECK constraint on api_keys.key_hash requires exactly 64 hex chars,
-- which 64 zeroes satisfies (it is a valid-length placeholder, not an empty
-- string). The script overwrites this row.
--
-- roles: '{"admin"}' grants full platform access.
-- rate_limit_rpm: 0 means "no rate limit" for bootstrap admin.
-- expires_at: NULL means the bootstrap key does not auto-expire; rotate it.

INSERT INTO api_keys (
    key_id,
    key_hash,
    client_id,
    roles,
    rate_limit_rpm,
    created_by,
    expires_at,
    revoked_at
)
VALUES (
    '00000000-0000-0000-0000-000000000001',          -- stable UUID for idempotent updates
    '0000000000000000000000000000000000000000000000000000000000000000',  -- 64-zero placeholder
    'bootstrap',
    '{"admin"}',
    300,                                              -- admin rate limit per API.md §1.6
    'system-migration',
    NULL,                                             -- no expiry; rotate after first login
    NULL                                              -- not revoked
)
ON CONFLICT (key_id) DO NOTHING;

-- Note for backend_dev:
-- After infra/scripts/create-bootstrap-key.sh runs, it will UPDATE the row
-- WHERE key_id = '00000000-0000-0000-0000-000000000001' with the real hash.
-- The raw key is printed to stdout once and never stored.
