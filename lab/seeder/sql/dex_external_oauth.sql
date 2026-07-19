-- =============================================================================
-- lab/seeder/sql/dex_external_oauth.sql
-- WP-A3 (CR-04 remainder) / Task 12: prove the NEW generic/dynamic
-- external_oauth_user_token dispatcher path against Dex as a SECOND, non-Entra
-- external IdP — distinct from the legacy static dex.py adapter (service='dex',
-- lab-dex-cal/dex-calendar 'user'-mode enrollment) and from entra_user_token
-- (Microsoft-specific). See docs/spec/01-authentication.md §4.6.
--
-- Requires tools.sql to have run first (echo-dex-external tool row must exist).
-- Idempotent: safe to re-run (ON CONFLICT / NULL-guarded UPDATE).
--
-- NOTE on approval path: every other injection-mode row in this lab
-- (echo-sa/echo-basic/lab-tickets/lab-m365/...) is seeded directly into
-- server_registry/tool_registry rather than driven through the self-service
-- submission+admin/approve HTTP API (see servers.sql's own header comment).
-- This file follows that same established lab convention for consistency,
-- but ALSO seeds a real oauth_provider_policy row (the WP-A2 approval-time
-- gate normally consulted by POST /api/v1/admin/submissions/{id}/approve —
-- see services/oauth_policy.py::validate_requested_config) so the policy
-- data this server's approved_upstream_idp_config would have been validated
-- against actually exists and is inspectable, even though this lab seed
-- bypasses the HTTP approval endpoint itself.
-- =============================================================================
BEGIN;

-- ── 1. oauth_provider_policy row for Dex's issuer ────────────────────────────
INSERT INTO oauth_provider_policy (
    issuer, tenant, allowed_scopes, blocked_scopes, max_risk,
    allowed_redirect_patterns, allowed_client_auth_methods, allowed_token_audiences,
    notes, created_by
) VALUES (
    'http://localhost:5556/dex', NULL,
    '["openid", "profile", "email", "offline_access"]'::jsonb,
    '[]'::jsonb,
    'low',
    '["https://127.0.0.1:8443/*", "http://localhost:8000/*"]'::jsonb,
    '["client_secret_post", "client_secret_basic"]'::jsonb,
    '[]'::jsonb,
    'WP-A3/Task-12: Dex as a second, non-Entra external IdP — proves the generic '
    'external_oauth_user_token dynamic-adapter path (GenericOAuthAdapter), independent '
    'of the legacy static dex.py adapter (service=dex) which this policy row does not govern.',
    'lab-seeder'
)
ON CONFLICT (issuer, COALESCE(tenant, '')) DO UPDATE SET
    allowed_scopes              = EXCLUDED.allowed_scopes,
    allowed_redirect_patterns   = EXCLUDED.allowed_redirect_patterns,
    allowed_client_auth_methods = EXCLUDED.allowed_client_auth_methods,
    updated_at                  = now();

-- ── 2. server_registry row: reviewer-approved config for service_name='dex-external' ──
INSERT INTO server_registry (
    name, upstream_url, status, owner_sub, injection_mode, custody_mode,
    trust_tier, trust_tier_label, upstream_allowlist_entry, url_allowlist_checked,
    platform_managed_creds, service_name,
    approved_upstream_idp_config, approved_oauth_scopes, oauth_policy_id,
    approved_at, approved_by
)
SELECT
    'lab-dex-external-oauth', 'http://lab-mcp-echo:8000/mcp', 'approved', 'alice@corp',
    'external_oauth_user_token'::injection_mode_enum, 'session_suk',
    2, 'internal', '10.89.0.0/16', false,
    false, 'dex-external',
    jsonb_build_object(
        'issuer', 'http://localhost:5556/dex',
        'client_id', 'mcp-dex-generic',
        -- authorization_endpoint is BROWSER-facing (the user agent is
        -- redirected here directly) — must be the host-mapped address.
        'authorization_endpoint', 'http://localhost:5556/dex/auth',
        -- token_endpoint is called SERVER-SIDE only (proxy container ->
        -- Dex), so it must use the container-network hostname, mirroring
        -- the existing DEX_ISSUER_URL (browser) vs DEX_INTERNAL_ISSUER_URL
        -- (proxy->container) split already established in .env.lab for the
        -- legacy static dex.py adapter.
        'token_endpoint', 'http://lab-dex:5556/dex/token',
        'scopes', jsonb_build_array('openid', 'profile', 'email', 'offline_access'),
        'redirect_uri', 'https://127.0.0.1:8443/auth/callback/dex-external',
        'client_auth_method', 'client_secret_post'
    ),
    ARRAY['openid', 'profile', 'email', 'offline_access'],
    p.id,
    now(), 'lab-seeder (WP-A3/Task-12 second-IdP proof)'
FROM oauth_provider_policy p
WHERE p.issuer = 'http://localhost:5556/dex' AND p.tenant IS NULL
ON CONFLICT (name) DO UPDATE SET
    status                        = 'approved',
    injection_mode                = EXCLUDED.injection_mode,
    service_name                  = EXCLUDED.service_name,
    approved_upstream_idp_config  = EXCLUDED.approved_upstream_idp_config,
    approved_oauth_scopes         = EXCLUDED.approved_oauth_scopes,
    oauth_policy_id               = EXCLUDED.oauth_policy_id,
    upstream_allowlist_entry      = EXCLUDED.upstream_allowlist_entry,
    updated_at                    = now();

-- ── 3. Link echo-dex-external's tool_registry row to THIS server_id explicitly ──
-- (not the generic "link by upstream_url" step in servers.sql — several tools
-- share the echo upstream_url, so that step must not be relied on here).
UPDATE tool_registry t
SET server_id = s.server_id, updated_at = now()
FROM server_registry s
WHERE s.name = 'lab-dex-external-oauth'
  AND t.name = 'echo-dex-external'
  AND t.deleted_at IS NULL;

-- ── 4. Entitlement: alice@corp may invoke this server ────────────────────────
INSERT INTO entitlement (server_id, principal_id, principal_type, granted_by, entitlement_version)
SELECT s.server_id, 'human:keycloak:alice@corp', 'human', 'lab-seeder', 1
FROM server_registry s
WHERE s.name = 'lab-dex-external-oauth'
ON CONFLICT (server_id, principal_id, principal_type) DO NOTHING;

COMMIT;
