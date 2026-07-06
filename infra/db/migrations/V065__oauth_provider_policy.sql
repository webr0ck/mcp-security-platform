-- V065__oauth_provider_policy.sql
-- MCP Security Platform — OAuth/IdP policy engine (WP-A2: CR-13 + CR-03 remainder)
--
-- Problem: requested onboarding config == approved config today. Whatever a
-- submitter asks for (issuer, tenant, scopes, redirect URIs, client auth
-- method, kc_token_exchange audience) is what gets used at invoke time, with
-- zero reviewer gate.
--
-- This migration adds TWO INDEPENDENT validation dimensions — deliberately
-- NOT collapsed into one allowlist. A prior attempt to reuse a single
-- allowlist mechanism for both was tried and rejected (Claude_status.md
-- CR-13 row): service_account's default scope is "openid" (a standard OIDC
-- scope string) while kc_token_exchange's audience is e.g. "lab-tickets" (an
-- audience string) — validating one against an allowlist shaped for the
-- other broke every existing service_account tool (lab-gitea,
-- lab-grafana-mcp, lab-wazuh).
--
--   1. oauth_provider_policy: issuer(+tenant) -> allowed/blocked SCOPE SET,
--      redirect-URI patterns, client-auth methods, risk ceiling. Governs the
--      scope-shaped dimension (entra_user_token, entra_client_credentials,
--      future external_oauth_* adapters, and service_account's scope string
--      via oauth_policy.validate_service_account_scope).
--   2. server_registry.approved_token_audience / approved_oauth_scopes: a
--      single per-server AUDIENCE STRING (+ optional scopes) for
--      kc_token_exchange (RFC 8693) — a different shape (one opaque
--      audience, not a scope set), enforced independently of #1.
--      approved_oauth_scopes (TEXT[]) already existed since V014 but was
--      never wired up anywhere in the app — reused here rather than adding
--      a redundant column.
--
-- Requested vs approved: server_registry.upstream_idp_config (existing,
-- V026) remains the submitter-REQUESTED config, untouched. The new
-- approved_upstream_idp_config / approved_token_audience columns (plus the
-- newly-wired approved_oauth_scopes) are the reviewer-APPROVED values,
-- written ONLY by the admin
-- /approve endpoint after oauth_policy validation passes. All dispatch-time
-- code (dispatcher.py, tools.py discovery) must read only the approved_*
-- columns going forward — never upstream_idp_config directly.
--
-- INV-011: explicit GRANTs on every object touched. No REFERENCES on ENUM
-- types (oauth_policy_id references oauth_provider_policy(id), a UUID PK —
-- fine). Fresh-boot-chain-consistent: no data assumed to pre-exist except
-- server_registry itself (V014+).

CREATE TABLE IF NOT EXISTS oauth_provider_policy (
    id                          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    -- Issuer URL, e.g. https://login.microsoftonline.com/{tenant}/v2.0 or the
    -- gateway Keycloak realm issuer. NOT NULL + unique per (issuer, tenant).
    issuer                      TEXT NOT NULL,
    -- Tenant discriminator (e.g. Entra tenant GUID). NULL for issuers that are
    -- not multi-tenant (gateway Keycloak realm, single-tenant custom OIDC).
    tenant                      TEXT,
    allowed_scopes              JSONB NOT NULL DEFAULT '[]'::jsonb,
    blocked_scopes              JSONB NOT NULL DEFAULT '[]'::jsonb,
    max_risk                    TEXT NOT NULL DEFAULT 'medium'
                                    CHECK (max_risk IN ('low', 'medium', 'high')),
    -- fnmatch-style glob patterns (e.g. "https://portal.example.com/*").
    allowed_redirect_patterns   JSONB NOT NULL DEFAULT '[]'::jsonb,
    -- e.g. "client_secret_post", "private_key_jwt". Empty = no constraint recorded.
    allowed_client_auth_methods JSONB NOT NULL DEFAULT '[]'::jsonb,
    -- kc_token_exchange / RFC 8693 audience allowlist for this issuer, kept
    -- alongside the scope-shaped columns above for admins who want to manage
    -- both dimensions from one policy row per issuer. server_registry's own
    -- approved_token_audience remains the per-server enforced value —
    -- this column is an authoring aid / ceiling, not itself dispatch-enforced.
    allowed_token_audiences     JSONB NOT NULL DEFAULT '[]'::jsonb,
    notes                       TEXT,
    created_by                  TEXT,
    created_at                  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at                  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_oauth_provider_policy_issuer_tenant
    ON oauth_provider_policy (issuer, COALESCE(tenant, ''));

COMMENT ON TABLE oauth_provider_policy IS
    'WP-A2/CR-13: admin-maintained allowlist of what an onboarded OAuth/IdP server MAY request (issuer+tenant scoped). Approval-time validation checks requested config is a subset of the matching row; no matching row = fail-closed reject (unknown issuer).';
COMMENT ON COLUMN oauth_provider_policy.max_risk IS
    'Risk ceiling for servers approved under this policy row; informational input to owner_max_risk_level, not auto-applied.';

-- ---------------------------------------------------------------------------
-- server_registry: approved (reviewer-set) config, separate from requested
-- ---------------------------------------------------------------------------

ALTER TABLE server_registry ADD COLUMN IF NOT EXISTS
    approved_upstream_idp_config JSONB DEFAULT NULL;
COMMENT ON COLUMN server_registry.approved_upstream_idp_config IS
    'WP-A2/CR-13: reviewer-approved IdP config (issuer, client_id, scopes, redirect_uri, client_auth_method), set ONLY by the admin /approve endpoint after oauth_policy validation. Dispatch-time code must read this, never upstream_idp_config (the submitter-requested value).';

ALTER TABLE server_registry ADD COLUMN IF NOT EXISTS
    approved_token_audience TEXT DEFAULT NULL;
COMMENT ON COLUMN server_registry.approved_token_audience IS
    'WP-A2/CR-03: reviewer-approved kc_token_exchange (RFC 8693) audience for this server. A DIFFERENT validation shape than scopes (single opaque audience string) — do not conflate with approved_token_scopes/oauth_provider_policy.allowed_scopes.';

-- NOTE: server_registry.approved_oauth_scopes (TEXT[], V014) already exists
-- for exactly this purpose but was never wired up anywhere in the app —
-- reused here instead of adding a redundant column. See COMMENT below.
COMMENT ON COLUMN server_registry.approved_oauth_scopes IS
    'WP-A2/CR-13: reviewer-approved scope set for this server''s OAuth/IdP config (subset of the matching oauth_provider_policy.allowed_scopes at approval time). Pre-existed since V014 unused; wired up by the WP-A2 approve endpoint.';

ALTER TABLE server_registry ADD COLUMN IF NOT EXISTS
    oauth_policy_id UUID REFERENCES oauth_provider_policy(id) ON DELETE SET NULL;
COMMENT ON COLUMN server_registry.oauth_policy_id IS
    'oauth_provider_policy row matched at approval time for this server''s upstream_idp_config issuer/tenant. NULL if the server has no OAuth/IdP config (service/user/basic_auth/none modes).';

ALTER TABLE server_registry ADD COLUMN IF NOT EXISTS
    high_risk_scopes_approved_by TEXT DEFAULT NULL;
ALTER TABLE server_registry ADD COLUMN IF NOT EXISTS
    high_risk_scopes_approved_at TIMESTAMPTZ DEFAULT NULL;
COMMENT ON COLUMN server_registry.high_risk_scopes_approved_by IS
    'Reviewer identity (typed principal / sub) who explicitly acknowledged high-risk scopes (write/admin/mail/files/offline_access) at approval time. NULL if no high-risk scopes were requested, or if not yet reviewed.';

CREATE INDEX IF NOT EXISTS idx_server_registry_oauth_policy_id
    ON server_registry (oauth_policy_id) WHERE oauth_policy_id IS NOT NULL;

-- ---------------------------------------------------------------------------
-- Backfill: grandfather already-approved servers under the pre-WP-A2 model.
-- They already passed human review; do not retroactively lock them out of
-- invocation just because approved_* is now the enforced column. New
-- approvals from this point forward go through oauth_policy validation.
-- ---------------------------------------------------------------------------

UPDATE server_registry
   SET approved_upstream_idp_config = upstream_idp_config
 WHERE status = 'approved'
   AND upstream_idp_config IS NOT NULL
   AND approved_upstream_idp_config IS NULL;

UPDATE server_registry
   SET approved_token_audience = (upstream_idp_config ->> 'audience')
 WHERE status = 'approved'
   AND approved_token_audience IS NULL
   AND upstream_idp_config ? 'audience'
   AND (
        injection_mode IN ('kc_token_exchange', 'oauth_user_token')
        OR default_injection_mode IN ('kc_token_exchange', 'oauth_user_token')
   );

UPDATE server_registry
   SET approved_oauth_scopes = ARRAY(SELECT jsonb_array_elements_text(upstream_idp_config -> 'scopes'))
 WHERE status = 'approved'
   AND approved_oauth_scopes IS NULL
   AND upstream_idp_config ? 'scopes';

-- INV-011: explicit grants for every object touched.
GRANT SELECT, INSERT, UPDATE ON oauth_provider_policy TO proxy_app;
GRANT SELECT, UPDATE ON server_registry TO proxy_app;
