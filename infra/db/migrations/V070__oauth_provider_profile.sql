-- V070__oauth_provider_profile.sql
-- MCP Security Platform — Generic OAuth 2.0 substrate productization (WP-A6)
-- Extends WP-A2's CR-04 remainder. See docs/spec/08-finalization-findings-generic-oauth.md
-- Findings 1-3.
--
-- Problem: oauth_provider_policy (V065) is a per-issuer ENFORCEMENT row, created
-- ad hoc the first time a submitter's requested config needs approval. There is
-- no product-level, admin-curated CATALOG a non-expert submitter can pick from
-- before that — "Same platform IdP" / "Generic OAuth 2.0" / "Jira Cloud" /
-- "Microsoft Entra" / "Custom OIDC" — with RFC 8414 metadata pre-fill and its
-- own reviewer-approval gate. oauth_provider_profile is that catalog; it sits
-- ABOVE oauth_provider_policy, not instead of it — a profile's issuer/scopes
-- still get validated against a matching oauth_provider_policy row (or one is
-- created) at server-approval time, unchanged from WP-A2.
--
-- Finding 3 (service adapter contract): server_registry.service_context stores
-- non-secret runtime context a ServiceAdapter discovers/selects post-enrollment
-- (e.g. a resolved API base URL, tenant/site id) — explicitly separate from
-- credential_store (which never holds anything but encrypted secrets).
--
-- INV-011: explicit GRANTs, no REFERENCES on ENUM types, additive/nullable only.

CREATE TABLE IF NOT EXISTS oauth_provider_profile (
    id                          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    slug                        TEXT NOT NULL UNIQUE,
    display_name                TEXT NOT NULL,
    -- Maps 1:1 to the non-expert wizard question set (Finding 1/2):
    --   same_platform_idp — "same IdP as this platform" -> kc_token_exchange
    --   generic_oauth2    — arbitrary external OAuth 2.0 authz-code/client-creds IdP
    --   entra             — Microsoft Entra (delegated or app-only)
    --   custom_oidc       — any other OIDC-discoverable IdP, no dedicated adapter
    --   jira_cloud        — Finding 4, NOT implemented by WP-A6 (deliberately
    --                       deprioritized); the value is reserved so a future
    --                       Jira adapter can slot in without a schema change.
    provider_type               TEXT NOT NULL
        CHECK (provider_type IN (
            'same_platform_idp', 'generic_oauth2', 'entra', 'custom_oidc', 'jira_cloud'
        )),
    issuer                      TEXT,
    authorization_endpoint       TEXT,
    token_endpoint               TEXT,
    jwks_uri                     TEXT,
    -- The issuer/metadata URL RFC 8414 discovery was run against (may differ
    -- from `issuer` itself, e.g. an explicit .well-known metadata_url).
    -- NULL when the profile was configured entirely by manual entry (no
    -- RFC 8414 document was reachable/published for this provider).
    metadata_url                 TEXT,
    default_scopes               JSONB NOT NULL DEFAULT '[]'::jsonb,
    allowed_scopes               JSONB NOT NULL DEFAULT '[]'::jsonb,
    blocked_scopes               JSONB NOT NULL DEFAULT '[]'::jsonb,
    allowed_redirect_patterns     JSONB NOT NULL DEFAULT '[]'::jsonb,
    allowed_client_auth_methods   JSONB NOT NULL DEFAULT '[]'::jsonb,
    -- kc_token_exchange audience OR a generic OAuth "resource" parameter
    -- (RFC 8707) — same "single opaque string" shape as
    -- server_registry.approved_token_audience (V065), reused here as the
    -- profile-level default/ceiling, not itself dispatch-enforced.
    token_audience_or_resource    TEXT,
    supports_pkce                 BOOLEAN NOT NULL DEFAULT true,
    supports_refresh_token        BOOLEAN NOT NULL DEFAULT true,
    supports_client_credentials   BOOLEAN NOT NULL DEFAULT false,
    -- slug of a registered ServiceAdapter (Finding 3), or NULL for
    -- "no extra discovery needed" (the generic reference adapter applies).
    service_adapter               TEXT,
    -- draft (submitter-created, not yet usable) -> pending_review ->
    -- approved (usable by submissions) | rejected. Mirrors the
    -- submission_status state-machine convention (submission.py).
    status                        TEXT NOT NULL DEFAULT 'draft'
        CHECK (status IN ('draft', 'pending_review', 'approved', 'rejected')),
    -- High-risk scopes (write/admin/mail/files/offline_access, per
    -- oauth_policy.HIGH_RISK_SCOPES) present in default_scopes/allowed_scopes
    -- require this explicit reviewer acknowledgement before status can become
    -- 'approved' — same non-negotiable as WP-A2's high_risk_scopes_approved_by.
    high_risk_scopes_approved_by  TEXT,
    high_risk_scopes_approved_at  TIMESTAMPTZ,
    created_by                    TEXT,
    approved_by                   TEXT,
    approved_at                   TIMESTAMPTZ,
    rejection_reason              TEXT,
    created_at                    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at                    TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE oauth_provider_profile IS
    'WP-A6 (Finding 1): admin-curated, reviewer-approved catalog of OAuth provider '
    'profiles a non-expert submitter picks from. Sits above oauth_provider_policy '
    '(V065) — a profile''s issuer/scopes still validate against a matching policy '
    'row at server-approval time; this table does not replace that enforcement.';

COMMENT ON COLUMN oauth_provider_profile.provider_type IS
    'Wizard-facing category (Finding 1/2). "same_platform_idp" maps to '
    'kc_token_exchange but is never shown to the submitter under that name — '
    'see app/services/oauth_provider_profile.py::recommend_provider_type.';

COMMENT ON COLUMN oauth_provider_profile.service_adapter IS
    'Finding 3: slug of a registered ServiceAdapter (see '
    'app/credential_broker/adapters/service_adapter.py). NULL = the generic '
    '"no extra discovery needed" reference adapter (GenericServiceAdapter) applies.';

CREATE INDEX IF NOT EXISTS idx_oauth_provider_profile_status
    ON oauth_provider_profile (status);

CREATE TRIGGER trg_oauth_provider_profile_updated_at
    BEFORE UPDATE ON oauth_provider_profile
    FOR EACH ROW EXECUTE FUNCTION fn_set_updated_at();

-- ---------------------------------------------------------------------------
-- Finding 3: non-secret adapter-discovered runtime context, separate from
-- credential_store (which holds only encrypted secrets, never plaintext
-- context). NULL = no adapter-specific context (the common "no extra
-- discovery needed" case).
-- ---------------------------------------------------------------------------
ALTER TABLE server_registry ADD COLUMN IF NOT EXISTS
    service_context JSONB DEFAULT NULL;
ALTER TABLE server_registry ADD COLUMN IF NOT EXISTS
    oauth_provider_profile_id UUID REFERENCES oauth_provider_profile(id) ON DELETE SET NULL;

COMMENT ON COLUMN server_registry.service_context IS
    'WP-A6 (Finding 3): non-secret runtime context a ServiceAdapter discovers/'
    'selects post-enrollment (e.g. {"adapter": "...", "api_base_url": "...", '
    '"resource_id": "...", "verified_at": "..."}). Never contains credentials — '
    'those remain exclusively in credential_store. Passed to the MCP server as '
    'config/env at deploy/verify time (WP-B3), not as a bearer token.';
COMMENT ON COLUMN server_registry.oauth_provider_profile_id IS
    'WP-A6 (Finding 1): the oauth_provider_profile this server''s submission was '
    'created from, if any. NULL for servers onboarded before this feature, or '
    'onboarded via raw upstream_idp_config without selecting a profile.';

CREATE INDEX IF NOT EXISTS idx_server_registry_oauth_provider_profile_id
    ON server_registry (oauth_provider_profile_id) WHERE oauth_provider_profile_id IS NOT NULL;

GRANT SELECT, INSERT, UPDATE ON oauth_provider_profile TO proxy_app;
GRANT SELECT, UPDATE ON server_registry TO proxy_app;
