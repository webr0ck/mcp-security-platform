-- =============================================================================
-- lab/seeder/sql/entra_oauth_policy.sql
-- PRD-0011 WS-4 (acceptance-test-report-2026-07-18 finding #5): admit the Entra
-- IdP as an approvable OAuth provider by seeding its oauth_provider_policy
-- trust-anchor row.
--
-- Before this, the ONLY oauth_provider_policy row was Dex's, so any real Entra
-- submission failed closed at approval with 422 OAUTH_POLICY_VIOLATION
-- (UnknownIssuerError) — see services/oauth_policy.py::validate_requested_config.
-- The pre-existing m365-graph server sidestepped this gate by being seeded
-- directly into server_registry; a genuine self-service Entra submission is the
-- first to actually hit the check.
--
-- Scope: minimal. Only the app-only client-credentials Graph scope the
-- entra-id directory reader requests ('https://graph.microsoft.com/.default').
-- 'tenant' is NULL because the requested upstream_idp_config carries no separate
-- 'tenant' field — the tenant GUID is already embedded in the issuer URL, and
-- get_policy_for_issuer matches on (issuer, COALESCE(tenant,'')).
-- No redirect patterns / client-auth methods: client-credentials mode uses
-- neither, and validate_requested_config only checks a field when present.
--
-- SECURITY NOTE (appsec): this is a NEW IdP trust anchor. Adding it widens which
-- issuers can be approved. Scope is intentionally the single '.default' Graph
-- scope. '.default' is app-only consent to whatever application permissions the
-- app registration already holds in Entra — open-ended and invisible to this
-- platform. It is therefore classified high-risk by oauth_policy._split_high_risk
-- (_is_wildcard_consent_scope), so approving an entra_client_credentials
-- submission for this issuer REQUIRES the reviewer to set
-- high_risk_scopes_approved=true — an explicit, recorded acknowledgement.
-- Widening allowed_scopes here should likewise remain an explicit, reviewed act.
--
-- Idempotent: ON CONFLICT NULL-guarded UPDATE. Does NOT create/modify the
-- entra-id-directory server_registry row — that must go through the real
-- reviewer approval flow.
-- =============================================================================
BEGIN;

INSERT INTO oauth_provider_policy (
    issuer, tenant, allowed_scopes, blocked_scopes, max_risk,
    allowed_redirect_patterns, allowed_client_auth_methods, allowed_token_audiences,
    notes, created_by
) VALUES (
    'https://login.microsoftonline.com/e756f76f-bbde-4d68-903c-f8d8cda37d1a/v2.0', NULL,
    '["https://graph.microsoft.com/.default"]'::jsonb,
    '[]'::jsonb,
    'medium',
    '[]'::jsonb,
    '[]'::jsonb,
    '[]'::jsonb,
    'PRD-0011 WS-4: Entra directory reader trust anchor (client-credentials, '
    'app-only Graph .default scope). Admits real Entra submissions to the '
    'reviewer approval gate. appsec-reviewed.',
    'lab-seeder'
)
ON CONFLICT (issuer, COALESCE(tenant, '')) DO UPDATE SET
    allowed_scopes = EXCLUDED.allowed_scopes,
    updated_at     = now();

COMMIT;
