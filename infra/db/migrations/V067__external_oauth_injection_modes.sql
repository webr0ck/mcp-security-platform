-- no-txn
-- V067__external_oauth_injection_modes.sql
-- MCP Security Platform — External IdP adapters (WP-A3: CR-04 remainder)
--
-- Adds the two injection modes that were already recognised in
-- app/services/auth_modes.py (AuthMode.EXTERNAL_OAUTH_USER_TOKEN /
-- EXTERNAL_OAUTH_CLIENT_CREDENTIALS, status='roadmap') but had no dispatcher
-- branch and no DB enum value — this migration + the WP-A3 code change close
-- that gap.
--
--   external_oauth_user_token         — per-user delegated OAuth 2.0 refresh flow
--                                        against a generic (non-KC, non-Entra)
--                                        IdP, e.g. Atlassian Jira Cloud OAuth 2.0
--                                        3LO. Approach A (broker.resolve), same
--                                        shape as entra_user_token but the
--                                        concrete adapter is built dynamically
--                                        from server_registry.approved_upstream_idp_config
--                                        (services/oauth_policy.py-governed)
--                                        rather than from global env settings.
--   external_oauth_client_credentials — app-only OAuth 2.0 client_credentials
--                                        grant against a generic token_endpoint.
--
-- Requires no-txn (ALTER TYPE ... ADD VALUE cannot run inside a transaction
-- block that might also reference the new label).
--
-- Also widens server_registry.upstream_idp_type's CHECK to accept
-- 'external_oauth' (previously gateway_idp | entra | custom_oidc only), so a
-- generic external IdP submission has a type distinct from the Entra-specific
-- and gateway-Keycloak-specific ones. Governed the same way as entra_* by
-- WP-A2's oauth_provider_policy (issuer/tenant → allowed scopes) — no new
-- policy-engine table needed, the existing one already keys on issuer+tenant
-- generically.

ALTER TYPE injection_mode_enum ADD VALUE IF NOT EXISTS 'external_oauth_user_token';
ALTER TYPE injection_mode_enum ADD VALUE IF NOT EXISTS 'external_oauth_client_credentials';

ALTER TABLE server_registry DROP CONSTRAINT IF EXISTS server_registry_upstream_idp_type_check;
ALTER TABLE server_registry ADD CONSTRAINT server_registry_upstream_idp_type_check
    CHECK (upstream_idp_type = ANY (ARRAY['gateway_idp', 'entra', 'custom_oidc', 'external_oauth']));
