-- V043: add platform_managed_creds flag to server_registry
--
-- When true, the platform credential broker stores and injects secrets for
-- this server (e.g. header API key, service-account token).
-- When false, credentials are managed externally (Entra client credentials,
-- Keycloak token exchange, mTLS, etc.) and the admin/user credential upload
-- UI is hidden.
--
-- Default FALSE so existing servers are unaffected; the admin opts in
-- explicitly per-server when the integration supports it.
--
-- Platform-managed modes (upload makes sense):
--   service, user, service_account, oauth_user_token
-- Externally-managed modes (no upload — credentials live outside the platform):
--   none, entra_client_credentials, entra_user_token, kc_token_exchange, passthrough

ALTER TABLE server_registry
    ADD COLUMN IF NOT EXISTS platform_managed_creds BOOLEAN NOT NULL DEFAULT FALSE;

COMMENT ON COLUMN server_registry.platform_managed_creds IS
    'True when the proxy credential broker stores and injects secrets for this server. '
    'False for externally-managed auth (Entra, Keycloak token exchange, mTLS, etc.).';
