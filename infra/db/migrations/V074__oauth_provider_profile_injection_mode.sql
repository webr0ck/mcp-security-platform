-- V074__oauth_provider_profile_injection_mode.sql
-- WP-A6 Finding 1 completion: oauth_provider_profile did not store the
-- injection_mode a registration should use — provider_type alone is
-- ambiguous (generic_oauth2 covers basic_auth, external_oauth_user_token,
-- AND external_oauth_client_credentials depending on wizard answers; see
-- recommend_provider_type). Self-service registration needs an unambiguous
-- value to copy onto server_registry.injection_mode, so the profile must
-- record it explicitly at creation time instead of the caller re-deriving
-- it later. Additive/nullable, INV-011.

ALTER TABLE oauth_provider_profile ADD COLUMN IF NOT EXISTS
    injection_mode TEXT;

COMMENT ON COLUMN oauth_provider_profile.injection_mode IS
    'WP-A6 (Finding 1): the injection_mode a server registered against this '
    'profile should use (e.g. kc_token_exchange, external_oauth_user_token, '
    'external_oauth_client_credentials, basic_auth) — see '
    'app/services/oauth_provider_profile.py::recommend_provider_type, whose '
    'output this column is meant to carry through into server_registry.';
