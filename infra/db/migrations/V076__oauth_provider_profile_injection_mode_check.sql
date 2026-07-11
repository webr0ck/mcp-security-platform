-- V076__oauth_provider_profile_injection_mode_check.sql
-- M-04 (2026-07-11 audit): V074 added oauth_provider_profile.injection_mode
-- as free-text with no CHECK constraint — the database could not prevent an
-- invalid value from ever being written (only the app-level
-- create_draft_profile validator did, which any direct SQL/migration/manual
-- fix bypasses). NULL is still allowed (a handful of provider_type values
-- are genuinely ambiguous without the original wizard answers, per V074's
-- own comment — see app/services/oauth_provider_profile.py::recommend_provider_type),
-- but any NON-NULL value must now be one of the canonical modes the app's
-- all_mode_values() (app/services/auth_modes.py) already recognizes.
--
-- Backfill: only 'same_platform_idp' has an unambiguous 1:1 provider_type ->
-- injection_mode mapping (always kc_token_exchange, per
-- recommend_provider_type) — that's the only case safely backfillable
-- without guessing. Every other NULL row is left NULL rather than assigned
-- a guessed value that could misroute credentials.

UPDATE oauth_provider_profile
   SET injection_mode = 'kc_token_exchange'
 WHERE provider_type = 'same_platform_idp'
   AND injection_mode IS NULL;

ALTER TABLE oauth_provider_profile ADD CONSTRAINT ck_oauth_provider_profile_injection_mode
    CHECK (injection_mode IS NULL OR injection_mode IN (
        'none', 'service', 'basic_auth', 'user', 'service_account',
        'kc_token_exchange', 'oauth_user_token',
        'entra_client_credentials', 'entra_user_token',
        'external_oauth_client_credentials', 'external_oauth_user_token',
        'passthrough'
    ));

COMMENT ON CONSTRAINT ck_oauth_provider_profile_injection_mode ON oauth_provider_profile IS
    'Mirrors app/services/auth_modes.py::AuthMode — keep both lists in sync when a mode is added.';
