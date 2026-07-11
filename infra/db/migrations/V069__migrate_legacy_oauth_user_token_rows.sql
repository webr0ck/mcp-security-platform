-- V069: WP-A5 (CR-02 completion) — migrate any remaining legacy
-- injection_mode='oauth_user_token' rows to the canonical 'kc_token_exchange'
-- name. oauth_user_token remains a valid injection_mode_enum value (kept for
-- backwards compatibility / historical audit rows) and the dispatcher still
-- accepts it, but new/existing tool and server rows should read the
-- canonical name going forward — this is data cleanup, not a schema change.
--
-- Idempotent: a no-op if no rows carry the legacy value (confirmed zero rows
-- in the current lab DB at the time this was written).

UPDATE tool_registry
SET injection_mode = 'kc_token_exchange'
WHERE injection_mode = 'oauth_user_token';

UPDATE server_registry
SET injection_mode = 'kc_token_exchange'
WHERE injection_mode = 'oauth_user_token';
