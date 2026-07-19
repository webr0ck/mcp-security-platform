-- V085__credential_store_upn.sql
-- Per-caller UPN resolution for app-only Microsoft Graph calls (m365-graph).
--
-- get_me under app-only auth cannot use /me (no signed-in user in a
-- client_credentials token) — Graph requires /users/{upn-or-id} instead. The
-- server-side fallback (M365_USER env var) is a single, hand-configured
-- mailbox shared by every caller. This column lets the proxy resolve each
-- caller's OWN UPN (captured once at their m365-graph-delegated enrollment,
-- via a one-time Graph /me call with their fresh delegated token) and inject
-- it per-request instead, so app-only get_me returns the calling user's own
-- profile rather than one shared mailbox or a always-fails /me.
--
-- Not a secret — a UPN/email is not sensitive the way encrypted_blob is —
-- stored in plaintext alongside the row it describes.

ALTER TABLE credential_store ADD COLUMN IF NOT EXISTS upn TEXT;
