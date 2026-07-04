-- =============================================================================
-- V050__role_assignments_append_only_revoke.sql
--
-- Adds an in-platform RBAC admin panel (grant/revoke roles via the portal UI,
-- not just Keycloak). V009 deliberately revoked UPDATE/DELETE on
-- role_assignments from the app's DB role (INV-011: single-writer,
-- append-only, no hard delete) — a "revoke" endpoint therefore cannot UPDATE
-- or DELETE an existing row. Instead each grant/revoke is its own INSERTed
-- event row; the *latest* event per (client_id, role) determines whether the
-- role is currently active. This keeps INV-011 intact with no new grants
-- needed on role_assignments (INSERT/SELECT already held by proxy_app).
--
-- Schema change: the old UNIQUE INDEX on (client_id, role) prevented ever
-- re-granting a role after a revoke (or re-syncing from Keycloak). Drop it —
-- multiple rows per (client_id, role) are now the norm (one per grant/revoke
-- event); "current state" is resolved by the app at read time, not by the
-- table shape.
-- =============================================================================

ALTER TABLE role_assignments
    ADD COLUMN IF NOT EXISTS revoked BOOLEAN NOT NULL DEFAULT false;

DROP INDEX IF EXISTS idx_role_assignments_client_role;

-- Latest-event-per-key lookups (both the auth middleware and the new admin
-- panel do "ORDER BY client_id, role, created_at DESC").
CREATE INDEX IF NOT EXISTS idx_role_assignments_client_role_created
    ON role_assignments (client_id, role, created_at DESC);
