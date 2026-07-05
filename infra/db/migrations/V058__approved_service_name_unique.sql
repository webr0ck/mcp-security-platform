-- V058__approved_service_name_unique.sql
-- CRITICAL-1 hardening (cross-user credential bleed): service_name is the
-- credential lookup key. Two independently-approved servers claiming the same
-- service_name would let a user's credential enrolled for one be resolvable for
-- the other. A partial unique index makes that state unrepresentable for
-- approved servers (the security-critic's DB-enforced control, complementing the
-- app-layer fix that stops the submitter from setting service_name at all).
--
-- Partial (WHERE status='approved' AND service_name IS NOT NULL) so pending/
-- rejected drafts and no-credential servers are unaffected.

CREATE UNIQUE INDEX IF NOT EXISTS uq_server_registry_approved_service_name
    ON server_registry (service_name)
    WHERE status = 'approved' AND service_name IS NOT NULL AND deleted_at IS NULL;

COMMENT ON INDEX uq_server_registry_approved_service_name IS
    'CRITICAL-1: at most one approved server per credential service_name (bleed guard).';
