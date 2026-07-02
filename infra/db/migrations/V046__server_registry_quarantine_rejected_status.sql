-- V046: extend server_registry status CHECK to allow 'quarantined' and 'rejected'
-- Previously only: pending | approved | suspended
ALTER TABLE server_registry DROP CONSTRAINT IF EXISTS server_registry_status_check;
ALTER TABLE server_registry ADD CONSTRAINT server_registry_status_check
    CHECK (status IN ('pending', 'approved', 'suspended', 'quarantined', 'rejected'));
