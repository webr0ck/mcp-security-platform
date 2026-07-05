-- V060__submission_status_check.sql
-- Validation MEDIUM #2: submission_status had no DB CHECK/enum, so a typo or a
-- code path could write an invalid state and the approval state machine had no
-- structural guard-rail. Constrain it to the known set (the state machine is
-- documented in PRD-0007). NULL is allowed — admin-registered servers
-- (server_registry.py path) skip the submission workflow and leave it NULL.
--
-- Verified: every existing row is already within this set before adding the CHECK.

ALTER TABLE server_registry
    DROP CONSTRAINT IF EXISTS ck_submission_status_valid;
ALTER TABLE server_registry
    ADD CONSTRAINT ck_submission_status_valid
    CHECK (submission_status IS NULL OR submission_status IN (
        'draft',
        'scan_pending', 'scan_running', 'scan_blocked',
        'awaiting_review', 'changes_requested',
        'approved_pending_url', 'scaffold_ready',
        'approved', 'active',
        'rejected'
    ));
