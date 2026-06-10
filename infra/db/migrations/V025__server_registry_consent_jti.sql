-- V025__server_registry_consent_jti.sql
-- Record which consent token authorized the approval action (dual-control audit trail).
-- This column is SET at approval time alongside approved_at/approved_by so that
-- an auditor can cross-reference the mode_change_consent table to verify the
-- owner explicitly consented before the platform_admin approved.
ALTER TABLE server_registry
    ADD COLUMN IF NOT EXISTS consent_jti TEXT
        REFERENCES mode_change_consent(jti) ON DELETE SET NULL;

COMMENT ON COLUMN server_registry.consent_jti IS
    'JTI of the mode_change_consent token that authorized this approval (dual-control, D3).'
    ' NULL for servers approved before V025 or in test environments without consent enforcement.';
