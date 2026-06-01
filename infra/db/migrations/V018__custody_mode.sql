-- V018: Add custody_mode to server_registry
-- Values: 'session_suk' (human principal, SUK-derived) | 'hsm_agent' (agent, Vault transit)
-- Default: 'session_suk' for all existing rows.

ALTER TABLE server_registry
    ADD COLUMN IF NOT EXISTS custody_mode TEXT NOT NULL DEFAULT 'session_suk'
        CHECK (custody_mode IN ('session_suk', 'hsm_agent'));

COMMENT ON COLUMN server_registry.custody_mode IS
    'Custody mode: session_suk = SUK-encrypted (storage-only ZK); hsm_agent = Vault transit non-exportable key';
