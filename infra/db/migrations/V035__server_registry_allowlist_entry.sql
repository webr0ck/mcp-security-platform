-- V032__server_registry_allowlist_entry.sql
--
-- Task 3.1 (ISO-F2.6): Record which UPSTREAM_PRIVATE_CIDR_ALLOWLIST entry
-- sanctioned a private upstream registration so approving admins see the
-- provenance and invoke-time re-validation can cross-check the same entry.
--
-- upstream_allowlist_entry: the CIDR string from UPSTREAM_PRIVATE_CIDR_ALLOWLIST
-- that matched the upstream's resolved IPs at registration time, or NULL when
-- the upstream is public (no allowlist entry needed / default behavior).
ALTER TABLE server_registry
    ADD COLUMN IF NOT EXISTS upstream_allowlist_entry TEXT;

COMMENT ON COLUMN server_registry.upstream_allowlist_entry IS
    'CIDR from UPSTREAM_PRIVATE_CIDR_ALLOWLIST that sanctioned this private upstream '
    'at registration time. NULL means public IP (no allowlist required). '
    'Used by invoke-time re-validation to bind the server to its approved CIDR range.';

-- INV-011: explicit GRANT so proxy_app can read/write the new column.
GRANT SELECT, INSERT, UPDATE ON server_registry TO proxy_app;
