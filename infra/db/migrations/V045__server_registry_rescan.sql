-- V045: track periodic re-scan freshness on approved servers
--
-- last_rescanned_at is set by the proxy's background rescan loop each time
-- it re-evaluates an approved server's supply-chain posture (scan-config.yaml
-- rules + pip-audit when github_repo_url is present).  NULL means "never
-- rescanned since approval" — the call-time gate treats that as stale when
-- SCAN_FRESHNESS_ENFORCED=true.

ALTER TABLE server_registry
    ADD COLUMN IF NOT EXISTS last_rescanned_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_server_registry_rescan
    ON server_registry (last_rescanned_at)
    WHERE deleted_at IS NULL AND status = 'approved';
