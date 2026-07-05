-- V055__git_providers.sql
-- PRD-0005 R-2: corporate Bitbucket git source ADDED ALONGSIDE GitHub.
--
-- Per-provider non-secret config. The service-account token lives ENCRYPTED in
-- platform_secrets under name 'git-<provider>' (V054) — never a column here.
--
-- SSRF safety (3-critic F-3): the git clone path does NOT traverse the egress
-- proxy (its allowlist covers only M365/Graph). So an admin-configured host is
-- validated at write time and re-validated immediately before clone:
--   * loopback / link-local / cloud-metadata (169.254.0.0/16) are ALWAYS rejected;
--   * RFC1918 / private ranges are rejected UNLESS allow_private=true (an explicit
--     admin acknowledgement, since corporate Bitbucket is typically internal),
--     which also emits a WARN audit event.

CREATE TABLE IF NOT EXISTS git_providers (
    provider      TEXT PRIMARY KEY,          -- 'github' | 'bitbucket'
    enabled       BOOLEAN NOT NULL DEFAULT false,
    host          TEXT NOT NULL,             -- exact host, e.g. 'github.com' or 'bitbucket.corp.example'
    clone_account TEXT,                      -- service-account username for HTTPS clone
    allow_private BOOLEAN NOT NULL DEFAULT false,  -- ack: host may resolve to an RFC1918 address
    updated_by    TEXT,
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE git_providers IS
    'Per-provider git clone config (PRD-0005 R-2). Token in platform_secrets name=git-<provider>. host is exact-match; allow_private gates RFC1918 clone targets.';

-- Seed github from the existing env defaults so current submissions keep working.
-- The token stays resolvable from env (GITHUB_CLONE_TOKEN) until an admin sets
-- one in platform_secrets; account prefers this row, falls back to env.
INSERT INTO git_providers (provider, enabled, host, clone_account, allow_private, updated_by)
VALUES ('github', true, 'github.com', NULL, false, 'migration-V055')
ON CONFLICT (provider) DO NOTHING;
