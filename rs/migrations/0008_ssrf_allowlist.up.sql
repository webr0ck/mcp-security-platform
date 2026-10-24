-- 0007_ssrf_allowlist.up.sql — backs `mcphub-gateway::ssrf`'s
-- `ToolMeta.allowed_cidr` field, which had no column to read from until
-- now (bin/mcphubd's entitlement wiring always passed `None`, meaning
-- every server whose upstream resolves to a private/loopback address was
-- unconditionally denied by the SSRF gate — correct for the public
-- internet, but there was no way to explicitly allowlist a legitimate
-- internal/lab MCP server). NULL (the default) preserves today's
-- behavior exactly: no exemption, public-upstream-only.

ALTER TABLE servers ADD COLUMN allowed_cidr TEXT;

COMMENT ON COLUMN servers.allowed_cidr IS
    'Explicit opt-in CIDR this server''s upstream_url is allowed to resolve into (e.g. for lab/internal deployments). NULL = no exemption from the public-upstream-only SSRF default.';
