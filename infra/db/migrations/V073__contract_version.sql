-- V073__contract_version.sql
-- CR-06 (WP-B3 phase 6): server_registry.contract_version.
--
-- Records which version of docs/reference/mcp-server-compatibility-contract.md
-- (+ its machine-testable subset, mcp-server-contract.schema.json /
-- contract_check.py) a server was last verified against. Written by
-- deploy_verifier.verify_server (platform-managed path) and
-- submission.py's provide_running_url (self-hosted path) — the two places
-- that run the shared run_verification_probes helper. NULL = never
-- verified against a contract_version-aware verify pass.
--
-- No GRANT changes needed — additive column on a table proxy_app already
-- owns in full (server_registry); V003's blanket per-table GRANTs already
-- cover it.

ALTER TABLE server_registry
    ADD COLUMN IF NOT EXISTS contract_version TEXT;

COMMENT ON COLUMN server_registry.contract_version IS
    'CR-06 (WP-B3 phase 6): version of the MCP server compatibility contract '
    '(docs/reference/mcp-server-compatibility-contract.md, currently "v0.1") '
    'this server was verified against by run_verification_probes. NULL until '
    'the first successful verify pass.';
