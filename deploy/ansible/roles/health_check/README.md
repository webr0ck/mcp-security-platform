# health_check

Post-deploy readiness (mcphubd directly, then through the gateway) plus
`files/smoke_test.sh`, which exercises the real chain — auth (client_credentials
against the configured IDP) -> policy (one allowed + one explicitly denied
tools/call, asserting the deny is actually rejected, not silently allowed)
-> invoke -> audit (`GET /api/v1/audit/events?request_id=...` must show the
allowed call's record). This is deliberately NOT just a port/TCP check —
"port is open" tells you nothing about whether the enforcement chain in
`rs/ARCHITECTURE.md` ("Enforcement order in `invoke`") is actually wired.

Requires two fixture tools registered against every environment:
`smoke-allowed-tool` (any role may call it, policy allows) and
`smoke-denied-tool` (policy always denies it) — register these once per env
via the same server-registration path real MCP servers use; they can point
at the `loadgen echo-server` fixture or any trivial stub, since the smoke
test only cares about the gateway's own decision, not backend behavior.

The smoke-test service account's `client_secret` is read from Vault
(`vault_mcphubd_creds_path/smoke-test`) at run time — same pattern as every
other secret in this repo, never committed.

## Pre-deploy check

Pre-deploy ("is the new digest pullable") lives in `playbooks/deploy.yml`
itself, not here — it needs the *candidate* digest before anything in this
role's post-deploy checks has meaning, so it runs earlier in that
playbook's block.
