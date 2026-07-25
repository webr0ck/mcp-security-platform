# entra-directory-mcp

Read-only Microsoft Entra ID / Graph directory MCP server (app-only
client_credentials). AT3 "real Entra directory onboarding" fixture — used by
`lab/tests/acceptance/test_at3_entra_directory_onboarding.py` to prove the
self-service `submit_mcp_server` MCP tool path (not the REST API) works
end-to-end for an `injection_mode=entra_client_credentials` server: submit ->
scan passed -> reviewer approve -> tools discovered -> entitle -> invoke
`list_users` against the real Microsoft Graph API.

This is a straight copy of `lab/mcp-servers/entra-directory/server.py` — it
must exist here, as its own clean git history, so the submission scanner has
a real repository to clone (`git_providers` host `lab-gitea-tls`, pushed by
`setup_gitea_fixtures.sh`) rather than scanning the platform's own source
tree.
