# clean-mcp

Minimal echo MCP server. AT3 "clean onboarding" fixture — used by
`lab/tests/acceptance/test_at3_onboarding.py` to prove the full self-service
submission lifecycle (submit -> scan passed -> reviewer approve -> provide
running URL -> tools discovered quarantined -> activated -> entitled ->
invoked) works end-to-end against a server with no findings.
