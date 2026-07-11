"""AT3 — T5: live end-to-end coverage for lab-mcp-fetch, a vendored
adaptation of the official MCP reference "fetch" server
(modelcontextprotocol/servers, src/fetch). Mirrors
test_at3_catfacts_onboarding.py's pattern: seeded directly via
lab/seeder/sql (servers.sql/tools.sql, status='approved'/'active'), no
submission-wizard transition to drive, so this proves the seeded row is
reachable end-to-end through the real gateway -> auth -> entitlement -> OPA
-> egress-proxy -> a real external URL (example.com), and that the response
contains real fetched page content rather than a gate-chain failure wrapped
in an HTTP 200 — the human's explicit "test against a real, already-
implemented open-source MCP server" criterion (catfacts is self-built and
does not satisfy it; this does)."""
from __future__ import annotations

from conftest import call_upstream_tool, db_query


def test_lab_fetch_seeded_approved_and_active():
    """Confirms the seeder path landed the row in the state the invoke path
    requires — server_registry approved, tool_registry active."""
    server_status = db_query("SELECT status FROM server_registry WHERE name='lab-fetch'")
    assert server_status == "approved", server_status
    tool_status = db_query("SELECT status FROM tool_registry WHERE name='fetch-url'")
    assert tool_status == "active", tool_status


def test_fetch_url_real_upstream_call(alice_token):
    """Real call through the gateway -> lab-mcp-fetch -> lab-egress-proxy
    (squid, example.com allowlisted) -> example.com. Asserts the actual
    fetched page content (example.com's canonical "Example Domain" copy),
    not just the absence of an error."""
    result = call_upstream_tool(alice_token, "fetch-url", "fetch_url_tool",
                                {"url": "https://example.com", "max_length": 2000})
    assert isinstance(result, dict), result
    assert "error" not in result, result
    assert result.get("url") == "https://example.com", result
    content = result.get("content", "")
    assert isinstance(content, str) and "Example Domain" in content, result
