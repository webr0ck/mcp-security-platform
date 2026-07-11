"""AT3 — T6: live end-to-end coverage for T5's new server (lab-catfacts /
catfacts-live), the first 'none'-injection-mode server in this lab that talks
to a REAL external third-party API (catfact.ninja) instead of itself or a
local/mocked backend.

Unlike test_at3_onboarding.py's submission-lifecycle walk (submit via REST ->
scan -> reviewer approve -> activate -> entitle), lab-catfacts was registered
directly via the seeder SQL path (lab/seeder/sql/servers.sql + tools.sql,
status='approved'/'active' from the INSERT itself) rather than through the
self-service submission wizard — so there is no pending->approved transition
to drive here. What this test proves instead, and what had zero live coverage
before it: that the seeded row is genuinely reachable end-to-end through the
real gateway -> auth -> entitlement -> OPA -> egress-proxy -> catfact.ninja
chain, for BOTH tools the server exposes, and that the response is real
upstream data (not a gate-chain failure silently wrapped in a 200 — see
call_upstream_tool's docstring on why a bare absence-of-error isn't enough).
"""
from __future__ import annotations

from conftest import call_upstream_tool, db_query


def test_lab_catfacts_seeded_approved_and_active():
    """Confirms the seeder path actually landed the row in the state the
    invoke path requires — server_registry approved, tool_registry active."""
    server_status = db_query("SELECT status FROM server_registry WHERE name='lab-catfacts'")
    assert server_status == "approved", server_status
    tool_status = db_query("SELECT status FROM tool_registry WHERE name='catfacts-live'")
    assert tool_status == "active", tool_status


def test_get_fact_real_upstream_call(alice_token):
    """Real call through the gateway -> lab-mcp-catfacts -> lab-egress-proxy
    (squid, catfact.ninja allowlisted) -> catfact.ninja. Asserts the actual
    upstream JSON shape (fact/length), not just the absence of an error."""
    result = call_upstream_tool(alice_token, "catfacts-live", "get_fact", {})
    assert isinstance(result, dict), result
    assert "fact" in result and isinstance(result["fact"], str) and result["fact"], result
    assert "length" in result, result


def test_get_breeds_real_upstream_call(alice_token):
    """Same chain, second tool — catfact.ninja's paginated breeds endpoint."""
    result = call_upstream_tool(alice_token, "catfacts-live", "get_breeds", {"limit": 3})
    assert isinstance(result, dict), result
    breeds = result.get("breeds")
    assert isinstance(breeds, list) and len(breeds) == 3, result
    assert all("breed" in b and "country" in b for b in breeds), result
