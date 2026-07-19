"""AT3b — self-service ownership regression, driven through the REAL MCP tool
(submit_mcp_server on the self-service server), not the submissions REST API
directly.

Root cause (see T2 commit 66dcb8f, proxy/app/routers/submission.py
_effective_owner): the self-service MCP server used to call the submissions
API with its own service credential (client_id=self-service, formerly
lab-self-service before the server was unified into one default across every
environment — docs/mcp-server-onboarding.md §10). There was no channel
for the submissions API to learn the real calling user, so every submission
made through the MCP tool — as opposed to a caller hitting the REST API with
their own session token — landed with server_registry.owner_sub =
'self-service' instead of the real submitter. AT3 (test_at3_onboarding.py)
only ever drove the REST API directly with alice's own token, so it could
never have caught this: it was never possible for that path to observe the
service-account misattribution in the first place.

This test closes that gap: it calls submit_mcp_server as bob through the real
gateway /mcp endpoint (the same path a real MCP client uses), then reads back
server_registry.owner_sub for the resulting submission and asserts it is
bob's own sub -- proving the X-On-Behalf-Of trust-bridge (T2) actually carries
the real caller identity through this specific tool-call path, not just
through a direct REST call. If a future change reintroduces the service
account as owner, this test fails.
"""
from __future__ import annotations

import json
import time
import uuid

import httpx
import pytest

from conftest import BASE_URL, db_query, mcp_session_headers


@pytest.fixture(scope="module", autouse=True)
def _bob_granted_submit_mcp_server():
    """OPA gates invoke_tool by data.mcp_grants[client_id].allowed_tools
    (client_grants table, synced to OPA every 60s by opa_data_sync.py — see
    that module's docstring), NOT the entitlement table. bob's seeded grant
    only covers 'ping'. The proper write path is POST /api/v1/admin/grants,
    but neither alice nor carol (this suite's only live tokens) actually
    holds the admin/platform_admin role in the lab (role_assignments only
    has 'bootstrap'=admin, no human token) -- so mirror this suite's existing
    direct-DB setup pattern (test_at3_onboarding's trust_tier UPDATE, taint
    Redis DEL) and wait out one reconcile cycle for OPA to pick it up."""
    existing = db_query("SELECT allowed_tools::text, allowed_tags::text, max_risk_level "
                        "FROM client_grants WHERE client_id='bob@corp'")
    if "submit_mcp_server" in existing:
        return
    tools_text, tags_text, risk = existing.split("|") if existing else ("[]", "[]", "medium")
    tools = json.loads(tools_text) if tools_text else []
    tags = json.loads(tags_text) if tags_text else []
    if "submit_mcp_server" not in tools:
        tools.append("submit_mcp_server")
    db_query(
        "UPDATE client_grants SET allowed_tools=" + f"'{json.dumps(tools)}'::jsonb, "
        f"updated_at=NOW() WHERE client_id='bob@corp'"
    )
    time.sleep(65)  # opa_data_sync's 60s reconcile loop must pick this up


def test_submit_mcp_server_via_gateway_attributes_real_caller_as_owner(bob_token):
    # This test's own fixture never went through submit_for_review, so it's
    # invisible to run_full_acceptance.sh's at3-clean-%/at3-malicious-% cleanup
    # step and every run left a permanent draft/pending row behind — one
    # surfaced live in the portal's MCP Servers tab, where an admin trying to
    # "Approve" it hit the D3 dual-control consent-token check (this row was
    # never registered through that flow, so no token exists for it) with a
    # confusing owner_consent_required error. Soft-delete unconditionally at
    # the end of this test, success or failure — never leave it live.
    name = f"at3b-selfservice-{uuid.uuid4().hex[:8]}"
    headers = mcp_session_headers(bob_token)
    # self-service is a multi-method registry tool like grafana-query/netbox-query
    # (see conftest.invoke_upstream) — invoke_tool needs {tool_name, method:
    # "tools/call", arguments: {name, arguments}}, not a flat {tool_name,
    # arguments} shape (that shape silently returns the upstream's tools/list
    # instead of calling anything, confirmed by hand against the live gateway).
    try:
        submit_args = {
            "name": name,
            "description": "AT3b ownership regression fixture",
            "injection_mode": "none",
            "data_categories": ["public"],
            "has_write_ops": False,
            "upstream_url": "http://at3b-placeholder:8000/mcp",
        }
        r = httpx.post(f"{BASE_URL}/mcp", headers=headers, verify=False, timeout=30,
            json={"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                  "params": {"name": "invoke_tool",
                             "arguments": {"tool_name": "submit_mcp_server", "method": "tools/call",
                                          "arguments": {"name": "submit_mcp_server", "arguments": submit_args}}}})
        assert r.status_code == 200, f"submit_mcp_server call failed: {r.status_code} {r.text}"
        body = r.json()
        assert "error" not in body, f"JSON-RPC error on submit_mcp_server: {body}"
        blob = json.dumps(body).lower()
        for bad in ("not entitled", "access denied", "not found in registry"):
            assert bad not in blob, f"gate-chain failure leaked through: {blob[:400]}"

        server_id = db_query(f"SELECT server_id::text FROM server_registry WHERE name='{name}'")
        assert server_id, f"no server_registry row created for {name!r}: {body}"

        owner_sub = db_query(f"SELECT owner_sub FROM server_registry WHERE server_id='{server_id}'")
        assert owner_sub != "self-service", (
            "REGRESSION: submit_mcp_server via the real gateway attributed ownership to the "
            "self-service tool's own service account instead of the real caller (bob) -- this is "
            "exactly the bug T2 fixed via X-On-Behalf-Of + submission_service role in "
            "proxy/app/routers/submission.py:_effective_owner."
        )
        assert owner_sub == "bob@corp", f"expected owner_sub='bob@corp', got {owner_sub!r}"
    finally:
        db_query(f"UPDATE server_registry SET deleted_at=now() "
                 f"WHERE name='{name}' AND deleted_at IS NULL")
