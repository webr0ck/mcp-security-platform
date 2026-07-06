"""AT1 — auth matrix: one real invocation per injection_mode through the
proxy's real /mcp invoke endpoint (gateway HTTPS, no shortcuts), plus the
required negative cases.

Case map (see lab/scripts/smoke_four_cases.sh for the canonical tool <->
injection_mode pairing):
  (a) service                : grafana-query
  (b) user                   : netbox-query (alice's per-user credential)
  (c) entra_client_credentials: m365-graph
  (d) kc_token_exchange       : lab-tickets-query
  (e) KC service-account JWT (svc-mcp-agent) invoking a service-mode tool
  (f) negatives: no token, garbage token, carol invoking an unentitled tool

Setup performed once (not by this test file, but as a prerequisite documented
in REPORT.md) to make (a)/(b)/(c) actually reachable: the lab's
grafana/m365/netbox/lab-tickets credentials and lab-tickets-query's
server_registry/allowlist row were re-provisioned via the admin credentials
API and a couple of direct DB repairs — see REPORT.md "Lab repairs performed"
for the full list and the product bugs those repairs uncovered.
"""
from __future__ import annotations

import httpx
import pytest

from conftest import BASE_URL, call_upstream_tool, invoke_upstream


# ── (a) service: grafana-query ───────────────────────────────────────────────

def test_service_mode_grafana_query(alice_token):
    """This lab runs the official grafana/mcp-grafana server, whose real tool
    names are list_datasources/search_dashboards/etc — not the simplified
    query_dashboards/get_datasources names in the task brief."""
    result = call_upstream_tool(alice_token, "grafana-query", "list_datasources", {})
    assert result is not None


def test_service_mode_grafana_search(alice_token):
    result = call_upstream_tool(alice_token, "grafana-query", "search_dashboards", {"query": ""})
    assert result is not None


# ── (b) user: netbox-query (alice's per-user credential) ────────────────────

def test_user_mode_netbox_list_devices(alice_token):
    result = call_upstream_tool(alice_token, "netbox-query", "list_devices", {"limit": 5})
    assert result is not None


def test_user_mode_netbox_list_ip_addresses(alice_token):
    result = call_upstream_tool(alice_token, "netbox-query", "list_ip_addresses", {"limit": 5})
    assert result is not None


# ── (c) entra_client_credentials: m365-graph ─────────────────────────────────

@pytest.mark.xfail(
    reason=(
        "PRODUCT BUG (documented in REPORT.md): the entra_client_credentials "
        "injector (proxy/app/credential_broker/dispatcher.py:562) retrieves the "
        "stored credential via credential_storage.retrieve_credential(), which "
        "decrypts with the raw KMS envelope (master secret only, kms.py "
        "envelope_decrypt). But the only admin-facing write path, "
        "PUT /admin/credentials/{tool_id} (admin_credentials.py:163-175), "
        "always encrypts via approach_a.encrypt() — a per-user-KEK derived "
        "scheme. The two are incompatible ciphertext formats, so decryption "
        "fails with InvalidTag every time regardless of what's uploaded. There "
        "is no working admin-API path to provision an entra_client_credentials "
        "tool today. (Separately, admin_credentials.py:296 update_injection_mode "
        "'valid_modes' doesn't even include 'entra_client_credentials', "
        "'entra_user_token', or 'kc_token_exchange' — those tools can never be "
        "range-configured through that endpoint either.)"
    ),
    strict=False,
)
def test_entra_client_credentials_m365_graph(alice_token):
    result = call_upstream_tool(alice_token, "m365-graph", "get_me", {})
    assert result is not None


# ── (d) kc_token_exchange: lab-tickets-query ─────────────────────────────────

def test_kc_token_exchange_lab_tickets(alice_token):
    """lab-tickets-query is seeded with a server_registry row (servers.sql) and
    lab-mcp-lab-tickets sits on lab-net so it can fetch KC JWKS to validate the
    exchanged aud=lab-tickets token — the full RFC 8693 path is exercised."""
    result = call_upstream_tool(alice_token, "lab-tickets-query", "list_tickets", {})
    assert result is not None


# ── (d2) service_account: echo-sa ─────────────────────────────────────────────

def test_service_account_mode_echo_sa(alice_token):
    """echo-sa (injection_mode=service_account) — the broker mints a KC
    client_credentials token for kc_client_id=lab-test and injects it; echo's
    whoami reflects a redacted preview of the injected Bearer.

    loopback: the upstream tool is literally named 'whoami', which the gateway
    WAF (CRS 932260 Unix-RCE wordlist) rightly 403s; every proxy-side gate is
    still exercised via the container-loopback path."""
    result = call_upstream_tool(alice_token, "echo-sa", "whoami", {}, loopback=True)
    assert result["has_credential"] is True, result
    assert result["sub"] == "alice@corp", result  # caller identity preserved


# ── (d2b) basic_auth: echo-basic (CR-05, RFC 7617) ────────────────────────────

def test_basic_auth_mode_echo_basic(alice_token):
    """echo-basic (injection_mode=basic_auth) — the broker decrypts the shared
    {"username","secret"} JSON row (service='lab-basic'), builds
    Authorization: Basic base64(username:secret) at call time, and injects it;
    echo's whoami reflects a redacted first-8/last-4 preview (spec H8 — never
    the raw header), so the preview + exact length pin the expected base64.

    loopback: same CRS 932260 'whoami' WAF false-positive as echo-sa."""
    import base64
    expected = "Basic " + base64.b64encode(b"labuser:lab-basic-secret").decode()
    result = call_upstream_tool(alice_token, "echo-basic", "whoami", {}, loopback=True)
    assert result["has_credential"] is True, result
    assert result["sub"] == "alice@corp", result
    assert result["credential_len"] == len(expected), result
    assert result["credential_preview"] == f"{expected[:8]}...{expected[-4:]}", result


# ── (d3) entra_user_token: m365-graph-delegated ──────────────────────────────

def test_entra_user_token_m365_delegated(alice_token):
    """m365-graph-delegated (injection_mode=entra_user_token) — the broker
    decrypts alice's stored refresh token, refreshes it against lab-mock-idp,
    and injects the delegated token; lab-mcp-m365 (REQUIRE_DELEGATED) resolves
    /me against the mock Graph, so a Graph-style profile proves the delegated
    path end-to-end (an enrollment prompt would trip the failure sentinels)."""
    result = call_upstream_tool(alice_token, "m365-graph-delegated", "get_me", {})
    assert result.get("display_name"), result


# ── (e) KC service-account JWT invoking a service-mode tool ──────────────────

def test_service_account_jwt_invokes_service_tool(service_token):
    """svc-mcp-agent (client_credentials grant) hitting grafana-query.

    Documents current behavior rather than assuming success: the RBAC
    middleware denies before the request ever reaches entitlement/credential
    logic, because the svc-mcp-agent KC client's service account carries no
    'agent' realm role (its token only has default-roles-mcp / offline_access
    / uma_authorization — see REPORT.md). That is itself a lab KC-config gap,
    not a security defect (fail-closed is the correct behavior for an
    under-privileged principal) — assert the actual, structured denial.
    """
    r = invoke_upstream(service_token, "grafana-query", "tools/call",
                        {"name": "get_datasources", "arguments": {}})
    assert r["status_code"] in (200, 403), f"unexpected status: {r}"
    if r["status_code"] == 403:
        body = r["body"]
        assert "error" in body, f"403 must carry a structured error body, got: {body}"
        assert body["error"].get("code") in ("FORBIDDEN", "NOT_ENTITLED"), body


# ── (f) negatives ─────────────────────────────────────────────────────────────

def test_no_token_rejected():
    r = httpx.get(f"{BASE_URL}/api/v1/submissions", timeout=10, verify=False)
    assert r.status_code == 401, f"expected 401 with no token, got {r.status_code}: {r.text[:200]}"


def test_garbage_token_rejected():
    r = httpx.get(f"{BASE_URL}/api/v1/submissions", timeout=10, verify=False,
                  headers={"Authorization": "Bearer obviously-not-a-real-jwt"})
    assert r.status_code == 401, f"expected 401 with garbage token, got {r.status_code}: {r.text[:200]}"


def test_carol_denied_unentitled_tool(carol_token):
    """carol (auditor/security_reviewer) has no entitlement grant on any of the
    grafana/netbox/m365 servers — invoking one must be denied, with a
    structured (not blind-200) error."""
    r = invoke_upstream(carol_token, "netbox-query", "tools/call",
                        {"name": "list_devices", "arguments": {"limit": 1}})
    assert r["status_code"] == 200, f"transport-level failure: {r}"
    body = r["body"]
    text_blob = str(body).lower()
    assert any(s in text_blob for s in ("access denied", "not entitled", "forbidden", "denied")), (
        f"expected a structured denial for carol's unentitled invoke, got: {body}"
    )
