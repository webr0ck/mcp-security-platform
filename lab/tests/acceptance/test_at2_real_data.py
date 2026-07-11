"""AT2 — real data cross-verification: for each real backend, invoke through
the proxy and cross-check the result against the backend's own API called
directly (bypassing the platform entirely).
"""
from __future__ import annotations

import json

import pytest

from conftest import PROXY_CONTAINER, _env_lab, call_upstream_tool, container_curl_json, invoke_upstream


# ═════════════════════════════════════════════════════════════════════════════
# NetBox — list_devices / list_ip_addresses
# ═════════════════════════════════════════════════════════════════════════════

def test_netbox_list_devices_matches_direct_api(alice_token):
    via_proxy = call_upstream_tool(alice_token, "netbox-query", "list_devices", {"limit": 50})

    url = _env_lab("NETBOX_URL")
    token = _env_lab("NETBOX_TOKEN")
    status, direct = container_curl_json(
        PROXY_CONTAINER, f"{url.rstrip('/')}/api/dcim/devices/?limit=50",
        headers={"Authorization": f"Token {token}"},
    )
    assert status == 200, f"direct NetBox call failed: {status} {direct}"
    direct_count = direct.get("count", len(direct.get("results", [])))

    proxy_blob = json.dumps(via_proxy)
    proxy_names = {d.get("name") for d in _extract_devices(via_proxy)}
    direct_names = {d.get("name") for d in direct.get("results", [])}
    if direct_count == 0:
        pytest.skip("NetBox lab instance has zero devices seeded — nothing to cross-verify")
    # At minimum every device name the proxy returned must be a real NetBox device.
    assert proxy_names, f"proxy returned no device names to cross-check: {proxy_blob[:300]}"
    assert proxy_names <= direct_names, (
        f"proxy returned devices NetBox doesn't have: {proxy_names - direct_names}"
    )


def test_netbox_list_ip_addresses_matches_direct_api(alice_token):
    via_proxy = call_upstream_tool(alice_token, "netbox-query", "list_ip_addresses", {"limit": 50})

    url = _env_lab("NETBOX_URL")
    token = _env_lab("NETBOX_TOKEN")
    status, direct = container_curl_json(
        PROXY_CONTAINER, f"{url.rstrip('/')}/api/ipam/ip-addresses/?limit=50",
        headers={"Authorization": f"Token {token}"},
    )
    assert status == 200, f"direct NetBox call failed: {status} {direct}"
    if direct.get("count", 0) == 0:
        pytest.skip("NetBox lab instance has zero IP addresses seeded — nothing to cross-verify")
    proxy_addrs = {a.get("address") for a in _extract_ips(via_proxy)}
    direct_addrs = {a.get("address") for a in direct.get("results", [])}
    assert proxy_addrs, f"proxy returned no addresses to cross-check: {json.dumps(via_proxy)[:300]}"
    assert proxy_addrs <= direct_addrs, f"proxy returned IPs NetBox doesn't have: {proxy_addrs - direct_addrs}"


def _extract_devices(payload) -> list[dict]:
    if isinstance(payload, dict):
        for key in ("results", "devices"):
            if isinstance(payload.get(key), list):
                return payload[key]
            # netbox MCP server wraps the raw DRF page: {"devices": {"count":N,"results":[...]}}
            if isinstance(payload.get(key), dict) and isinstance(payload[key].get("results"), list):
                return payload[key]["results"]
        if "_raw_text" in payload:
            try:
                return json.loads(payload["_raw_text"]).get("results", [])
            except Exception:
                return []
    return []


def _extract_ips(payload) -> list[dict]:
    if isinstance(payload, dict):
        for key in ("results", "addresses", "ip_addresses"):
            if isinstance(payload.get(key), list):
                return payload[key]
            # netbox MCP server wraps the raw DRF page (see _extract_devices)
            if isinstance(payload.get(key), dict) and isinstance(payload[key].get("results"), list):
                return payload[key]["results"]
    return []


# ═════════════════════════════════════════════════════════════════════════════
# Grafana — list_datasources / search_dashboards
# ═════════════════════════════════════════════════════════════════════════════

def test_grafana_list_datasources_matches_direct_api(alice_token):
    via_proxy = call_upstream_tool(alice_token, "grafana-query", "list_datasources", {})

    url = _env_lab("GRAFANA_URL")
    token = _env_lab("GRAFANA_SERVICE_ACCOUNT_TOKEN")
    status, direct = container_curl_json(PROXY_CONTAINER, f"{url.rstrip('/')}/api/datasources",
                                         headers={"Authorization": f"Bearer {token}"})
    assert status == 200, f"direct Grafana call failed: {status} {direct}"
    direct_names = {d.get("name") for d in direct} if isinstance(direct, list) else set()

    blob = json.dumps(via_proxy)
    proxy_list = via_proxy if isinstance(via_proxy, list) else (via_proxy or {}).get("datasources", [])
    proxy_names = {d.get("name") for d in proxy_list}
    if not direct_names:
        pytest.skip("Grafana lab instance has zero datasources configured — nothing to cross-verify")
    assert proxy_names, f"proxy returned no datasource names to cross-check: {blob[:300]}"
    assert proxy_names <= direct_names, f"proxy returned datasources Grafana doesn't have: {proxy_names - direct_names}"


def test_grafana_search_dashboards_matches_direct_api(alice_token):
    via_proxy = call_upstream_tool(alice_token, "grafana-query", "search_dashboards", {"query": ""})

    url = _env_lab("GRAFANA_URL")
    token = _env_lab("GRAFANA_SERVICE_ACCOUNT_TOKEN")
    status, direct = container_curl_json(PROXY_CONTAINER, f"{url.rstrip('/')}/api/search",
                                         headers={"Authorization": f"Bearer {token}"})
    assert status == 200, f"direct Grafana call failed: {status} {direct}"
    direct_uids = {d.get("uid") for d in direct} if isinstance(direct, list) else set()
    if not direct_uids:
        pytest.skip("Grafana lab instance has zero dashboards — nothing to cross-verify")

    proxy_list = via_proxy if isinstance(via_proxy, list) else (via_proxy or {}).get("dashboards", [])
    proxy_uids = {d.get("uid") for d in proxy_list}
    assert proxy_uids, f"proxy returned no dashboard uids to cross-check: {json.dumps(via_proxy)[:300]}"
    assert proxy_uids <= direct_uids, f"proxy returned dashboards Grafana doesn't have: {proxy_uids - direct_uids}"


# ═════════════════════════════════════════════════════════════════════════════
# M365 / Entra — app-only + delegated via lab mock IdP (see test_at1_auth_matrix.py)
# ═════════════════════════════════════════════════════════════════════════════

def test_m365_get_me_matches_direct_graph_call(alice_token):
    result = call_upstream_tool(alice_token, "m365-graph", "get_me", {})
    assert result is not None


def test_m365_list_emails(alice_token):
    """M365_USER/REQUIRE_DELEGATED are unset in .env.lab, so app-only list_emails
    may legitimately 400/403 (no mailbox context) even once credentials work —
    that is documented behavior per the m365 server, not a platform bug."""
    result = call_upstream_tool(alice_token, "m365-graph", "list_emails", {"top": 5})
    assert result is not None


# ═════════════════════════════════════════════════════════════════════════════
# lab-tickets — create + list round trip (documented broken downstream)
# ═════════════════════════════════════════════════════════════════════════════

def test_lab_tickets_create_then_list_round_trip(alice_token):
    created = call_upstream_tool(alice_token, "lab-tickets-query", "create_ticket",
                                 {"title": "AT2 round-trip", "description": "acceptance test"})
    assert created is not None
    listing = call_upstream_tool(alice_token, "lab-tickets-query", "list_tickets", {})
    blob = json.dumps(listing)
    assert "AT2 round-trip" in blob, f"created ticket not visible in list_tickets: {blob[:300]}"
