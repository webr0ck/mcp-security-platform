"""AT0 — preflight: proxy healthy, Keycloak reachable, every real backend
reachable DIRECTLY (not through the platform), each with a clear failure
reason. Run this group first — if it's red, AT1-AT3 failures are noise.
"""
from __future__ import annotations

import httpx
import pytest

from conftest import KC_REALM, KC_URL, PROXY_CONTAINER, _env_lab, container_curl_json, proxy_exec_json


def test_proxy_health_all_ok():
    """Proxy /health (from inside its own network namespace — see conftest
    docstring) must report every dependency ok."""
    status, body = proxy_exec_json("/health")
    assert status == 200, f"proxy /health returned HTTP {status}: {body}"
    assert body.get("status") == "ok", f"proxy status not ok: {body}"
    services = body.get("services", {})
    bad = {k: v for k, v in services.items() if v != "ok"}
    assert not bad, f"proxy dependency unhealthy: {bad} (full: {services})"


def test_keycloak_realm_reachable():
    last_exc = None
    for path in (f"/realms/{KC_REALM}", "/health/ready", "/health"):
        try:
            r = httpx.get(f"{KC_URL}{path}", timeout=10)
            if r.status_code == 200:
                return
        except httpx.HTTPError as exc:
            last_exc = exc
    pytest.fail(f"Keycloak not reachable at {KC_URL} (realm={KC_REALM}); last error: {last_exc}")


def test_netbox_reachable_directly():
    """NETBOX_URL in .env.lab is an internal container hostname (http://lab-netbox:8080),
    not reachable from the host — hit it from inside mcp-proxy's network namespace,
    which shares lab-net with lab-netbox. This is still a call straight to NetBox's
    own REST API, bypassing the platform's tool-invocation layer entirely."""
    url = _env_lab("NETBOX_URL")
    token = _env_lab("NETBOX_TOKEN")
    assert url, "NETBOX_URL not set in .env.lab"
    assert token, "NETBOX_TOKEN not set in .env.lab"
    status, body = container_curl_json(PROXY_CONTAINER, f"{url.rstrip('/')}/api/status/",
                                       headers={"Authorization": f"Token {token}"})
    assert status == 200, f"NetBox /api/status/ returned {status}: {body}"
    assert "netbox-version" in body, f"unexpected NetBox status body: {body}"


def test_grafana_reachable_directly():
    """Same rationale as NetBox above — GRAFANA_URL is internal-only."""
    url = _env_lab("GRAFANA_URL")
    token = _env_lab("GRAFANA_SERVICE_ACCOUNT_TOKEN")
    assert url, "GRAFANA_URL not set in .env.lab"
    assert token, "GRAFANA_SERVICE_ACCOUNT_TOKEN not set in .env.lab"
    h = {"Authorization": f"Bearer {token}"}
    status, body = container_curl_json(PROXY_CONTAINER, f"{url.rstrip('/')}/api/health", headers=h)
    assert status == 200, f"Grafana /api/health returned {status}: {body}"
    status2, body2 = container_curl_json(PROXY_CONTAINER, f"{url.rstrip('/')}/api/search", headers=h)
    assert status2 == 200, f"Grafana /api/search returned {status2}: {body2}"


def test_entra_reachable_directly():
    """Client-credentials token from Entra, then a live Graph call."""
    tenant = _env_lab("AZURE_TENANT_ID")
    client_id = _env_lab("AZURE_CLIENT_ID")
    client_secret = _env_lab("AZURE_CLIENT_SECRET")
    assert tenant and client_id and client_secret, "AZURE_TENANT_ID/CLIENT_ID/CLIENT_SECRET must be set in .env.lab"

    token_url = f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
    r = httpx.post(token_url, data={
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
        "scope": "https://graph.microsoft.com/.default",
    }, timeout=20)
    assert r.status_code == 200, f"Entra token endpoint returned {r.status_code}: {r.text[:300]}"
    access_token = r.json()["access_token"]

    graph = httpx.get("https://graph.microsoft.com/v1.0/users?$top=1",
                      headers={"Authorization": f"Bearer {access_token}"}, timeout=20)
    assert graph.status_code == 200, f"Graph /v1.0/users returned {graph.status_code}: {graph.text[:300]}"
