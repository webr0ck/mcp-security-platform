"""
Option B fix — multi-host OIDC callback URL derivation.

Problem: PROXY_BASE_URL is a static config value. When a user reaches the proxy
from a different IP (LAN vs Tailscale), the redirect_uri in the PKCE flow uses the
configured IP, not the one the browser used. Keycloak rejects the callback because
the redirect_uri doesn't match what the browser sent.

Fix: when OIDC_TRUST_FORWARDED_HOST=True, _derive_callback_url() uses
X-Forwarded-Host (set by the gateway) or the Host header (direct access), so the
redirect_uri always matches what the browser sees. PROXY_BASE_URL still takes
precedence when set (backward-compatible; production should set it explicitly).

Security note: trusting the Host header is safe only when either:
  a) the proxy is behind a trusted reverse proxy that overwrites it, or
  b) Keycloak's valid redirect URI list restricts which hosts are accepted.
  The lab sets OIDC_TRUST_FORWARDED_HOST=true and uses a broad KC wildcard
  because ALL traffic is on trusted local/VPN networks.
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from starlette.requests import Request


def _make_request(host: str, forwarded_host: str | None = None,
                  forwarded_proto: str | None = None, scheme: str = "http") -> Request:
    headers = [(b"host", host.encode())]
    if forwarded_host:
        headers.append((b"x-forwarded-host", forwarded_host.encode()))
    if forwarded_proto:
        headers.append((b"x-forwarded-proto", forwarded_proto.encode()))
    scope = {
        "type": "http", "method": "GET", "path": "/api/v1/auth/oidc/login",
        "headers": headers, "query_string": b"",
        "client": ("127.0.0.1", 1234),
        "server": ("testserver", 80),
        "scheme": scheme,
    }
    return Request(scope)


@pytest.mark.unit
def test_derive_callback_uses_proxy_base_url_when_set():
    """PROXY_BASE_URL always wins when set — backward-compatible behavior."""
    from app.routers.oidc_browser import _derive_callback_url
    req = _make_request("203.0.113.10:8000")
    with patch("app.routers.oidc_browser.settings") as s:
        s.PROXY_BASE_URL = "http://203.0.113.10:8000"
        s.OIDC_TRUST_FORWARDED_HOST = True
        url = _derive_callback_url(req)
    assert url == "http://203.0.113.10:8000/api/v1/auth/oidc/callback"


@pytest.mark.unit
def test_derive_callback_uses_host_header_when_base_url_empty():
    """When PROXY_BASE_URL is empty string, fall back to the Host header."""
    from app.routers.oidc_browser import _derive_callback_url
    req = _make_request("203.0.113.10:8000")
    with patch("app.routers.oidc_browser.settings") as s:
        s.PROXY_BASE_URL = ""
        s.OIDC_TRUST_FORWARDED_HOST = True
        url = _derive_callback_url(req)
    assert url == "http://203.0.113.10:8000/api/v1/auth/oidc/callback"


@pytest.mark.unit
def test_derive_callback_prefers_x_forwarded_host():
    """X-Forwarded-Host (set by the gateway) takes precedence over the Host header."""
    from app.routers.oidc_browser import _derive_callback_url
    req = _make_request(host="10.0.0.1:8000", forwarded_host="203.0.113.10:8000",
                        forwarded_proto="http")
    with patch("app.routers.oidc_browser.settings") as s:
        s.PROXY_BASE_URL = ""
        s.OIDC_TRUST_FORWARDED_HOST = True
        url = _derive_callback_url(req)
    assert url == "http://203.0.113.10:8000/api/v1/auth/oidc/callback"


@pytest.mark.unit
def test_derive_callback_trust_forwarded_false_uses_base_url():
    """When OIDC_TRUST_FORWARDED_HOST=False (default), Host header is ignored
    and PROXY_BASE_URL is always used (existing production behavior)."""
    from app.routers.oidc_browser import _derive_callback_url
    req = _make_request("203.0.113.10:8000")
    with patch("app.routers.oidc_browser.settings") as s:
        s.PROXY_BASE_URL = "http://203.0.113.10:8000"
        s.OIDC_TRUST_FORWARDED_HOST = False
        url = _derive_callback_url(req)
    assert url == "http://203.0.113.10:8000/api/v1/auth/oidc/callback"


@pytest.mark.unit
def test_derive_callback_tailscale_ip_works():
    """Direct Tailscale access with no forwarded headers uses Tailscale IP."""
    from app.routers.oidc_browser import _derive_callback_url
    req = _make_request("203.0.113.10:8000")
    with patch("app.routers.oidc_browser.settings") as s:
        s.PROXY_BASE_URL = ""
        s.OIDC_TRUST_FORWARDED_HOST = True
        url = _derive_callback_url(req)
    assert url == "http://203.0.113.10:8000/api/v1/auth/oidc/callback"
