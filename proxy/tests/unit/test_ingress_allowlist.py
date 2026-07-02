"""SEC-05 regression: the ingress guard blocks non-gateway peers.

An acceptance-test run found MCP backend containers could dial proxy:8000 back
over their per-backend bridge net (a 200 leak). IngressAllowlistMiddleware rejects
any TCP peer that isn't the gateway or loopback. These checks pin the allow/deny
decision so a refactor can't silently re-open backend->proxy reachability.
"""
import asyncio
from types import SimpleNamespace

from app.middleware.ingress import IngressAllowlistMiddleware


def _mw(trusted):
    # app=None is fine — we never call BaseHTTPMiddleware machinery, only our helpers.
    return IngressAllowlistMiddleware(app=None, trusted_hosts=trusted)


def test_loopback_always_allowed():
    assert _mw(trusted=[])._allowed("127.0.0.1") is True
    assert _mw(trusted=[])._allowed("::1") is True


def test_backend_peer_denied():
    # An mcp-echo-net backend IP is not the gateway/loopback → denied.
    assert _mw(trusted=[])._allowed("10.89.13.3") is False


def test_trusted_host_resolves_and_allows():
    # 'localhost' resolves to loopback → allowed.
    assert _mw(trusted=["localhost"])._allowed("127.0.0.1") is True


def test_resolved_gateway_ip_allowed():
    mw = _mw(trusted=[])
    mw._allow.add("10.89.4.13")  # simulate resolved gateway IP
    assert mw._allowed("10.89.4.13") is True


def test_dispatch_denies_backend_with_403():
    mw = _mw(trusted=[])
    called = {"next": False}

    async def call_next(_req):
        called["next"] = True
        return SimpleNamespace(status_code=200)

    req = SimpleNamespace(
        client=SimpleNamespace(host="10.89.13.3"),
        url=SimpleNamespace(path="/health"),
    )
    resp = asyncio.run(mw.dispatch(req, call_next))
    assert resp.status_code == 403
    assert called["next"] is False  # blocked BEFORE reaching the app
