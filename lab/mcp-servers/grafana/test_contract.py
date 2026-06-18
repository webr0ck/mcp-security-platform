"""Contract test: grafana MCP server forwards injected Authorization header to Grafana API."""
import sys
import os
import types
from unittest.mock import AsyncMock, patch, MagicMock


def _stub_mcp_modules():
    """Stub out mcp.server.fastmcp and starlette so server.py can be imported without them."""
    # Stub mcp hierarchy
    mcp_mod = types.ModuleType("mcp")
    mcp_server = types.ModuleType("mcp.server")
    mcp_server_fastmcp = types.ModuleType("mcp.server.fastmcp")
    mcp_server_transport = types.ModuleType("mcp.server.transport_security")

    class _FakeFastMCP:
        def __init__(self, *a, **kw):
            self.settings = MagicMock()
        def tool(self):
            def decorator(fn):
                return fn
            return decorator
        def streamable_http_app(self):
            app = MagicMock()
            app.add_middleware = MagicMock()
            return app

    class _FakeTransportSecuritySettings:
        def __init__(self, **kw):
            pass

    mcp_server_fastmcp.FastMCP = _FakeFastMCP
    mcp_server_transport.TransportSecuritySettings = _FakeTransportSecuritySettings

    mcp_mod.server = mcp_server
    mcp_server.fastmcp = mcp_server_fastmcp
    mcp_server.transport_security = mcp_server_transport

    sys.modules.setdefault("mcp", mcp_mod)
    sys.modules.setdefault("mcp.server", mcp_server)
    sys.modules.setdefault("mcp.server.fastmcp", mcp_server_fastmcp)
    sys.modules.setdefault("mcp.server.transport_security", mcp_server_transport)

    # Stub starlette.middleware.base
    starlette = types.ModuleType("starlette")
    starlette_mw = types.ModuleType("starlette.middleware")
    starlette_mw_base = types.ModuleType("starlette.middleware.base")

    class _BaseHTTPMiddleware:
        def __init__(self, app=None, **kw):
            self.app = app
        async def dispatch(self, request, call_next):
            return await call_next(request)

    starlette_mw_base.BaseHTTPMiddleware = _BaseHTTPMiddleware
    starlette.middleware = starlette_mw
    starlette_mw.base = starlette_mw_base

    sys.modules.setdefault("starlette", starlette)
    sys.modules.setdefault("starlette.middleware", starlette_mw)
    sys.modules.setdefault("starlette.middleware.base", starlette_mw_base)

    # Stub uvicorn
    uvicorn_mod = types.ModuleType("uvicorn")
    uvicorn_mod.run = MagicMock()
    sys.modules.setdefault("uvicorn", uvicorn_mod)


_stub_mcp_modules()

# Now import the server module (stubs are in place)
sys.path.insert(0, os.path.dirname(__file__))
import server as _server  # noqa: E402


def test_query_dashboards_forwards_auth_header():
    """The server must forward the injected Authorization header verbatim to Grafana."""
    token = _server._auth_header.set("Bearer glsa_test_token_123")
    captured_headers = {}

    async def mock_get(url, *, headers, params=None, timeout=None):
        captured_headers.update(headers)
        resp = MagicMock()
        resp.raise_for_status = lambda: None
        resp.json.return_value = [{"title": "Test Dashboard", "uid": "abc123"}]
        return resp

    import asyncio
    with patch("httpx.AsyncClient") as mock_client:
        mock_client.return_value.__aenter__ = AsyncMock(return_value=MagicMock(get=mock_get))
        mock_client.return_value.__aexit__ = AsyncMock(return_value=False)
        result = asyncio.run(_server.query_dashboards("test"))

    _server._auth_header.reset(token)

    assert captured_headers.get("Authorization") == "Bearer glsa_test_token_123"
    assert "dashboards" in result


def test_missing_auth_header_raises():
    """When no Authorization header is set, _grafana_headers() must raise RuntimeError."""
    import contextvars
    # Set the ContextVar to empty (simulates no broker injection)
    tok = _server._auth_header.set("")
    try:
        try:
            _server._grafana_headers()
            assert False, "Expected RuntimeError was not raised"
        except RuntimeError as exc:
            assert "broker" in str(exc).lower() or "authorization" in str(exc).lower()
    finally:
        _server._auth_header.reset(tok)
