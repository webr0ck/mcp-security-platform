"""Contract test: two different callers get two different injected tokens (user mode, Case 3)."""
import sys
import os
import types
from unittest.mock import AsyncMock, MagicMock, patch


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


def test_different_callers_get_different_tokens():
    """User mode: alice's token != bob's token (both get their own injected token)."""
    import asyncio

    async def run_as(user_token):
        tok = _server._auth_header.set(f"Token {user_token}")
        captured = {}

        async def mock_get(url, *, headers, params=None, timeout=None):
            captured["Authorization"] = headers.get("Authorization", "")
            resp = MagicMock()
            resp.raise_for_status = lambda: None
            resp.json.return_value = {"count": 0, "results": []}
            return resp

        with patch("httpx.AsyncClient") as mc:
            mc.return_value.__aenter__ = AsyncMock(return_value=MagicMock(get=mock_get))
            mc.return_value.__aexit__ = AsyncMock(return_value=False)
            await _server.list_devices()

        _server._auth_header.reset(tok)
        return captured.get("Authorization", "")

    alice_header = asyncio.run(run_as("netbox-token-alice"))
    bob_header = asyncio.run(run_as("netbox-token-bob"))

    assert alice_header == "Token netbox-token-alice"
    assert bob_header == "Token netbox-token-bob"
    assert alice_header != bob_header, "Different callers must use different tokens"


def test_missing_token_raises():
    """When no Authorization header is set, _netbox_headers() must raise RuntimeError."""
    tok = _server._auth_header.set("")  # no token injected
    try:
        try:
            _server._netbox_headers()
            assert False, "Expected RuntimeError was not raised"
        except RuntimeError as exc:
            assert "authorization" in str(exc).lower() or "broker" in str(exc).lower()
    finally:
        _server._auth_header.reset(tok)
