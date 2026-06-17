"""
mcphub_sdk.server — PlatformMCPServer: the single entrypoint for SDK users.

Wraps FastMCP with:
  - stateless_http=True (H11 MANDATORY: ContextVars reach tools only in stateless mode)
  - TransportSecuritySettings(enable_dns_rebinding_protection=False) (lab/behind-proxy)
  - _ContextMiddleware on the Starlette app (identity + credential + require_proxy)
  - Explicit /health route (H1: FastMCP does not auto-serve it)
  - HOST/PORT from env with sensible defaults

Usage:
    from mcphub_sdk import PlatformMCPServer, identity, credential

    srv = PlatformMCPServer("my-mcp", credential_env="MY_SERVICE_TOKEN")

    @srv.tool()
    async def whoami() -> dict:
        who = identity()
        return {"sub": who.sub, "role": who.role}

    if __name__ == "__main__":
        srv.run()
"""
from __future__ import annotations

import os

from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings

from .context import _ContextMiddleware, credential, identity  # noqa: F401 — re-exported


class PlatformMCPServer:
    """
    A FastMCP server pre-wired for the MCP Security Platform.

    Parameters
    ----------
    name:
        MCP server name (passed to FastMCP).
    credential_env:
        Optional env-var name used as fallback by credential().  When set,
        credential() returns os.environ[credential_env] on a proxied request
        that carries no Authorization header.  Un-proxied requests always get
        None regardless of this setting (H2 fail-closed).
    require_proxy:
        When True (default), any request without an X-User-Sub header is
        rejected with HTTP 403 before tools run — except GET /health.
        Set to False only in controlled test/dev scenarios.
    """

    def __init__(
        self,
        name: str,
        *,
        credential_env: str | None = None,
        require_proxy: bool = True,
    ) -> None:
        self.name = name
        self.credential_env = credential_env
        self.require_proxy = require_proxy

        # H11: stateless_http=True is MANDATORY.
        #
        # In FastMCP's default (stateful) streamable-http mode, tool handlers
        # run inside a long-lived session task group created at session-init
        # time.  A ContextVar set by BaseHTTPMiddleware on the *per-request*
        # task does NOT propagate into that group — identity()/credential()
        # would always return defaults ("anonymous"/None).
        #
        # With stateless_http=True every tool call is handled in a fresh task
        # spawned from the request context, so the ContextVars set by
        # _ContextMiddleware reach the tool.
        #
        # Confirmed working form (notes/server.py, 2026-06-18):
        #   mcp = FastMCP("notes-mcp", stateless_http=True)
        self._mcp = FastMCP(name, stateless_http=True)

        # Disable DNS-rebinding protection: this server sits behind the proxy
        # on an internal network; browser access is not expected.
        self._mcp.settings.transport_security = TransportSecuritySettings(
            enable_dns_rebinding_protection=False
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @property
    def mcp(self) -> FastMCP:
        """Underlying FastMCP instance, for advanced customisation."""
        return self._mcp

    def tool(self, *args, **kwargs):
        """Register a tool — delegates directly to FastMCP.tool().

        H6: this is a pure delegation (return self._mcp.tool(*args, **kwargs)),
        NOT a wrapper around the decorated function.  Wrapping would collapse
        the function's parameter list into *args/**kwargs, producing an empty
        or broken inputSchema in tools/list.
        """
        return self._mcp.tool(*args, **kwargs)

    def app(self):
        """Build and return the middlewared Starlette app.

        H5: the context middleware is ALWAYS installed — there is no code path
        that returns an un-middlewared app that could expose the env credential
        to un-proxied callers.

        H1: registers an explicit /health route because FastMCP does NOT
        auto-serve one.  Both .app() and .run() use this method, so health is
        always present.

        Middleware ordering matters in Starlette: middleware added via
        add_middleware wraps in LIFO order, so _ContextMiddleware added last
        runs first on incoming requests — before the MCP handlers and before
        the /health route handler.  /health is exempted from the proxy check
        inside _ContextMiddleware.dispatch().
        """
        starlette_app = self._mcp.streamable_http_app()

        # H1: explicit /health (FastMCP does not auto-serve this)
        async def _health_handler(request):
            from starlette.responses import JSONResponse

            return JSONResponse({"status": "ok", "server": self.name})

        starlette_app.add_route("/health", _health_handler, methods=["GET"])

        # H5: always middlewared — do this AFTER add_route so the middleware
        # wraps /health too (required: /health must be reachable without proxy
        # headers, handled by the path-check inside _ContextMiddleware.dispatch)
        starlette_app.add_middleware(
            _ContextMiddleware, require_proxy=self.require_proxy
        )

        return starlette_app

    def run(self, host: str | None = None, port: int | None = None) -> None:
        """Start uvicorn serving the middlewared app.

        Host and port are resolved from arguments, then HOST/PORT env vars,
        then defaults 0.0.0.0:8000 — matching all existing lab servers.
        """
        import uvicorn

        uvicorn.run(
            self.app(),
            host=host or os.getenv("HOST", "0.0.0.0"),
            port=int(port or os.getenv("PORT", "8000")),
            log_level="info",
        )
