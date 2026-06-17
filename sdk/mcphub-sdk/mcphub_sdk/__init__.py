"""
mcphub_sdk — MCP-Server Integration SDK for the MCP Security Platform.

Public API
----------
PlatformMCPServer   Wraps FastMCP with stateless_http, require_proxy, /health,
                    and the context middleware.  Primary entrypoint for SDK users.
identity()          Returns Identity(sub, role) from proxy-injected headers.
credential()        Returns the injected Authorization token (prefix-stripped),
                    with optional env-var fallback when the request is proxied.
                    NEVER returns the env token on an un-proxied request (H2).
Identity            Frozen dataclass: sub: str, role: str.

Quick start
-----------
    from mcphub_sdk import PlatformMCPServer, identity, credential

    srv = PlatformMCPServer("echo-mcp", credential_env="SERVICE_TOKEN")

    @srv.tool()
    async def whoami() -> dict:
        who = identity()
        return {"sub": who.sub, "role": who.role}

    if __name__ == "__main__":
        srv.run()

Security notes
--------------
- Identity comes exclusively from X-User-Sub / X-User-Role headers injected
  by the platform proxy.  Direct callers (no proxy) always resolve as
  Identity(sub="anonymous", role="agent").
- credential() env fallback fires only on proxied requests (X-User-Sub present).
  Un-proxied callers NEVER receive the env service credential.
- Never log the return value of credential().
- Never use tool parameters named user_sub / caller_sub / principal_id —
  those are forgeable.  Always call identity() inside the tool body instead.
"""

from .context import Identity, credential, identity
from .server import PlatformMCPServer

__all__ = ["PlatformMCPServer", "identity", "credential", "Identity"]
