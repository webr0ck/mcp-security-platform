"""
Echo MCP Server — lab stress-test and auth-verification target.

Tools:
  ping          — liveness check; returns server name + timestamp
  echo_args     — reflects back every argument passed (for schema verification)
  whoami        — returns the credential headers visible to the server
  slow_tool     — sleeps for a configurable duration (tests timeout handling)
  bulk_compute  — pure-CPU Fibonacci (tests concurrency limits under load)
"""
from __future__ import annotations

import hashlib
import os
import time
import asyncio
from datetime import datetime, timezone

import uvicorn
from mcp.server.fastmcp import FastMCP

SERVER_NAME = os.environ.get("SERVER_NAME", "echo-mcp")
HOST = os.environ.get("HOST", "0.0.0.0")
PORT = int(os.environ.get("PORT", "8000"))

mcp = FastMCP(SERVER_NAME)

# Store last-seen auth headers so whoami can report them
_last_auth: dict = {}


@mcp.tool()
async def ping() -> dict:
    """Liveness check — returns server identity and current timestamp."""
    return {
        "server": SERVER_NAME,
        "status": "ok",
        "ts": datetime.now(timezone.utc).isoformat(),
    }


@mcp.tool()
async def echo_args(message: str = "", count: int = 1, tag: str = "") -> dict:
    """Reflect back the supplied arguments, hashed for integrity verification."""
    payload = f"{message}:{count}:{tag}"
    return {
        "message": message,
        "count": count,
        "tag": tag,
        "echo_hash": hashlib.sha256(payload.encode()).hexdigest()[:16],
        "server": SERVER_NAME,
    }


@mcp.tool()
async def whoami() -> dict:
    """
    Returns the Authorization header value the server received (redacted).
    Used to verify credential injection is working correctly.
    """
    auth = _last_auth.get("authorization", "")
    scheme = ""
    masked = "(none)"
    if auth:
        parts = auth.split(" ", 1)
        scheme = parts[0] if parts else ""
        token = parts[1] if len(parts) > 1 else ""
        # Show only first 8 + last 4 chars of the token
        if len(token) > 12:
            masked = f"{token[:8]}...{token[-4:]}"
        else:
            masked = "***"
    return {
        "server": SERVER_NAME,
        "auth_scheme": scheme,
        "token_preview": masked,
        "has_auth": bool(auth),
    }


@mcp.tool()
async def slow_tool(delay_ms: int = 100) -> dict:
    """Sleep for delay_ms milliseconds. Tests proxy timeout handling."""
    delay_ms = max(0, min(delay_ms, 5000))  # cap at 5s
    await asyncio.sleep(delay_ms / 1000)
    return {"slept_ms": delay_ms, "server": SERVER_NAME}


@mcp.tool()
async def bulk_compute(n: int = 20) -> dict:
    """Compute Fibonacci(n) iteratively. Tests CPU-bound concurrency."""
    n = max(0, min(n, 40))  # cap at fib(40) to prevent DoS
    a, b = 0, 1
    for _ in range(n):
        a, b = b, a + b
    return {"n": n, "fib": a, "server": SERVER_NAME}


if __name__ == "__main__":
    # Disable DNS rebinding protection for lab (internal network only, no browser access)
    from mcp.server.transport_security import TransportSecuritySettings
    mcp.settings.transport_security = TransportSecuritySettings(enable_dns_rebinding_protection=False)
    app = mcp.streamable_http_app()
    uvicorn.run(app, host=HOST, port=PORT, log_level="info")
