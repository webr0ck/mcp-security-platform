"""
Echo MCP Server — lab stress-test and auth-verification target.

Built on the mcphub_sdk PlatformMCPServer as the SDK's proof-of-concept:
the SDK supplies stateless_http, the identity/credential context middleware,
the /health route, DNS-rebind disable, and the uvicorn run loop — so this file
is pure tool logic with no transport/middleware boilerplate.

Echo is a liveness/debug server. It does NOT need per-user identity to function,
so it runs with require_proxy=False: a direct (un-proxied) call must never 403,
because echo is the canary used to confirm the gateway path is alive. When the
gateway DOES inject X-User-Sub (the normal invoke path), identity() reflects the
real caller; otherwise it reads the safe default "anonymous".

Tools:
  ping          — liveness check; returns server name, caller identity, timestamp
  echo_args     — reflects back every argument passed, hashed (schema verification)
  whoami        — reports caller identity + a REDACTED preview of the injected
                  credential (never the raw token — spec H8)
  slow_tool     — sleeps for a configurable duration (tests timeout handling)
  bulk_compute  — pure-CPU Fibonacci (tests concurrency limits under load)
"""
from __future__ import annotations

import asyncio
import hashlib
import os
from datetime import datetime, timezone

from mcphub_sdk import PlatformMCPServer, credential, identity

SERVER_NAME = os.environ.get("SERVER_NAME", "echo-mcp")

# require_proxy=False: echo is a debug/liveness canary and must never 403 on an
# un-proxied call. identity() still reflects the real caller when the gateway
# injects X-User-Sub, and falls back to "anonymous" otherwise.
srv = PlatformMCPServer(SERVER_NAME, require_proxy=False)


@srv.tool()
async def ping() -> dict:
    """Liveness check — returns server identity, caller, and current timestamp."""
    who = identity()
    return {
        "server": SERVER_NAME,
        "status": "ok",
        "caller_sub": who.sub,
        "ts": datetime.now(timezone.utc).isoformat(),
    }


@srv.tool()
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


@srv.tool()
async def whoami() -> dict:
    """
    Report the caller's proxy-injected identity plus a REDACTED preview of the
    injected credential. Used to verify identity + credential injection.

    SECURITY (spec H8): never returns the raw credential — only present/absent,
    length, and a first-8/last-4 masked preview.
    """
    who = identity()
    token = credential()  # injected Authorization token (prefix-stripped) or None

    has_cred = bool(token)
    if token:
        if len(token) > 12:
            preview = f"{token[:8]}...{token[-4:]}"
        else:
            preview = "***"
        token_len = len(token)
    else:
        preview = "(none)"
        token_len = 0

    return {
        "server": SERVER_NAME,
        "sub": who.sub,
        "role": who.role,
        "has_credential": has_cred,
        "credential_len": token_len,
        "credential_preview": preview,
    }


@srv.tool()
async def slow_tool(delay_ms: int = 100) -> dict:
    """Sleep for delay_ms milliseconds. Tests proxy timeout handling."""
    delay_ms = max(0, min(delay_ms, 5000))  # cap at 5s
    await asyncio.sleep(delay_ms / 1000)
    return {"slept_ms": delay_ms, "server": SERVER_NAME}


@srv.tool()
async def bulk_compute(n: int = 20) -> dict:
    """Compute Fibonacci(n) iteratively. Tests CPU-bound concurrency."""
    n = max(0, min(n, 40))  # cap at fib(40) to prevent DoS
    a, b = 0, 1
    for _ in range(n):
        a, b = b, a + b
    return {"n": n, "fib": a, "server": SERVER_NAME}


if __name__ == "__main__":
    srv.run()
