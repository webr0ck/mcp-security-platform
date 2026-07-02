"""Demo "uploaded" MCP server for the auto-provision flow (Part 2, flow A).

This stands in for "a user uploads a simple public MCP repo". It's a real MCP
server built on the platform's mcphub_sdk (same HTTP /mcp contract every lab
backend uses), with two harmless tools. The provisioner (scripts/provision_mcp.py)
clones/builds this, runs it on a dedicated per-backend network, wires the proxy in,
discovers these tools, and marks them active — after which they are invocable.

Any public MCP that speaks the platform's streamable-HTTP /mcp contract provisions
identically; this repo just keeps the demo self-contained and reproducible.
"""
from __future__ import annotations

import os

from mcphub_sdk import PlatformMCPServer, identity

SERVER_NAME = os.environ.get("SERVER_NAME", "demo-uploaded-mcp")

# require_proxy=False so the provisioner's discovery handshake (an un-proxied
# call from inside the container) is not 403'd. Real callers still arrive via
# the gateway, which injects identity.
srv = PlatformMCPServer(SERVER_NAME, require_proxy=False)


@srv.tool()
async def reverse_text(text: str = "") -> dict:
    """Return the input string reversed."""
    return {"input": text, "reversed": text[::-1], "server": SERVER_NAME}


@srv.tool()
async def word_count(text: str = "") -> dict:
    """Count words and characters in the input string."""
    words = text.split()
    return {
        "words": len(words),
        "chars": len(text),
        "caller": identity().sub,
        "server": SERVER_NAME,
    }


if __name__ == "__main__":
    srv.run()
