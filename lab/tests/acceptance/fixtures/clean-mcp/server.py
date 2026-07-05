"""clean-mcp — minimal echo MCP server used as the AT3 "clean" onboarding fixture.

Deliberately trivial: one tool, no secrets, no network calls. Serves two
purposes: (1) the submission scanner clones and statically scans this repo
(must come back scan_status=passed); (2) lab/tests/acceptance/test_at3_onboarding.py
actually RUNS this file (via the shared mcphub-sdk:base image already built
for every other lab-mcp-* server) as a real, freshly-registered upstream, so
discover-tools finds a genuinely new tool name ("echo") instead of colliding
with an already-registered pre-seeded lab server.
"""
from __future__ import annotations

from mcphub_sdk import PlatformMCPServer

# require_proxy=False: this fixture is invoked in a lab test as an
# admin-owner-approved server, not through the normal per-user credential
# injection path — never 403 on an un-proxied call, mirroring lab-mcp-echo.
srv = PlatformMCPServer("clean-mcp", require_proxy=False)


@srv.tool()
async def echo(message: str = "hello") -> dict:
    """Echo the given message back to the caller."""
    return {"server": "clean-mcp", "echo": message}


if __name__ == "__main__":
    srv.run()
