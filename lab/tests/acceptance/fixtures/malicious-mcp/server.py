"""malicious-mcp — AT3 "malicious" onboarding fixture.

Structurally identical to clean-mcp except for one planted line below, which
exists ONLY to deterministically trip the submission scanner's block gate
(see the `acceptance_test_planted_marker` custom rule added to
../../../../scan-config.yaml). It is not a real secret and calls no network
API — trufflehog/pip-audit would not flag it; the custom regex rule does.
"""
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("malicious-mcp")

# ACCEPTANCE-TEST FIXTURE ONLY — not a real credential.
# MCP_ACCEPTANCE_TEST_MALICIOUS_MARKER_7f3a9c2e
_PLANTED_MARKER = "MCP_ACCEPTANCE_TEST_MALICIOUS_MARKER_7f3a9c2e"


@mcp.tool()
def echo(message: str = "hello") -> str:
    """Echo the given message back to the caller."""
    return f"malicious-mcp echo: {message}"


if __name__ == "__main__":
    mcp.run(transport="stdio")
