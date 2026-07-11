"""
Fetch MCP Server — vendored adaptation of the official MCP reference
"fetch" server (T3: prove onboarding of a REAL upstream open-source MCP
server, not another hand-built lab fixture).

Source: https://github.com/modelcontextprotocol/servers
        path: src/fetch/src/mcp_server_fetch/server.py
        commit: a72e93e5030241a8f717604765170b8c9f4da728 (main, fetched 2026-07-11)
        license: MIT (see upstream LICENSE at that path)

What's vendored near-verbatim from upstream: extract_content_from_html(),
get_robots_txt_url(), check_may_autonomously_fetch_url(), fetch_url(), and
the max_length/start_index truncation logic from call_tool(). This is the
actual behavior of the upstream server — robots.txt honoring, HTML→markdown
simplification via readabilipy+markdownify, chunked reads for long pages.

What's adapted (not upstream): upstream registers over stdio via the raw
`mcp.server.Server` + `stdio_server()` (single-client, spawned-per-session
transport — wrong shape for a shared multi-tenant lab). Every other server
in this lab runs over HTTP behind the platform gateway, so transport and
tool registration are swapped for mcphub_sdk.PlatformMCPServer (the same
swap catfacts/echo/etc. all make) — HTTP in, upstream's own fetch/robots/
extraction logic untouched underneath. Egress goes through lab-egress-proxy
(HTTPS_PROXY, honored by httpx's default trust_env=True) like every other
lab server that calls a real external host — example.com must be (and is)
added to squid.conf's allowlist for this demo.

Tool:
  fetch_url  — fetch a URL and return simplified markdown (or raw content
               for non-HTML), honoring robots.txt, with start_index/
               max_length pagination for long pages.
"""
from __future__ import annotations

import os
from urllib.parse import urlparse, urlunparse

import httpx
import markdownify
import readabilipy.simple_json
from mcphub_sdk import PlatformMCPServer
from protego import Protego

SERVER_NAME = os.environ.get("SERVER_NAME", "fetch-mcp")

DEFAULT_USER_AGENT = "MCPSecurityPlatform-Fetch/1.0 (+lab; vendored from modelcontextprotocol/servers)"

srv = PlatformMCPServer(SERVER_NAME)


# --- vendored upstream logic (see module docstring for source/commit) ------


def extract_content_from_html(html: str) -> str:
    """Extract and convert HTML content to Markdown format."""
    ret = readabilipy.simple_json.simple_json_from_html_string(html, use_readability=True)
    if not ret["content"]:
        return "<error>Page failed to be simplified from HTML</error>"
    return markdownify.markdownify(ret["content"], heading_style=markdownify.ATX)


def get_robots_txt_url(url: str) -> str:
    parsed = urlparse(url)
    return urlunparse((parsed.scheme, parsed.netloc, "/robots.txt", "", "", ""))


async def check_may_autonomously_fetch_url(url: str, user_agent: str) -> str | None:
    """Returns an error string if robots.txt disallows the fetch, else None."""
    robot_txt_url = get_robots_txt_url(url)
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(
                robot_txt_url, follow_redirects=True, headers={"User-Agent": user_agent}, timeout=10
            )
        except httpx.HTTPError:
            return f"Failed to fetch robots.txt {robot_txt_url} due to a connection issue"
        if response.status_code in (401, 403):
            return f"robots.txt ({robot_txt_url}) returned {response.status_code}; assuming fetching is disallowed"
        if 400 <= response.status_code < 500:
            return None
        robot_txt = response.text
    processed = "\n".join(line for line in robot_txt.splitlines() if not line.strip().startswith("#"))
    parser = Protego.parse(processed)
    if not parser.can_fetch(url, user_agent):
        return f"robots.txt ({robot_txt_url}) disallows fetching for user-agent {user_agent}"
    return None


async def fetch_url(url: str, user_agent: str, force_raw: bool = False) -> tuple[str, str]:
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(
                url, follow_redirects=True, headers={"User-Agent": user_agent}, timeout=30
            )
        except httpx.HTTPError as e:
            raise ValueError(f"Failed to fetch {url}: {e!r}")
        if response.status_code >= 400:
            raise ValueError(f"Failed to fetch {url} - status code {response.status_code}")
        page_raw = response.text

    content_type = response.headers.get("content-type", "")
    is_html = "<html" in page_raw[:100] or "text/html" in content_type or not content_type
    if is_html and not force_raw:
        return extract_content_from_html(page_raw), ""
    return page_raw, f"Content type {content_type} cannot be simplified to markdown, but here is the raw content:\n"


# --- platform tool wrapper ---------------------------------------------


@srv.tool()
async def fetch_url_tool(
    url: str,
    max_length: int = 5000,
    start_index: int = 0,
    raw: bool = False,
    ignore_robots_txt: bool = False,
) -> dict:
    """Fetch a URL from the internet and return its content simplified to
    markdown (or raw for non-HTML). Honors robots.txt unless ignore_robots_txt
    is set. max_length/start_index page through long content."""
    if not ignore_robots_txt:
        denial = await check_may_autonomously_fetch_url(url, DEFAULT_USER_AGENT)
        if denial:
            return {"error": denial, "url": url}

    try:
        content, prefix = await fetch_url(url, DEFAULT_USER_AGENT, force_raw=raw)
    except ValueError as e:
        return {"error": str(e), "url": url}

    original_length = len(content)
    if start_index >= original_length:
        return {"error": "No more content available.", "url": url}

    truncated = content[start_index : start_index + max_length]
    remaining = original_length - (start_index + len(truncated))
    result = {"url": url, "content": prefix + truncated, "server": SERVER_NAME}
    if len(truncated) == max_length and remaining > 0:
        result["next_start_index"] = start_index + len(truncated)
    return result


if __name__ == "__main__":
    srv.run()
