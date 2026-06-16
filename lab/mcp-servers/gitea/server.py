"""
Gitea MCP Server — lab Bitbucket equivalent.
Exposes repository, issue, PR, and file tools via streamable HTTP.

Token resolution order:
  1. Authorization header injected by the MCP security proxy (credential_store path).
     The proxy injects "token <sha1>" for injection_mode='service' tools.
  2. GITEA_TOKEN env var (direct-run / env fallback).
"""
from __future__ import annotations

import contextvars
import os
import httpx
import uvicorn
from mcp.server.fastmcp import FastMCP
from starlette.middleware.base import BaseHTTPMiddleware

GITEA_URL = os.environ.get("GITEA_URL", "http://lab-gitea:3000").rstrip("/")
_ENV_TOKEN = os.environ.get("GITEA_TOKEN", "")

# ContextVar populated by _AuthHeaderMiddleware for each request.
# Tools read from this var; falls back to _ENV_TOKEN when not set.
_request_token: contextvars.ContextVar[str] = contextvars.ContextVar(
    "_request_token", default=_ENV_TOKEN
)

mcp = FastMCP("gitea-mcp")


class _AuthHeaderMiddleware(BaseHTTPMiddleware):
    """Extract Authorization header injected by the MCP proxy into a ContextVar."""

    async def dispatch(self, request, call_next):
        auth = request.headers.get("authorization", "")
        token = _ENV_TOKEN
        if auth.lower().startswith("token "):
            token = auth[6:].strip()
        elif auth.lower().startswith("bearer "):
            token = auth[7:].strip()
        tok = _request_token.set(token)
        try:
            return await call_next(request)
        finally:
            _request_token.reset(tok)


def _token() -> str:
    return _request_token.get()


def _headers() -> dict:
    t = _token()
    if t:
        return {"Authorization": f"token {t}"}
    return {}


@mcp.tool()
async def list_repos(owner: str = "", limit: int = 20) -> dict:
    """List repositories. Pass owner to filter by user/org, or omit for all."""
    async with httpx.AsyncClient(timeout=10) as client:
        if owner:
            url = f"{GITEA_URL}/api/v1/repos/search?owner={owner}&limit={limit}"
        else:
            url = f"{GITEA_URL}/api/v1/repos/search?limit={limit}"
        resp = await client.get(url, headers=_headers())
        resp.raise_for_status()
        raw = resp.json()
        repos = raw.get("data", raw) if isinstance(raw, dict) else raw
        return {
            "repos": [
                {
                    "name": r["name"],
                    "full_name": r["full_name"],
                    "description": r.get("description", ""),
                    "stars": r.get("stars_count", 0),
                    "updated_at": r.get("updated",  ""),
                }
                for r in repos
            ]
        }


@mcp.tool()
async def get_repo(owner: str, repo: str) -> dict:
    """Get details of a specific repository."""
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.get(
            f"{GITEA_URL}/api/v1/repos/{owner}/{repo}", headers=_headers()
        )
        resp.raise_for_status()
        r = resp.json()
        return {
            "name": r["name"],
            "full_name": r["full_name"],
            "description": r.get("description", ""),
            "default_branch": r.get("default_branch", "main"),
            "stars": r.get("stars_count", 0),
            "open_issues_count": r.get("open_issues_count", 0),
            "clone_url": r.get("clone_url", ""),
        }


@mcp.tool()
async def list_issues(owner: str, repo: str, state: str = "open", limit: int = 20) -> dict:
    """List issues for a repository. state: open | closed | all"""
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.get(
            f"{GITEA_URL}/api/v1/repos/{owner}/{repo}/issues",
            params={"type": "issues", "state": state, "limit": limit},
            headers=_headers(),
        )
        resp.raise_for_status()
        return {
            "issues": [
                {"number": i["number"], "title": i["title"], "state": i["state"]}
                for i in resp.json()
            ]
        }


@mcp.tool()
async def create_issue(owner: str, repo: str, title: str, body: str = "") -> dict:
    """Create a new issue in a repository."""
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.post(
            f"{GITEA_URL}/api/v1/repos/{owner}/{repo}/issues",
            json={"title": title, "body": body},
            headers={**_headers(), "Content-Type": "application/json"},
        )
        resp.raise_for_status()
        i = resp.json()
        return {"number": i["number"], "title": i["title"], "html_url": i["html_url"]}


@mcp.tool()
async def list_pull_requests(owner: str, repo: str, state: str = "open") -> dict:
    """List pull requests for a repository. state: open | closed | all"""
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.get(
            f"{GITEA_URL}/api/v1/repos/{owner}/{repo}/pulls",
            params={"state": state, "limit": 20},
            headers=_headers(),
        )
        resp.raise_for_status()
        return {
            "pull_requests": [
                {"number": p["number"], "title": p["title"], "state": p["state"]}
                for p in resp.json()
            ]
        }


@mcp.tool()
async def get_file_contents(
    owner: str, repo: str, filepath: str, ref: str = "main"
) -> dict:
    """Get the raw contents of a file from a repository."""
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.get(
            f"{GITEA_URL}/api/v1/repos/{owner}/{repo}/raw/{filepath}",
            params={"ref": ref},
            headers=_headers(),
        )
        resp.raise_for_status()
        return {"content": resp.text, "path": filepath, "ref": ref}


@mcp.tool()
async def list_branches(owner: str, repo: str) -> dict:
    """List branches for a repository."""
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.get(
            f"{GITEA_URL}/api/v1/repos/{owner}/{repo}/branches",
            headers=_headers(),
        )
        resp.raise_for_status()
        return {
            "branches": [b["name"] for b in resp.json()]
        }


if __name__ == "__main__":
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", "8000"))
    transport = os.environ.get("TRANSPORT", "http")

    if transport == "http":
        from mcp.server.transport_security import TransportSecuritySettings
        mcp.settings.transport_security = TransportSecuritySettings(enable_dns_rebinding_protection=False)
        app = mcp.streamable_http_app()
        app.add_middleware(_AuthHeaderMiddleware)
        uvicorn.run(app, host=host, port=port, log_level="info")
    else:
        mcp.run()
