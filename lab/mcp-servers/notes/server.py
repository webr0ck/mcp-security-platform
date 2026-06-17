"""
Notes MCP Server — per-user isolated note storage.

Auth scenario: JWT token injection per user (approach A).
Each note is keyed by (user_sub, note_id) — different users cannot read each other's notes.

Identity (user_sub) is resolved EXCLUSIVELY from the X-User-Sub HTTP header that the
proxy injects after it validates the caller's Bearer token. It is NEVER a tool parameter:
a client-supplied user_sub would let any caller forge another user's identity and read or
delete their notes. The _IdentityMiddleware below populates a ContextVar from the header,
and every tool reads the caller's sub from that ContextVar — closing the identity spoof.

Backend: Redis (in-memory, for lab simplicity).
"""
from __future__ import annotations

import contextvars
import os
import json
import uuid
from datetime import datetime, timezone

import redis.asyncio as aioredis
import uvicorn
from mcp.server.fastmcp import FastMCP
from starlette.middleware.base import BaseHTTPMiddleware

HOST = os.environ.get("HOST", "0.0.0.0")
PORT = int(os.environ.get("PORT", "8000"))
REDIS_URL = os.environ.get("REDIS_URL", "redis://mcp-redis:6379/3")

# ContextVar populated by _IdentityMiddleware from the proxy-injected X-User-Sub header.
# Tools read the caller's identity from here — never from a (forgeable) tool argument.
_caller_sub: contextvars.ContextVar[str] = contextvars.ContextVar(
    "_caller_sub", default="anonymous"
)


def _caller_sub_get() -> str:
    """Return the caller's sub, resolved from the proxy-injected X-User-Sub header."""
    return _caller_sub.get()


class _IdentityMiddleware(BaseHTTPMiddleware):
    """Populate the caller-identity ContextVar from the proxy-injected X-User-Sub header."""

    async def dispatch(self, request, call_next):
        sub = request.headers.get("x-user-sub", "anonymous")
        tok = _caller_sub.set(sub)
        try:
            return await call_next(request)
        finally:
            _caller_sub.reset(tok)


# stateless_http=True is REQUIRED for the identity ContextVar to work. In the
# default (stateful) streamable-http mode, tool handlers run inside a long-lived
# task group created at session-init time, so the ContextVar set by
# _IdentityMiddleware on the per-request task does NOT propagate to the handler —
# the caller would always read the default "anonymous". In stateless mode each
# request is processed in its own task spawned from the request context, so the
# X-User-Sub the proxy injects on the tools/call request reaches the tool.
mcp = FastMCP("notes-mcp", stateless_http=True)

_redis: aioredis.Redis | None = None


def _get_redis() -> aioredis.Redis:
    global _redis
    if _redis is None:
        _redis = aioredis.from_url(REDIS_URL, decode_responses=True)
    return _redis


def _user_key(user_sub: str, note_id: str) -> str:
    return f"notes:{user_sub}:{note_id}"


def _user_index_key(user_sub: str) -> str:
    return f"notes_index:{user_sub}"


@mcp.tool()
async def create_note(title: str, body: str) -> dict:
    """
    Create a new note for the calling user.
    Identity is resolved from the proxy-injected X-User-Sub header — there is no
    user_sub parameter, so a client cannot create notes under another identity.
    """
    sub = _caller_sub_get()
    note_id = str(uuid.uuid4())[:8]
    now = datetime.now(timezone.utc).isoformat()
    note = {"id": note_id, "title": title, "body": body, "created_at": now, "user_sub": sub}
    r = _get_redis()
    await r.set(_user_key(sub, note_id), json.dumps(note), ex=3600)
    await r.sadd(_user_index_key(sub), note_id)
    await r.expire(_user_index_key(sub), 3600)
    return {"created": True, "note_id": note_id, "user_sub": sub}


@mcp.tool()
async def list_notes() -> dict:
    """List all note IDs and titles for the calling user (identity from X-User-Sub header)."""
    sub = _caller_sub_get()
    r = _get_redis()
    ids = await r.smembers(_user_index_key(sub))
    notes = []
    for nid in ids:
        raw = await r.get(_user_key(sub, nid))
        if raw:
            n = json.loads(raw)
            notes.append({"id": n["id"], "title": n["title"], "created_at": n["created_at"]})
    return {"user_sub": sub, "count": len(notes), "notes": sorted(notes, key=lambda x: x["created_at"])}


@mcp.tool()
async def get_note(note_id: str) -> dict:
    """Retrieve a single note by ID for the calling user (identity from X-User-Sub header).

    Returns 404-equivalent if not found or the note belongs to another user."""
    sub = _caller_sub_get()
    r = _get_redis()
    raw = await r.get(_user_key(sub, note_id))
    if not raw:
        return {"error": "not_found", "note_id": note_id, "user_sub": sub}
    return json.loads(raw)


@mcp.tool()
async def delete_note(note_id: str) -> dict:
    """Delete a note owned by the calling user (identity from X-User-Sub header)."""
    sub = _caller_sub_get()
    r = _get_redis()
    deleted = await r.delete(_user_key(sub, note_id))
    await r.srem(_user_index_key(sub), note_id)
    return {"deleted": bool(deleted), "note_id": note_id}


if __name__ == "__main__":
    # Disable DNS rebinding protection for lab (internal network only, no browser access)
    from mcp.server.transport_security import TransportSecuritySettings
    mcp.settings.transport_security = TransportSecuritySettings(enable_dns_rebinding_protection=False)
    app = mcp.streamable_http_app()
    app.add_middleware(_IdentityMiddleware)
    uvicorn.run(app, host=HOST, port=PORT, log_level="info")
