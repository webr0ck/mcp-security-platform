"""
Notes MCP Server — per-user isolated note storage.

Auth scenario: JWT token injection per user (approach A).
Each note is keyed by (user_sub, note_id) — different users cannot read each other's notes.
The server trusts the X-User-Sub header injected by the proxy (never trust raw Bearer token
from clients, which the proxy validates before forwarding).

Backend: Redis (in-memory, for lab simplicity).
"""
from __future__ import annotations

import os
import json
import uuid
from datetime import datetime, timezone

import redis.asyncio as aioredis
import uvicorn
from mcp.server.fastmcp import FastMCP

HOST = os.environ.get("HOST", "0.0.0.0")
PORT = int(os.environ.get("PORT", "8000"))
REDIS_URL = os.environ.get("REDIS_URL", "redis://mcp-redis:6379/3")

mcp = FastMCP("notes-mcp")

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
async def create_note(title: str, body: str, user_sub: str = "anonymous") -> dict:
    """
    Create a new note for user_sub.
    In production the proxy injects user_sub from the verified JWT — never trust
    the client-supplied value without that injection step.
    """
    note_id = str(uuid.uuid4())[:8]
    now = datetime.now(timezone.utc).isoformat()
    note = {"id": note_id, "title": title, "body": body, "created_at": now, "user_sub": user_sub}
    r = _get_redis()
    await r.set(_user_key(user_sub, note_id), json.dumps(note), ex=3600)
    await r.sadd(_user_index_key(user_sub), note_id)
    await r.expire(_user_index_key(user_sub), 3600)
    return {"created": True, "note_id": note_id, "user_sub": user_sub}


@mcp.tool()
async def list_notes(user_sub: str = "anonymous") -> dict:
    """List all note IDs and titles for user_sub."""
    r = _get_redis()
    ids = await r.smembers(_user_index_key(user_sub))
    notes = []
    for nid in ids:
        raw = await r.get(_user_key(user_sub, nid))
        if raw:
            n = json.loads(raw)
            notes.append({"id": n["id"], "title": n["title"], "created_at": n["created_at"]})
    return {"user_sub": user_sub, "count": len(notes), "notes": sorted(notes, key=lambda x: x["created_at"])}


@mcp.tool()
async def get_note(note_id: str, user_sub: str = "anonymous") -> dict:
    """Retrieve a single note by ID. Returns 404-equivalent if not found or user mismatch."""
    r = _get_redis()
    raw = await r.get(_user_key(user_sub, note_id))
    if not raw:
        return {"error": "not_found", "note_id": note_id, "user_sub": user_sub}
    return json.loads(raw)


@mcp.tool()
async def delete_note(note_id: str, user_sub: str = "anonymous") -> dict:
    """Delete a note owned by user_sub."""
    r = _get_redis()
    deleted = await r.delete(_user_key(user_sub, note_id))
    await r.srem(_user_index_key(user_sub), note_id)
    return {"deleted": bool(deleted), "note_id": note_id}


if __name__ == "__main__":
    app = mcp.streamable_http_app()
    uvicorn.run(app, host=HOST, port=PORT, log_level="info")
