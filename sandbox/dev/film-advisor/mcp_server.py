"""
Film Advisor MCP Server — HTTP Streamable Transport (fastmcp 3.x)

Exposes the Film Advisor REST API as MCP tools using FastMCP.
Compatible with Microsoft Copilot Studio, Claude Desktop, and any MCP client
that supports the 2024-11-05 protocol with streamable-HTTP or SSE transport.

Tools:
  list_films(genre?, min_rating?)     — search/list films from the DB
  get_film(id)                        — get a specific film by ID
  recommend_film(genre?, min_rating?) — get a random recommendation
  add_film(title, year, ...)          — add a new film to the DB
  get_stats()                         — genre distribution + average ratings

Transports served at:
  POST/GET /mcp  — MCP Streamable HTTP (2024-11-05 spec, preferred)
  GET  /sse      — SSE transport (legacy clients)
  GET  /health   — liveness probe

Quick test (initialize + list tools):
  curl -s -X POST http://localhost:8081/mcp \
       -H 'Content-Type: application/json' \
       -H 'Accept: application/json, text/event-stream' \
       -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}'
"""
from __future__ import annotations

import os
from typing import Optional

import httpx
import uvicorn
from fastmcp import FastMCP
from fastmcp.server.http import create_sse_app, create_streamable_http_app
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Mount, Route

FILM_API_URL = os.environ.get("FILM_API_URL", "http://localhost:8080")

mcp = FastMCP(
    name="film-advisor",
    instructions=(
        "You are a knowledgeable film advisor. Use these tools to search, "
        "recommend, and manage a curated film database. "
        "Always provide context about a film's rating when recommending."
    ),
)


# ─── Tools ────────────────────────────────────────────────────────────────────

@mcp.tool()
async def list_films(
    genre: Optional[str] = None,
    min_rating: Optional[float] = None,
) -> list[dict]:
    """
    List films from the database, optionally filtered by genre and minimum rating.

    Args:
        genre: Filter by genre — one of: sci-fi, drama, action, crime, thriller,
               animation, comedy, horror (optional)
        min_rating: Minimum IMDb-style rating 0.0–10.0 (optional, no default filter)

    Returns:
        List of film objects sorted by rating descending.
    """
    params: dict = {}
    if genre:
        params["genre"] = genre
    if min_rating is not None:
        params["min_rating"] = min_rating

    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.get(f"{FILM_API_URL}/films", params=params)
        resp.raise_for_status()
        return resp.json()


@mcp.tool()
async def get_film(film_id: int) -> dict:
    """
    Get full details for a specific film by its database ID.

    Args:
        film_id: Integer ID of the film (from list_films results)

    Returns:
        Film object: {id, title, year, genre, director, rating, description}
    """
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.get(f"{FILM_API_URL}/films/{film_id}")
        if resp.status_code == 404:
            return {"error": f"Film with id={film_id} not found"}
        resp.raise_for_status()
        return resp.json()


@mcp.tool()
async def recommend_film(
    genre: Optional[str] = None,
    min_rating: float = 8.0,
) -> dict:
    """
    Get a random high-quality film recommendation.

    Args:
        genre: Preferred genre (optional — omit for any genre)
        min_rating: Minimum rating threshold (default 8.0 for curated picks)

    Returns:
        A single film recommendation. Returns error message if no films match.
    """
    params: dict = {"min_rating": min_rating}
    if genre:
        params["genre"] = genre

    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.get(f"{FILM_API_URL}/recommend", params=params)
        if resp.status_code == 404:
            return {
                "error": "No films found matching your criteria. "
                         "Try lowering min_rating or removing the genre filter."
            }
        resp.raise_for_status()
        return resp.json()


@mcp.tool()
async def add_film(
    title: str,
    year: int,
    genre: str,
    director: str,
    rating: float,
    description: Optional[str] = None,
) -> dict:
    """
    Add a new film to the database.

    Args:
        title: Film title (required)
        year: Release year, 1888–2030 (required)
        genre: Genre such as drama, sci-fi, action, comedy, thriller (required)
        director: Director's full name (required)
        rating: IMDb-style rating 0.0–10.0 (required)
        description: Short synopsis, max 500 chars (optional)

    Returns:
        Created film record with assigned database ID.
    """
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.post(
            f"{FILM_API_URL}/films",
            json={
                "title": title,
                "year": year,
                "genre": genre,
                "director": director,
                "rating": rating,
                "description": description,
            },
        )
        resp.raise_for_status()
        return resp.json()


@mcp.tool()
async def get_stats() -> list[dict]:
    """
    Get genre distribution and average ratings from the film database.

    Returns:
        List of {genre, count, avg_rating} sorted by count descending.
        Useful for understanding what's in the database before recommending.
    """
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.get(f"{FILM_API_URL}/stats")
        resp.raise_for_status()
        return resp.json()


# ─── Build combined ASGI app ──────────────────────────────────────────────────
# FastMCP 3.x requires the streamable HTTP app's lifespan to be wired into the
# parent Starlette app so the session manager task group gets initialized.

async def health(request: Request) -> JSONResponse:
    return JSONResponse({"status": "ok", "service": "film-advisor-mcp", "tools": 5})


streamable_app = create_streamable_http_app(mcp, streamable_http_path="/mcp")
sse_app = create_sse_app(mcp, message_path="/sse/message", sse_path="/sse")

app = Starlette(
    lifespan=streamable_app.lifespan,
    routes=[
        Route("/health", health),
        Mount("/sse", app=sse_app),
        Mount("/", app=streamable_app),
    ],
)


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8081, log_level="info")
