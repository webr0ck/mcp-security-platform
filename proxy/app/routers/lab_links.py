"""
Lab service links — transparent reverse proxy for lab UIs behind the main proxy port.

Routes (no auth — target services manage their own authentication):
  GET /          → 302 redirect to /portal
  GET/POST /netbox{path}    → lab-netbox:8080
  GET/POST /grafana{path}   → lab-grafana:3000
  GET/POST /keycloak{path}  → lab-keycloak:8080

These routes are lab-only conveniences so a single ip:port serves as the
entry point for the entire lab environment. They are excluded from the
AuthMiddleware via the SKIP_AUTH_PATHS config (set in .env.lab).
"""
from __future__ import annotations

import logging
import os

import httpx
from fastapi import APIRouter, Request
from fastapi.responses import RedirectResponse, StreamingResponse

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Lab Links"])

_LAB_SERVICES: dict[str, str] = {
    "netbox":   os.environ.get("LAB_NETBOX_URL",   "http://lab-netbox:8080"),
    "grafana":  os.environ.get("LAB_GRAFANA_URL",  "http://lab-grafana:3000"),
    "keycloak": os.environ.get("LAB_KEYCLOAK_URL", "http://lab-keycloak:8080"),
}

_HOP_BY_HOP = frozenset({
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade",
    "content-encoding",  # let httpx handle decompression
})


async def _proxy(target_base: str, path: str, request: Request) -> StreamingResponse:
    url = f"{target_base.rstrip('/')}/{path.lstrip('/')}"
    qs = request.url.query
    if qs:
        url = f"{url}?{qs}"

    # Forward safe headers; strip hop-by-hop and auth (target manages its own)
    forward_headers = {
        k: v for k, v in request.headers.items()
        if k.lower() not in _HOP_BY_HOP and k.lower() != "authorization"
    }
    forward_headers["X-Forwarded-For"] = request.client.host if request.client else "unknown"
    forward_headers["X-Forwarded-Proto"] = "http"

    body = await request.body()

    try:
        async with httpx.AsyncClient(timeout=30.0, follow_redirects=False) as client:
            upstream = await client.request(
                method=request.method,
                url=url,
                headers=forward_headers,
                content=body,
            )
    except httpx.RequestError as exc:
        logger.warning("Lab proxy error for %s: %s", url, exc)
        return StreamingResponse(
            iter([b'{"error":"upstream_unavailable"}']),
            status_code=502,
            media_type="application/json",
        )

    response_headers = {
        k: v for k, v in upstream.headers.items()
        if k.lower() not in _HOP_BY_HOP
    }
    # Rewrite absolute Location redirects to go through our proxy
    if "location" in response_headers:
        loc = response_headers["location"]
        for svc, base in _LAB_SERVICES.items():
            if loc.startswith(base):
                response_headers["location"] = loc.replace(base, f"/{svc}", 1)
                break

    return StreamingResponse(
        upstream.aiter_bytes(),
        status_code=upstream.status_code,
        headers=response_headers,
        media_type=upstream.headers.get("content-type"),
    )


@router.get("/", include_in_schema=False)
async def root_redirect():
    return RedirectResponse(url="/portal", status_code=302)


@router.api_route("/netbox/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"], include_in_schema=False)
async def netbox_proxy(path: str, request: Request):
    return await _proxy(_LAB_SERVICES["netbox"], path, request)


@router.api_route("/grafana/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"], include_in_schema=False)
async def grafana_proxy(path: str, request: Request):
    return await _proxy(_LAB_SERVICES["grafana"], path, request)


@router.api_route("/keycloak/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"], include_in_schema=False)
async def keycloak_proxy(path: str, request: Request):
    return await _proxy(_LAB_SERVICES["keycloak"], path, request)
