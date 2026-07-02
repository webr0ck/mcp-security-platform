"""Ingress source-guard middleware (SEC-05).

An acceptance-test run (SEC-05) found that MCP backend containers can dial the
proxy back on :8000 over their dedicated per-backend bridge network — Podman
bridge networks are bidirectional, and the proxy must join each backend net to
*dial* the backend, so the backend can dial it in return. Pure L3 interface
binding isn't viable here: the gateway resolves ``proxy`` to several IPs (it
shares gateway-net AND step-ca-net with the proxy) and re-resolves per request,
so binding uvicorn to a single interface intermittently 502s the gateway.

This closes the gap at L7 instead. The proxy has exactly two legitimate inbound
callers: the gateway (ingress) and localhost (its own healthcheck). Every other
inbound peer — which is precisely what a backend dialing ``proxy:8000`` looks
like — is rejected before any routing. uvicorn is not run with --proxy-headers,
so ``request.client.host`` is the real TCP peer, not an X-Forwarded-For value.

Enabled via PROXY_INGRESS_ALLOWLIST_ENABLED=true. The trusted ingress hostnames
(default: "gateway") are resolved to IPs and cached; loopback is always allowed.
"""
from __future__ import annotations

import ipaddress
import logging
import os
import socket
import time

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

logger = logging.getLogger(__name__)

_LOOPBACK = {"127.0.0.1", "::1"}
_REFRESH_SECONDS = 30.0


class IngressAllowlistMiddleware(BaseHTTPMiddleware):
    """Reject any request whose TCP peer is not the gateway or loopback."""

    def __init__(self, app, trusted_hosts: list[str] | None = None):
        super().__init__(app)
        raw = trusted_hosts or [
            h.strip()
            for h in os.environ.get("PROXY_INGRESS_TRUSTED_HOSTS", "gateway").split(",")
            if h.strip()
        ]
        self._trusted_hosts = raw
        self._allow: set[str] = set(_LOOPBACK)
        self._last_resolve = 0.0
        self._resolve()

    def _resolve(self) -> None:
        allow = set(_LOOPBACK)
        for host in self._trusted_hosts:
            try:
                for info in socket.getaddrinfo(host, None):
                    allow.add(info[4][0])
            except OSError as exc:
                logger.warning("ingress allowlist: could not resolve %r: %s", host, exc)
        self._allow = allow
        self._last_resolve = time.monotonic()

    def _allowed(self, peer: str) -> bool:
        if peer in self._allow:
            return True
        # Refresh at most every _REFRESH_SECONDS, then re-check (container IPs
        # can change on restart; a stale cache must not permanently 403 the gateway).
        if time.monotonic() - self._last_resolve > _REFRESH_SECONDS:
            self._resolve()
            return peer in self._allow
        return False

    async def dispatch(self, request: Request, call_next):
        peer = request.client.host if request.client else None
        if peer and not self._allowed(peer):
            logger.warning(
                "SEC-05 ingress denied: peer %s -> %s (not gateway/loopback)",
                peer, request.url.path,
            )
            return JSONResponse(
                status_code=403,
                content={"code": "INGRESS_DENIED", "message": "direct backend access to the proxy is not permitted"},
            )
        return await call_next(request)
