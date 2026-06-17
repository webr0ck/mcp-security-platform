"""
mcphub_sdk.context — Identity and credential ContextVar propagation.

Security invariants:
  - Identity is populated ONLY from proxy-injected headers (X-User-Sub, X-User-Role).
    A caller that bypasses the proxy always resolves as anonymous/agent.
  - credential() env fallback applies ONLY when the request is marked proxied
    (i.e. X-User-Sub is present). An un-proxied request gets None — never the
    env service credential — so direct/SSRF callers cannot harvest the token.
  - ContextVars are reset in a try/finally block so there is zero bleed between
    requests on a reused worker (H10 concurrent-request safety).
  - credential() value is never logged by the SDK.
"""
from __future__ import annotations

import os
from contextvars import ContextVar
from dataclasses import dataclass

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

# ---------------------------------------------------------------------------
# Module-level ContextVars — one set per Python interpreter; reset per request
# ---------------------------------------------------------------------------

_sub: ContextVar[str] = ContextVar("mcphub_sub", default="anonymous")
_role: ContextVar[str] = ContextVar("mcphub_role", default="agent")
_auth: ContextVar[str] = ContextVar("mcphub_auth", default="")

# True iff the current request carried an X-User-Sub header (proxy fingerprint).
# Used by credential() to enforce fail-closed env fallback (H2).
_proxied: ContextVar[bool] = ContextVar("mcphub_proxied", default=False)


# ---------------------------------------------------------------------------
# Public types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Identity:
    """
    Immutable snapshot of the caller's identity for the current request.

    Fields are populated from proxy-injected headers only; direct callers
    always receive the defaults (sub="anonymous", role="agent").

    IMPORTANT — FO-1 / H3: identity() is the ONLY correct way to obtain caller
    identity inside a tool. Never use a tool parameter named user_sub, caller_sub,
    principal_id, or similar — such parameters are spoofable by any caller.
    """

    sub: str = "anonymous"
    role: str = "agent"


# ---------------------------------------------------------------------------
# Public accessors
# ---------------------------------------------------------------------------


def identity() -> Identity:
    """Return the proxy-injected caller identity for the current request.

    Returns Identity(sub="anonymous", role="agent") for un-proxied requests.
    Thread/task-safe: backed by ContextVars reset per request in _ContextMiddleware.
    """
    return Identity(sub=_sub.get(), role=_role.get())


def credential(env_var: str | None = None) -> str | None:
    """Return the injected Authorization token for the current request.

    Resolution order:
      1. Authorization header injected by the proxy (Bearer/token prefix stripped).
      2. os.environ[env_var] — ONLY when env_var is set AND the request is proxied
         (X-User-Sub header was present). Un-proxied requests always receive None
         even if env_var is set (H2 fail-closed, security IV-4/FO-2).

    DO NOT log the return value — it is a live credential.
    """
    raw = _auth.get()
    if raw:
        low = raw.lower()
        if low.startswith("bearer "):
            return raw[7:].strip()
        if low.startswith("token "):
            return raw[6:].strip()
        return raw.strip()
    # env fallback: only when proxied (X-User-Sub was present on this request)
    if env_var and _proxied.get():
        v = os.environ.get(env_var, "")
        return v or None
    return None


# ---------------------------------------------------------------------------
# Middleware
# ---------------------------------------------------------------------------


class _ContextMiddleware(BaseHTTPMiddleware):
    """Populate per-request ContextVars from proxy-injected HTTP headers.

    H2: When require_proxy=True (default), any request missing X-User-Sub is
    rejected with HTTP 403 BEFORE any tool runs — except the /health route,
    which must always be reachable for liveness probes.

    ContextVars are reset in finally so concurrent/pipelined requests on the
    same event-loop thread never bleed identity across request boundaries (H10).
    """

    def __init__(self, app, *, require_proxy: bool = True) -> None:
        super().__init__(app)
        self._require_proxy = require_proxy

    async def dispatch(self, request: Request, call_next):
        sub = request.headers.get("x-user-sub")

        # H1: /health is always allowed — the proxy may not inject headers on
        # internal liveness probes.
        if self._require_proxy and sub is None and request.url.path != "/health":
            return JSONResponse(
                {"error": "proxy identity header required"}, status_code=403
            )

        t_sub = _sub.set(sub or "anonymous")
        t_role = _role.set(request.headers.get("x-user-role", "agent"))
        t_auth = _auth.set(request.headers.get("authorization", ""))
        t_px = _proxied.set(sub is not None)
        try:
            return await call_next(request)
        finally:
            _sub.reset(t_sub)
            _role.reset(t_role)
            _auth.reset(t_auth)
            _proxied.reset(t_px)
