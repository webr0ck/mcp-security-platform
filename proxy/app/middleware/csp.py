"""
Content-Security-Policy for server-rendered portal HTML (roadmap R1.4).

Until now the portal shipped with NO CSP at all. The lab gateway sets none, and the
production-shaped gateway config sets `default-src 'none'` at server level — which
would block the portal's own /static/portal.js and portal.css outright if it ever
applied to these routes. So the header was either absent or wrong, and either way the
portal had no script-injection containment.

A CSP is only worth adding once inline event handlers are gone: `onclick=` is blocked
by any policy without 'unsafe-inline', and unlike an inline <script> it CANNOT be
rescued by a nonce. R1.4 removed all 100 of them, which is what makes this possible.

The nonce must exist before the HTML is rendered (the inline <script> tags carry it),
so it is generated on the way IN and stashed on request.state; the header is set on
the way out.

Known gap, deliberate: style-src still needs 'unsafe-inline' because the portal has
~570 inline style= attributes. That is roadmap R1.5, and this is its concrete payoff —
finishing it lets the 'unsafe-inline' below be dropped.
"""
from __future__ import annotations

import secrets

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

# script-src intentionally omits 'unsafe-inline': the nonce covers our own inline
# blocks, and a policy carrying both would silently disable the nonce in every
# browser that supports one (a nonce/hash makes 'unsafe-inline' a no-op by spec).
_POLICY = (
    "default-src 'self'; "
    "script-src 'self' 'nonce-{nonce}'; "
    # fonts.googleapis.com serves the webfont CSS; fonts.gstatic.com the font files.
    # Allowed rather than removed because the typography is a product choice — but it
    # IS a third-party request from a platform that otherwise isolates egress, so
    # self-hosting the two families is tracked as follow-up.
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "  # R1.5: drop unsafe-inline
    "img-src 'self' data:; "
    "font-src 'self' https://fonts.gstatic.com; "
    "connect-src 'self'; "
    "form-action 'self'; "
    "frame-ancestors 'none'; "
    "base-uri 'none'; "
    "object-src 'none'"
)


class CSPMiddleware(BaseHTTPMiddleware):
    """Attach a per-request nonce and emit a CSP on HTML responses."""

    def __init__(self, app: ASGIApp, path_prefixes: tuple[str, ...] = ("/portal",)) -> None:
        super().__init__(app)
        self._prefixes = path_prefixes

    async def dispatch(self, request, call_next):
        nonce = secrets.token_urlsafe(16)
        request.state.csp_nonce = nonce
        response = await call_next(request)
        # Only HTML gets a CSP. Applying it to JSON API responses is noise at best,
        # and this middleware is mounted app-wide so /api/v1 traffic passes through it.
        if not request.url.path.startswith(self._prefixes):
            return response
        if "text/html" not in response.headers.get("content-type", ""):
            return response
        response.headers["Content-Security-Policy"] = _POLICY.format(nonce=nonce)
        return response
