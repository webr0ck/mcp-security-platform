"""Derive the absolute, user-facing base URL for the current request.

User-facing links (OAuth enrollment prompts, callbacks) must point at the SAME
host the client reached the proxy on — localhost, a LAN/Tailscale IP, a tunnel,
or a public hostname — otherwise the link is unreachable from the user's browser
and (for OAuth) the enrollment host won't match the callback host.

This mirrors the priority used by ``oidc_browser._derive_callback_url`` so the
enrollment link and the OAuth callback always agree on host:
1. ``PROXY_BASE_URL`` — always wins when non-empty (production default).
2. Else, when ``OIDC_TRUST_FORWARDED_HOST`` is true: derive from
   ``X-Forwarded-Proto`` / ``X-Forwarded-Host`` (set by a fronting gateway), or
   the request's ``Host`` header and scheme. The host is validated against a
   strict charset and, when configured, the ``PROXY_ALLOWED_HOSTS`` allow-list
   to block Host-header injection.
3. Else: fall back to ``request.base_url``.
"""
from __future__ import annotations

import re

from fastapi import HTTPException, Request

from app.core.config import get_settings

# hostname[:port] — same charset guard used by the OIDC callback derivation.
_HOST_RE = re.compile(r"^[A-Za-z0-9.\-]+(:\d{1,5})?$")


def derive_public_base_url(request: Request) -> str:
    """Return the absolute base URL (scheme://host[:port]) with no trailing slash."""
    settings = get_settings()

    if settings.PROXY_BASE_URL:
        return settings.PROXY_BASE_URL.rstrip("/")

    if getattr(settings, "OIDC_TRUST_FORWARDED_HOST", False):
        proto = request.headers.get("x-forwarded-proto", request.url.scheme)
        host = request.headers.get("x-forwarded-host") or request.headers.get("host", "localhost")

        if not _HOST_RE.match(host):
            raise HTTPException(status_code=400, detail="Invalid Host header")

        allowed_raw = getattr(settings, "PROXY_ALLOWED_HOSTS", "") or ""
        if allowed_raw:
            allowed = {h.strip() for h in allowed_raw.split(",") if h.strip()}
            if host not in allowed:
                raise HTTPException(status_code=400, detail="Untrusted Host header")

        return f"{proto}://{host}"

    return str(request.base_url).rstrip("/")
