"""
M365 MCP Server — Microsoft Graph API gateway-native server.

Designed to run behind mcp-security-platform proxy.
Auth: uses Azure AD client_credentials grant with AZURE_TENANT_ID /
      AZURE_CLIENT_ID / AZURE_CLIENT_SECRET from the environment.
      App-only token is fetched on first call and cached for 50 minutes.

Tools:
  get_me                 — current user profile
  list_emails            — recent inbox messages
  get_email              — single message body + metadata
  list_calendar_events   — upcoming calendar events
  create_calendar_event  — create an event
  list_files             — OneDrive root children
  list_teams             — joined Teams
  send_email             — send a message (requires Mail.Send scope)
"""
from __future__ import annotations

import contextvars
import json
import logging
import os
import re
import time
from datetime import datetime, timezone
from typing import Any

import httpx
import uvicorn
from mcp.server.fastmcp import FastMCP

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("m365-mcp")

GRAPH = (os.environ.get("M365_GRAPH_BASE") or "https://graph.microsoft.com/v1.0").rstrip("/")
HOST = os.environ.get("HOST", "0.0.0.0")
PORT = int(os.environ.get("PORT", "8000"))

# Hardening switch (CR finding #2): when true, refuse to fall back to the
# app-only token if the gateway did not inject a per-user delegated token.
# This prevents the server from silently acting as the APPLICATION (and reading
# the fixed M365_USER mailbox) when an operator believes delegated mode is active.
# S-1 (PRD-0002): default to True. Must be explicitly disabled for app-only testing.
_rd = os.environ.get("REQUIRE_DELEGATED", "true").strip().lower()
REQUIRE_DELEGATED = _rd not in ("0", "false", "no", "off")

# Case-3 "native passthrough" (3b): when true, this server behaves as an OAuth
# 2.0 PROTECTED RESOURCE (RFC 9728). A tools/call without a usable bearer token
# gets HTTP 401 + WWW-Authenticate pointing at this server's protected-resource
# metadata, which names Entra as the authorization server. The gateway relays
# that challenge to the client, which then performs the Entra OAuth itself.
NATIVE_AUTH = os.environ.get("NATIVE_AUTH", "").strip().lower() in (
    "1", "true", "yes", "on",
)
# Public base URL of THIS resource as seen by the client (through the gateway).
# Used as the `resource` identifier and to build the metadata URL in challenges.
RESOURCE_URL = os.environ.get("M365_RESOURCE_URL", "http://localhost:8000/mcp")
_PRM_PATH = "/.well-known/oauth-protected-resource"

# ---------------------------------------------------------------------------
# Delegated-token plumbing.
#
# The gateway may inject a per-user DELEGATED Microsoft Graph token via the
# inbound Authorization header (injection_mode=entra_user_token). When present,
# the server acts AS THE USER (/me has meaning). When absent, it falls back to
# the app-only client_credentials token (acts as the application, /users/{id}).
# The inbound header is captured by an ASGI middleware (see __main__) into this
# contextvar so @mcp.tool() functions — which have no request object — can read it.
# ---------------------------------------------------------------------------
_injected_auth: contextvars.ContextVar[str] = contextvars.ContextVar("injected_auth", default="")


def _http_request():
    """Best-effort access to the current Starlette HTTP request.

    The MCP streamable-http server sets request_ctx in the SAME task that runs
    the tool, so reading headers here works even though the ASGI middleware's
    contextvar (set in a different task) does not propagate to the tool.
    """
    try:
        from mcp.server.lowlevel.server import request_ctx
        req = getattr(request_ctx.get(), "request", None)
        if req is not None and hasattr(req, "headers"):
            return req
    except Exception:
        pass
    return None


def _injected_token() -> str:
    """Return the bearer token the gateway injected for this request, or ''."""
    req = _http_request()
    raw = req.headers.get("authorization", "") if req is not None else _injected_auth.get()
    if raw and raw[:7].lower() == "bearer ":
        return raw[7:].strip()
    return ""


_UPN_RE = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")


def _caller_upn() -> str:
    """Return the calling principal's own UPN, when the proxy resolved one
    (X-M365-Caller-Upn — injected only in app-only/entra_client_credentials
    mode, when this caller has their own m365-graph-delegated enrollment on
    record; see dispatcher.py::_lookup_m365_caller_upn). Empty otherwise.

    Trust model: identical to every other proxy-injected identity header this
    server already relies on (X-User-Sub etc) — this server is network-
    isolated behind the proxy's pairwise net and never receives direct
    traffic (SEC-05 ingress hardening); the proxy, not this server, is the
    trust anchor for identity. Regardless of that boundary, strictly validate
    the shape here before it's interpolated into a Graph URL path — a
    malformed or malicious value must never reach the upstream request.
    """
    req = _http_request()
    if req is None:
        return ""
    raw = req.headers.get("x-m365-caller-upn", "").strip()
    if raw and not _UPN_RE.match(raw):
        logger.warning("Rejecting malformed X-M365-Caller-Upn header (not a valid UPN shape)")
        return ""
    return raw


def _is_delegated() -> bool:
    """True when a gateway-injected per-user (delegated) token is in play for
    this request — NOT merely "is there an Authorization header", since an
    app-only (entra_client_credentials) call injects one too, with the exact
    same header/prefix. Checking token presence alone made every app-only
    call look delegated, so get_me always tried /me and always 400'd under
    app-only auth regardless of M365_USER/per-caller UPN (found live). The
    proxy sets X-Entra-Auth-Mode explicitly per dispatch case — see
    dispatcher.py's _inject_entra_user_token ("delegated") vs
    _inject_entra_client_credentials ("app-only") — so trust that instead.
    """
    req = _http_request()
    if req is not None:
        mode = req.headers.get("x-entra-auth-mode", "")
        if mode:
            return mode == "delegated"
    # No explicit mode header (e.g. a direct test call bypassing the proxy) —
    # fall back to the old heuristic rather than silently treating everything
    # as app-only, which would be a behavior change for anyone relying on it.
    return bool(_injected_token())

AZURE_TENANT_ID = os.environ.get("AZURE_TENANT_ID") or os.environ.get("ENTRA_TENANT_ID", "")
_DEFAULT_TOKEN_URL = (
    f"https://login.microsoftonline.com/{AZURE_TENANT_ID}/oauth2/v2.0/token"
    if AZURE_TENANT_ID else "https://login.microsoftonline.com/common/oauth2/v2.0/token"
)
M365_TOKEN_URL = os.environ.get("M365_TOKEN_URL") or _DEFAULT_TOKEN_URL
AZURE_CLIENT_ID = os.environ.get("AZURE_CLIENT_ID") or os.environ.get("ENTRA_CLIENT_ID", "")
# Task 2.5: AZURE_CLIENT_SECRET is NOT read from env (env var removed from compose).
# The credential broker injects it at call time via a custom Authorization header scheme.
# The _InjectedAuthMiddleware captures an "X-Entra-Client-Secret" header if present;
# _get_client_secret() returns it. Falls back to empty string (tools will fail loudly).
_injected_client_secret: contextvars.ContextVar[str] = contextvars.ContextVar(
    "_injected_client_secret", default=""
)
# UPN or object ID of the mailbox/calendar to access with app-only token.
# Example: "user@contoso.com" or a GUID. Required for /me endpoints with client_credentials.
M365_USER = os.environ.get("M365_USER", "")

# Entra authorization-server issuer for this tenant (advertised in RFC 9728 PRM).
_ENTRA_ISSUER = (
    f"https://login.microsoftonline.com/{AZURE_TENANT_ID}/v2.0"
    if AZURE_TENANT_ID else "https://login.microsoftonline.com/common/v2.0"
)


def _me(path: str = "") -> str:
    """
    Resolve the Graph target for "the current user".

    - Delegated (gateway-injected user token): use /me — the token carries the
      signed-in user's context, so /me is valid and resolves to that human.
    - App-only, per-caller UPN known: the proxy resolved THIS caller's own UPN
      from their own m365-graph-delegated enrollment (X-M365-Caller-Upn) —
      target /users/{their UPN}, so different callers each see their own
      profile rather than one shared mailbox.
    - App-only, no per-caller UPN: fall back to the single hand-configured
      M365_USER mailbox if set, else /me (which will 400 — surfaces the
      misconfig clearly).
    """
    if _is_delegated():
        return f"/me{path}"
    caller_upn = _caller_upn()
    if caller_upn:
        return f"/users/{caller_upn}{path}"
    if M365_USER:
        return f"/users/{M365_USER}{path}"
    return f"/me{path}"

mcp = FastMCP("m365-mcp")

# App-only token cache: (access_token, expires_at_monotonic)
_token_cache: tuple[str, float] | None = None


def _get_client_secret() -> str:
    """
    Return the Entra client secret for this request.

    Task 2.5: secret comes from the broker-injected X-Entra-Client-Secret header,
    NOT from the AZURE_CLIENT_SECRET env var (which is absent from compose).
    """
    req = _http_request()
    if req is not None:
        return req.headers.get("x-entra-client-secret", "")
    return _injected_client_secret.get()


async def _get_app_token() -> str:
    """Fetch (or return cached) app-only Microsoft Graph access token."""
    global _token_cache
    now = time.monotonic()
    if _token_cache and now < _token_cache[1]:
        return _token_cache[0]

    client_secret = _get_client_secret()
    if not all([AZURE_TENANT_ID, AZURE_CLIENT_ID, client_secret]):
        raise ValueError(
            "M365 MCP server not configured: AZURE_TENANT_ID and AZURE_CLIENT_ID must be set, "
            "and the credential broker must inject the client secret via X-Entra-Client-Secret header. "
            "Ensure the tool is registered with injection_mode=entra_client_credentials in the proxy."
        )

    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.post(
            M365_TOKEN_URL,
            data={
                "grant_type": "client_credentials",
                "client_id": AZURE_CLIENT_ID,
                "client_secret": client_secret,
                "scope": "https://graph.microsoft.com/.default",
            },
        )
        resp.raise_for_status()
        data = resp.json()

    token = data.get("access_token", "")
    expires_in = int(data.get("expires_in", 3600))
    _token_cache = (token, now + expires_in - 600)  # 10-min safety margin
    return token


async def _headers() -> dict[str, str]:
    # Prefer the gateway-injected delegated token (acts as the user).
    token = _injected_token()
    if not token:
        # No per-user token was injected. Either delegated mode is not wired on
        # the gateway, or the caller is not enrolled. Falling back to app-only
        # silently changes identity from "the user" to "the application" — the
        # exact footgun behind the confusing glass@ results. Make it loud, and
        # refuse outright when REQUIRE_DELEGATED is set.
        if REQUIRE_DELEGATED:
            raise PermissionError(
                "REQUIRE_DELEGATED is set but the gateway injected no per-user "
                "token. Refusing app-only fallback. Ensure the gateway tool uses "
                "injection_mode=entra_user_token and that the caller has enrolled "
                "via /auth/enroll/m365."
            )
        logger.warning(
            "No gateway-injected delegated token — falling back to APP-ONLY "
            "credentials (acting as the application '%s', reading M365_USER=%s, "
            "NOT the calling user). For per-user access set the gateway tool to "
            "injection_mode=entra_user_token and enroll via /auth/enroll/m365.",
            AZURE_CLIENT_ID or "(unset)",
            M365_USER or "(unset)",
        )
        token = await _get_app_token()
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }


async def _get(path: str, params: dict | None = None) -> Any:
    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.get(f"{GRAPH}{path}", headers=await _headers(), params=params or {})
        resp.raise_for_status()
        return resp.json()


async def _post(path: str, body: dict) -> Any:
    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.post(f"{GRAPH}{path}", headers=await _headers(), json=body)
        resp.raise_for_status()
        return resp.json() if resp.content else {}


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------

@mcp.tool()
async def get_me() -> dict:
    """Return the authenticated user's profile from Microsoft Graph."""
    data = await _get(_me())
    return {
        "id": data.get("id"),
        "display_name": data.get("displayName"),
        "email": data.get("mail") or data.get("userPrincipalName"),
        "job_title": data.get("jobTitle"),
        "department": data.get("department"),
        "office_location": data.get("officeLocation"),
    }


@mcp.tool()
async def list_emails(top: int = 20, filter: str = "") -> dict:
    """
    List inbox messages, newest first.
    top: number of messages to return (max 50).
    filter: OData filter string, e.g. "isRead eq false" or "importance eq 'high'".
    """
    top = max(1, min(top, 50))
    params: dict[str, Any] = {
        "$top": top,
        "$orderby": "receivedDateTime desc",
        "$select": "id,subject,from,receivedDateTime,isRead,importance,hasAttachments,bodyPreview",
    }
    if filter:
        params["$filter"] = filter
    data = await _get(_me("/mailFolders/inbox/messages"), params)
    return {
        "messages": [
            {
                "id": m["id"],
                "subject": m.get("subject", "(no subject)"),
                "from": m.get("from", {}).get("emailAddress", {}).get("address"),
                "received_at": m.get("receivedDateTime"),
                "is_read": m.get("isRead"),
                "importance": m.get("importance"),
                "has_attachments": m.get("hasAttachments"),
                "preview": m.get("bodyPreview", "")[:200],
            }
            for m in data.get("value", [])
        ],
        "count": len(data.get("value", [])),
    }


@mcp.tool()
async def get_email(message_id: str) -> dict:
    """
    Get the full content of a specific email message.
    message_id: the id field from list_emails.
    """
    data = await _get(
        _me(f"/messages/{message_id}"),
        {"$select": "id,subject,from,toRecipients,ccRecipients,receivedDateTime,body,isRead,importance,hasAttachments"},
    )
    return {
        "id": data.get("id"),
        "subject": data.get("subject"),
        "from": data.get("from", {}).get("emailAddress", {}).get("address"),
        "to": [r["emailAddress"]["address"] for r in data.get("toRecipients", [])],
        "cc": [r["emailAddress"]["address"] for r in data.get("ccRecipients", [])],
        "received_at": data.get("receivedDateTime"),
        "importance": data.get("importance"),
        "has_attachments": data.get("hasAttachments"),
        "body_type": data.get("body", {}).get("contentType"),
        "body": data.get("body", {}).get("content", ""),
    }


@mcp.tool()
async def send_email(
    to: str,
    subject: str,
    body: str,
    cc: str = "",
    body_type: str = "Text",
) -> dict:
    """
    Send an email via Microsoft Graph.
    to: recipient email address (single address).
    subject: email subject.
    body: email body content.
    cc: optional CC address.
    body_type: "Text" or "HTML".
    """
    message: dict[str, Any] = {
        "subject": subject,
        "body": {"contentType": body_type, "content": body},
        "toRecipients": [{"emailAddress": {"address": to}}],
    }
    if cc:
        message["ccRecipients"] = [{"emailAddress": {"address": cc}}]
    await _post(_me("/sendMail"), {"message": message})
    return {"sent": True, "to": to, "subject": subject}


@mcp.tool()
async def list_calendar_events(
    top: int = 20,
    start: str = "",
    end: str = "",
) -> dict:
    """
    List upcoming calendar events.
    top: max events to return (max 50).
    start: ISO 8601 start of range, e.g. "2026-06-01T00:00:00Z". Defaults to now.
    end: ISO 8601 end of range, e.g. "2026-06-30T23:59:59Z". Defaults to +30 days.
    """
    from datetime import timedelta

    top = max(1, min(top, 50))
    now = datetime.now(timezone.utc)
    start_dt = start or now.isoformat()
    end_dt = end or (now + timedelta(days=30)).isoformat()

    params = {
        "startDateTime": start_dt,
        "endDateTime": end_dt,
        "$top": top,
        "$orderby": "start/dateTime",
        "$select": "id,subject,start,end,location,organizer,isAllDay,isCancelled,onlineMeetingUrl",
    }
    data = await _get(_me("/calendarView"), params)
    return {
        "events": [
            {
                "id": e["id"],
                "subject": e.get("subject", "(no subject)"),
                "start": e.get("start", {}).get("dateTime"),
                "end": e.get("end", {}).get("dateTime"),
                "timezone": e.get("start", {}).get("timeZone"),
                "location": e.get("location", {}).get("displayName"),
                "organizer": e.get("organizer", {}).get("emailAddress", {}).get("address"),
                "is_all_day": e.get("isAllDay"),
                "is_cancelled": e.get("isCancelled"),
                "meeting_url": e.get("onlineMeetingUrl"),
            }
            for e in data.get("value", [])
        ],
        "count": len(data.get("value", [])),
    }


@mcp.tool()
async def create_calendar_event(
    subject: str,
    start: str,
    end: str,
    body: str = "",
    location: str = "",
    attendees: str = "",
    is_online_meeting: bool = False,
) -> dict:
    """
    Create a calendar event.
    subject: event title.
    start: ISO 8601 datetime, e.g. "2026-06-10T09:00:00".
    end: ISO 8601 datetime, e.g. "2026-06-10T10:00:00".
    body: optional event description.
    location: optional location string.
    attendees: comma-separated email addresses.
    is_online_meeting: whether to create a Teams meeting link.
    """
    event: dict[str, Any] = {
        "subject": subject,
        "start": {"dateTime": start, "timeZone": "UTC"},
        "end": {"dateTime": end, "timeZone": "UTC"},
        "isOnlineMeeting": is_online_meeting,
    }
    if body:
        event["body"] = {"contentType": "Text", "content": body}
    if location:
        event["location"] = {"displayName": location}
    if attendees:
        event["attendees"] = [
            {"emailAddress": {"address": a.strip()}, "type": "required"}
            for a in attendees.split(",")
            if a.strip()
        ]
    data = await _post(_me("/events"), event)
    return {
        "id": data.get("id"),
        "subject": data.get("subject"),
        "start": data.get("start", {}).get("dateTime"),
        "end": data.get("end", {}).get("dateTime"),
        "web_link": data.get("webLink"),
        "meeting_url": data.get("onlineMeetingUrl"),
    }


@mcp.tool()
async def list_files(folder_id: str = "root", top: int = 50) -> dict:
    """
    List files/folders in OneDrive.
    folder_id: DriveItem id, or "root" for the root folder.
    top: max items to return (max 100).
    """
    top = max(1, min(top, 100))
    path = _me(f"/drive/{folder_id}/children") if folder_id == "root" else _me(f"/drive/items/{folder_id}/children")
    data = await _get(path, {"$top": top, "$select": "id,name,size,lastModifiedDateTime,folder,file,webUrl"})
    return {
        "items": [
            {
                "id": item["id"],
                "name": item["name"],
                "type": "folder" if "folder" in item else "file",
                "size_bytes": item.get("size"),
                "modified_at": item.get("lastModifiedDateTime"),
                "web_url": item.get("webUrl"),
                "child_count": item.get("folder", {}).get("childCount"),
            }
            for item in data.get("value", [])
        ],
        "count": len(data.get("value", [])),
    }


@mcp.tool()
async def list_teams() -> dict:
    """List the Microsoft Teams the authenticated user has joined."""
    data = await _get(_me("/joinedTeams"), {"$select": "id,displayName,description,isArchived"})
    return {
        "teams": [
            {
                "id": t["id"],
                "name": t.get("displayName"),
                "description": t.get("description", ""),
                "is_archived": t.get("isArchived", False),
            }
            for t in data.get("value", [])
        ],
        "count": len(data.get("value", [])),
    }


@mcp.tool()
async def list_team_channels(team_id: str) -> dict:
    """
    List channels in a Teams team.
    team_id: the id field from list_teams.
    """
    data = await _get(
        f"/teams/{team_id}/channels",
        {"$select": "id,displayName,description,membershipType"},
    )
    return {
        "team_id": team_id,
        "channels": [
            {
                "id": c["id"],
                "name": c.get("displayName"),
                "description": c.get("description", ""),
                "type": c.get("membershipType"),
            }
            for c in data.get("value", [])
        ],
        "count": len(data.get("value", [])),
    }


# ---------------------------------------------------------------------------
# App wiring
# ---------------------------------------------------------------------------


def _protected_resource_metadata() -> dict:
    """RFC 9728 Protected Resource Metadata: names Entra as the auth server."""
    return {
        "resource": RESOURCE_URL,
        "authorization_servers": [_ENTRA_ISSUER],
        "scopes_supported": (os.environ.get("ENTRA_SCOPES", "") or "User.Read").split(),
        "bearer_methods_supported": ["header"],
    }


async def _send_json(send, status: int, payload: dict, extra_headers: list | None = None) -> None:
    body = json.dumps(payload).encode()
    headers = [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())]
    if extra_headers:
        headers.extend(extra_headers)
    await send({"type": "http.response.start", "status": status, "headers": headers})
    await send({"type": "http.response.body", "body": body})


class _InjectedAuthMiddleware:
    """
    Pure-ASGI middleware with two jobs:

    1. Capture the inbound Authorization header into a contextvar BEFORE FastMCP
       handles the request, so tool functions (no request object) can read the
       gateway-injected token. Pure-ASGI (not Starlette BaseHTTPMiddleware) on
       purpose: the contextvar set here is visible in the same task that runs the
       JSON-RPC tool call; BaseHTTPMiddleware runs the app in a child task and the
       value would not propagate.

    2. NATIVE_AUTH (Case-3 / 3b) — act as an OAuth 2.0 protected resource:
       - serve RFC 9728 metadata at /.well-known/oauth-protected-resource
       - answer a tools/call that carries no bearer token with HTTP 401 +
         WWW-Authenticate, pointing the client at that metadata (→ Entra).
       initialize / notifications / tools/list pass through unchallenged so the
       gateway can still set up the session and enumerate tools.
    """

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        auth = ""
        client_secret = ""
        for k, v in scope.get("headers", []):
            kl = k.lower()
            if kl == b"authorization":
                auth = v.decode("latin-1")
            elif kl == b"x-entra-client-secret":
                # Task 2.5: broker-injected client secret for entra_client_credentials mode
                client_secret = v.decode("latin-1")
        _injected_auth.set(auth)
        _injected_client_secret.set(client_secret)

        # NATIVE_AUTH: serve protected-resource metadata.
        if NATIVE_AUTH and path == _PRM_PATH:
            await _send_json(send, 200, _protected_resource_metadata())
            return

        # NATIVE_AUTH: challenge token-less tools/call with a 401.
        if NATIVE_AUTH and scope.get("method") == "POST" and not _injected_token():
            body_chunks = []
            more = True
            while more:
                msg = await receive()
                body_chunks.append(msg.get("body", b""))
                more = msg.get("more_body", False)
            raw = b"".join(body_chunks)
            try:
                method = json.loads(raw or b"{}").get("method", "")
            except Exception:
                method = ""
            if method == "tools/call":
                meta_url = RESOURCE_URL.rsplit("/mcp", 1)[0].rstrip("/") + _PRM_PATH
                www = (
                    f'Bearer realm="m365-mcp", '
                    f'authorization_uri="{_ENTRA_ISSUER}", '
                    f'resource_metadata="{meta_url}"'
                )
                await _send_json(
                    send, 401,
                    {"error": "unauthorized",
                     "error_description": "Delegated Microsoft Graph token required. "
                                          "Authenticate via the resource metadata authorization server (Entra).",
                     "authorization_servers": [_ENTRA_ISSUER]},
                    extra_headers=[(b"www-authenticate", www.encode())],
                )
                return
            # Not a tools/call — replay the buffered body downstream.
            replayed = {"sent": False}

            async def _replay_receive():
                if not replayed["sent"]:
                    replayed["sent"] = True
                    return {"type": "http.request", "body": raw, "more_body": False}
                return await receive()

            await self.app(scope, _replay_receive, send)
            return

        await self.app(scope, receive, send)


if __name__ == "__main__":
    from mcp.server.transport_security import TransportSecuritySettings

    mcp.settings.transport_security = TransportSecuritySettings(
        enable_dns_rebinding_protection=False
    )
    app = _InjectedAuthMiddleware(mcp.streamable_http_app())
    uvicorn.run(app, host=HOST, port=PORT, log_level="info")
