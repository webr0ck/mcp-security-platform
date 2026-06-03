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

import os
import time
from datetime import datetime, timezone
from typing import Any

import httpx
import uvicorn
from mcp.server.fastmcp import FastMCP

GRAPH = "https://graph.microsoft.com/v1.0"
HOST = os.environ.get("HOST", "0.0.0.0")
PORT = int(os.environ.get("PORT", "8000"))

AZURE_TENANT_ID = os.environ.get("AZURE_TENANT_ID") or os.environ.get("ENTRA_TENANT_ID", "")
AZURE_CLIENT_ID = os.environ.get("AZURE_CLIENT_ID") or os.environ.get("ENTRA_CLIENT_ID", "")
AZURE_CLIENT_SECRET = os.environ.get("AZURE_CLIENT_SECRET") or os.environ.get("ENTRA_CLIENT_SECRET", "")

mcp = FastMCP("m365-mcp")

# App-only token cache: (access_token, expires_at_monotonic)
_token_cache: tuple[str, float] | None = None


async def _get_app_token() -> str:
    """Fetch (or return cached) app-only Microsoft Graph access token."""
    global _token_cache
    now = time.monotonic()
    if _token_cache and now < _token_cache[1]:
        return _token_cache[0]

    if not all([AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET]):
        raise ValueError(
            "M365 MCP server not configured: set AZURE_TENANT_ID, AZURE_CLIENT_ID, "
            "AZURE_CLIENT_SECRET in the container environment."
        )

    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.post(
            f"https://login.microsoftonline.com/{AZURE_TENANT_ID}/oauth2/v2.0/token",
            data={
                "grant_type": "client_credentials",
                "client_id": AZURE_CLIENT_ID,
                "client_secret": AZURE_CLIENT_SECRET,
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
    data = await _get("/me")
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
    data = await _get("/me/mailFolders/inbox/messages", params)
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
        f"/me/messages/{message_id}",
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
    await _post("/me/sendMail", {"message": message})
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
    data = await _get("/me/calendarView", params)
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
    data = await _post("/me/events", event)
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
    path = f"/me/drive/{folder_id}/children" if folder_id == "root" else f"/me/drive/items/{folder_id}/children"
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
    data = await _get("/me/joinedTeams", {"$select": "id,displayName,description,isArchived"})
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

if __name__ == "__main__":
    from mcp.server.transport_security import TransportSecuritySettings

    mcp.settings.transport_security = TransportSecuritySettings(
        enable_dns_rebinding_protection=False
    )
    app = mcp.streamable_http_app()
    uvicorn.run(app, host=HOST, port=PORT, log_level="info")
