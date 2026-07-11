"""
Integration Test — Invocation Audit on Credential Injection Failure (INV-001)

Verifies that a tool configured with an unsupported injection_mode (e.g.
'basic_auth') causes the invocation pipeline to:
  1. Return 500 or 502 with a credential_injection_failed error code
     (never 200, never a silent unauthenticated upstream call).
  2. Emit exactly one audit event with outcome='deny' before returning
     (INV-001 compliance).

Run: pytest tests/integration/test_invocation_audit.py -m integration
Requires: docker compose up (postgres, redis, opa, proxy services)

Test data requirements:
  - A tool seeded in tool_registry with injection_mode='basic_auth'
    and tool_id=BASIC_AUTH_TOOL_ID (UUID below)
  - client 'test-agent-client' with role=agent, OPA grant for that tool
  - DB DSN accessible at localhost:5432

NOTE: basic_auth is now a SUPPORTED mode (CR-05, _inject_basic_auth). This test
still holds because the seeded fixture tool has NO provisioned credential /
service_name: the dispatcher must raise CredentialInjectionError
(ServiceCredentialMissingError / missing-service_name fail-closed), never
forward the call unauthenticated — the INV-001 deny-audit invariant is
mode-independent.
"""
from __future__ import annotations

import asyncio
from typing import AsyncIterator

import asyncpg
import httpx
import pytest

import os as _os
from app.core.config import settings as _settings

PROXY_URL = "http://localhost:8000"
DB_DSN = _os.environ.get("TEST_DB_DSN") or (
    f"postgresql://{_settings.DB_USER}:{_settings.DB_PASSWORD}"
    f"@{_settings.DB_HOST}:{_settings.DB_PORT}/{_settings.DB_NAME}"
)

# UUID for a tool seeded with injection_mode='basic_auth' — must match fixtures.
BASIC_AUTH_TOOL_ID = "00000000-0000-0000-0000-000000000031"


def _gw() -> str:
    try:
        from app.core.config import settings
        return settings.GATEWAY_SHARED_SECRET
    except Exception:
        return ""


_GW = _gw()

AGENT_HEADERS = {"X-Client-Cert-CN": "test-agent-client", "X-Gateway-Secret": _GW}


@pytest.fixture
async def db_conn() -> AsyncIterator[asyncpg.Connection]:
    """Live PostgreSQL connection for audit event verification."""
    conn = await asyncpg.connect(DB_DSN)
    yield conn
    await conn.close()


async def _count_deny_events(conn: asyncpg.Connection, tool_id: str) -> int:
    """Count audit_events rows with outcome='deny' for the given tool_id."""
    row = await conn.fetchrow(
        "SELECT COUNT(*) AS cnt FROM audit_events WHERE tool_id = $1 AND outcome = 'deny'",
        tool_id,
    )
    return int(row["cnt"]) if row else 0


# ---------------------------------------------------------------------------
# Test: basic_auth injection_mode → fail-closed response + deny audit event
# ---------------------------------------------------------------------------

@pytest.mark.integration
@pytest.mark.asyncio
async def test_basic_auth_tool_returns_error_and_emits_deny_audit(db_conn):
    """
    A tool configured with injection_mode='basic_auth' must:
      1. Return HTTP 500 or 502 (never 200).
      2. Include a structured error body indicating credential_injection_failed.
      3. Emit exactly one audit event with outcome='deny' (INV-001).

    This covers the fail-closed fix: previously the dispatcher returned {}
    and the call was forwarded unauthenticated. After the fix it raises
    CredentialInjectionError which the invocation layer translates to a
    5xx response and a deny audit event.
    """
    invoke_body = {
        "jsonrpc": "2.0",
        "id": "test-basic-auth-fail-closed",
        "method": "tools/call",
        "params": {
            "name": "basic-auth-unsupported-tool",
            "arguments": {},
        },
    }

    events_before = await _count_deny_events(db_conn, BASIC_AUTH_TOOL_ID)

    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"{PROXY_URL}/api/v1/tools/{BASIC_AUTH_TOOL_ID}/invoke",
            json=invoke_body,
            headers=AGENT_HEADERS,
        )

    # The dispatcher raises CredentialInjectionError; invoke_tool translates
    # this to a 500/502 — never 200 (which would indicate a silent forward).
    assert resp.status_code in (500, 502), (
        f"Expected 500 or 502 for basic_auth injection_mode, got {resp.status_code}. "
        f"Body: {resp.text[:400]}"
    )

    body = resp.json()

    # The error envelope must identify credential injection failure.
    # Accept both detail-envelope (FastAPI) and error-envelope (JSON-RPC) shapes.
    error_payload = body.get("detail") or body.get("error") or {}
    if isinstance(error_payload, str):
        error_str = error_payload
    else:
        error_str = (
            error_payload.get("code", "")
            + " "
            + error_payload.get("message", "")
        ).lower()

    assert "credential_injection" in error_str or "credential" in error_str, (
        f"Expected credential injection error in response, got: {body}"
    )

    # INV-001: exactly one deny audit event must have been emitted before the
    # response was returned.
    events_after = await _count_deny_events(db_conn, BASIC_AUTH_TOOL_ID)
    assert events_after == events_before + 1, (
        f"INV-001: Expected exactly one new deny audit event for tool {BASIC_AUTH_TOOL_ID}, "
        f"got {events_after - events_before}. "
        "The dispatcher fail-closed raise must be caught by invoke_tool and result "
        "in a deny audit event before responding."
    )
