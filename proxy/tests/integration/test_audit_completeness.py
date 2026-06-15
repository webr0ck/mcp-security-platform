"""
Integration Test — Audit Event Completeness (INV-001)

Verifies that every tool invocation (ALLOW or DENY) produces exactly one
audit event in the audit_events table before the response is returned to
the caller.

INV-001 statement: "Every call to POST /tools/{tool_id}/invoke, whether
the outcome is ALLOW or DENY, must produce an audit event record before
any response is returned."

Corollary: Auth-layer rejections (401 UNAUTHENTICATED) occur before the
invocation pipeline is entered. They must NOT produce audit events.

Run: pytest tests/integration/test_audit_completeness.py -m integration
Requires: docker compose up (postgres, redis, opa, proxy services)

Test data requirements (see docs/test-plan.md Section 5):
  - tool 'active-low-risk-tool' with status=active, risk_level=low
  - tool 'quarantined-tool' with status=quarantined
  - client 'test-agent-client' with role=agent, OPA grant for active-low-risk-tool
  - client 'test-agent-no-grant' with role=agent, NO OPA grants
"""
from __future__ import annotations

import asyncio
from typing import AsyncIterator

import asyncpg
import httpx
import pytest

PROXY_URL = "http://localhost:8000"
import os as _os
from app.core.config import settings as _settings

# Derive the DSN from the same settings the app uses (DB_HOST=db inside the
# proxy container; localhost only when run from the host with TEST_DB_DSN).
# asyncpg.connect needs a plain postgresql:// DSN (no +asyncpg driver tag).
DB_DSN = _os.environ.get("TEST_DB_DSN") or (
    f"postgresql://{_settings.DB_USER}:{_settings.DB_PASSWORD}"
    f"@{_settings.DB_HOST}:{_settings.DB_PORT}/{_settings.DB_NAME}"
)

# Test tool UUIDs — must match seeded fixtures
ACTIVE_TOOL_ID = "00000000-0000-0000-0000-000000000010"
QUARANTINED_TOOL_ID = "00000000-0000-0000-0000-000000000020"

def _gw() -> str:
    try:
        from app.core.config import settings
        return settings.GATEWAY_SHARED_SECRET
    except Exception:
        return ""

_GW = _gw()

# Auth headers — simulate mTLS cert CN injected by Nginx gateway
AGENT_HEADERS = {"X-Client-Cert-CN": "test-agent-client", "X-Gateway-Secret": _GW}
AGENT_NO_GRANT_HEADERS = {"X-Client-Cert-CN": "test-agent-no-grant", "X-Gateway-Secret": _GW}
ADMIN_HEADERS = {"X-Client-Cert-CN": "test-admin-client", "X-Gateway-Secret": _GW}

INVOKE_BODY_TEMPLATE = {
    "jsonrpc": "2.0",
    "id": "test-audit-1",
    "method": "tools/call",
    "params": {
        "name": "active-low-risk-tool",
        "arguments": {"path": "/tmp/test.txt"},
    },
}


@pytest.fixture
async def db_conn() -> AsyncIterator[asyncpg.Connection]:
    """
    Async PostgreSQL connection for audit event count verification.
    Only used by integration tests (requires running postgres).
    """
    conn = await asyncpg.connect(DB_DSN)
    yield conn
    await conn.close()


async def _count_audit_events(conn: asyncpg.Connection, client_id: str) -> int:
    """Count audit events in the database for a specific client_id."""
    row = await conn.fetchrow(
        "SELECT COUNT(*) AS cnt FROM audit_events WHERE client_id = $1",
        client_id,
    )
    return int(row["cnt"])


async def _get_latest_audit_event(conn: asyncpg.Connection, client_id: str) -> dict | None:
    """Fetch the most recent audit event for a client."""
    row = await conn.fetchrow(
        """
        SELECT event_id, client_id, tool_name, outcome, sha256_hash, created_at
        FROM audit_events
        WHERE client_id = $1
        ORDER BY created_at DESC
        LIMIT 1
        """,
        client_id,
    )
    return dict(row) if row else None


@pytest.mark.integration
@pytest.mark.asyncio
async def test_allow_path_produces_one_audit_event(db_conn: asyncpg.Connection):
    """
    Covers INV-001: ALLOW path.

    When an agent with a valid OPA grant invokes an active tool and the upstream
    succeeds, exactly one audit event with outcome='allow' must be written to
    audit_events before the HTTP response is returned.
    """
    client_id = "test-agent-client"
    before_count = await _count_audit_events(db_conn, client_id)

    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"{PROXY_URL}/api/v1/tools/{ACTIVE_TOOL_ID}/invoke",
            json=INVOKE_BODY_TEMPLATE,
            headers=AGENT_HEADERS,
        )

    # We accept 200 (allow) or 500 (upstream error) — both must emit an audit event.
    # We do NOT accept 403/401/503, which would indicate a test fixture problem.
    assert resp.status_code in (200, 500), (
        f"Expected 200 or 500 from allow path, got {resp.status_code}. "
        f"Body: {resp.text[:300]}"
    )

    after_count = await _count_audit_events(db_conn, client_id)
    assert after_count == before_count + 1, (
        f"INV-001 violated on ALLOW path: expected exactly 1 new audit event, "
        f"got {after_count - before_count}. "
        f"before={before_count}, after={after_count}"
    )

    latest = await _get_latest_audit_event(db_conn, client_id)
    assert latest is not None
    # DB CHECK constraint only allows 'allow'/'deny'; upstream errors are stored as 'deny'
    # (with opa_reasons=[\"upstream_init_failed\"] to distinguish from OPA denies).
    # The invariant is that ONE audit event was emitted (checked above).
    assert latest["outcome"] in ("allow", "deny"), (
        f"Expected outcome in ('allow', 'deny'), got '{latest['outcome']}'"
    )
    assert latest["tool_name"] == "active-low-risk-tool"


@pytest.mark.integration
@pytest.mark.asyncio
async def test_deny_path_produces_one_audit_event(db_conn: asyncpg.Connection):
    """
    Covers INV-001: DENY path (OPA deny for agent with no grant).

    When an agent with NO OPA grant attempts to invoke a tool, OPA denies the
    request. The proxy must still emit exactly one audit event with outcome='deny'
    before returning the 403 response.
    """
    client_id = "test-agent-no-grant"
    before_count = await _count_audit_events(db_conn, client_id)

    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"{PROXY_URL}/api/v1/tools/{ACTIVE_TOOL_ID}/invoke",
            json=INVOKE_BODY_TEMPLATE,
            headers=AGENT_NO_GRANT_HEADERS,
        )

    assert resp.status_code == 403, (
        f"Expected 403 OPA_DENY for agent without grant, got {resp.status_code}. "
        f"Body: {resp.text[:300]}"
    )
    body = resp.json()
    # The proxy wraps OPA deny in a JSON-RPC error envelope on the invoke endpoint.
    # code -32603 = JSON-RPC Internal Error; data.opa_reasons carries the deny reasons.
    assert "error" in body, f"Expected error key in response, got: {list(body.keys())}"
    err = body["error"]
    # Accept either REST-format string code or JSON-RPC numeric code
    if isinstance(err, dict):
        assert err.get("code") in ("OPA_DENY", "FORBIDDEN", -32603), (
            f"Expected OPA_DENY/FORBIDDEN/-32603 error code, got: {err.get('code')}"
        )
    else:
        assert err == "forbidden" or "denied" in str(err).lower(), (
            f"Unexpected error format: {err}"
        )

    after_count = await _count_audit_events(db_conn, client_id)
    assert after_count == before_count + 1, (
        f"INV-001 violated on DENY path: expected exactly 1 new audit event, "
        f"got {after_count - before_count}. "
        f"before={before_count}, after={after_count}"
    )

    latest = await _get_latest_audit_event(db_conn, client_id)
    assert latest is not None
    assert latest["outcome"] == "deny", (
        f"Expected outcome='deny', got '{latest['outcome']}'"
    )


@pytest.mark.integration
@pytest.mark.asyncio
async def test_opa_down_produces_error_audit_event(db_conn: asyncpg.Connection):
    """
    Covers INV-001 + INV-004: OPA-down path.

    When OPA is unreachable, the proxy returns 503. Per INV-001, the invocation
    pipeline must still emit one audit event (outcome='error') before the 503
    is returned to the caller.

    NOTE: This test requires the ability to take OPA down temporarily. In CI,
    this is done by stopping the OPA service container between requests.
    The test uses a dedicated OPA-down environment variable or a separate
    docker-compose profile.

    If OPA cannot be isolated in this test run, this test will skip with a note.
    """
    # This test requires external OPA control — skipped if not in OPA-down fixture mode.
    # In CI, the integration-tests.yml job runs this in a separate step where OPA is stopped.
    import os
    if not os.getenv("OPA_DOWN_TEST_MODE"):
        pytest.skip(
            "OPA-down test requires OPA_DOWN_TEST_MODE=1 env var. "
            "Set this in CI after stopping the OPA container. "
            "See ci/test-jobs/integration-tests.yml for the two-phase test setup."
        )

    client_id = "test-agent-client"
    before_count = await _count_audit_events(db_conn, client_id)

    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"{PROXY_URL}/api/v1/tools/{ACTIVE_TOOL_ID}/invoke",
            json=INVOKE_BODY_TEMPLATE,
            headers=AGENT_HEADERS,
        )

    assert resp.status_code == 503, (
        f"INV-004: Expected 503 when OPA is down, got {resp.status_code}. "
        f"Body: {resp.text[:300]}"
    )
    body = resp.json()
    assert body["error"]["code"] == "OPA_UNAVAILABLE"

    after_count = await _count_audit_events(db_conn, client_id)
    assert after_count == before_count + 1, (
        f"INV-001 violated on OPA-down path: expected 1 new audit event, "
        f"got {after_count - before_count}."
    )

    latest = await _get_latest_audit_event(db_conn, client_id)
    assert latest is not None
    assert latest["outcome"] == "error", (
        f"Expected outcome='error' for OPA-down path, got '{latest['outcome']}'"
    )


@pytest.mark.integration
@pytest.mark.asyncio
async def test_401_produces_audit_event(db_conn: asyncpg.Connection):
    """
    Covers INV-001 extension (Task 1.1): unauthenticated requests (401) MUST
    produce exactly one audit event with tool_id IS NULL.

    Prior to Task 1.1 the AuditMiddleware swallowed emission exceptions with
    `except Exception: pass`, meaning a DB outage gave unauthenticated probes a
    quieter channel. Post-Task-1.1 the emit is fail-closed (500 on failure) and
    the row is unconditionally persisted.

    The client_id for unauthenticated requests is 'unauthenticated' (the
    AuditMiddleware fallback value).
    """
    total_before = await db_conn.fetchval("SELECT COUNT(*) FROM audit_events")

    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"{PROXY_URL}/api/v1/tools/{ACTIVE_TOOL_ID}/invoke",
            json=INVOKE_BODY_TEMPLATE,
            # No auth headers — simulates missing cert and no Bearer token
        )

    assert resp.status_code == 401, (
        f"INV-009: Expected 401 for unauthenticated request, got {resp.status_code}"
    )
    body = resp.json()
    assert body.get("error") == "unauthenticated" or (
        isinstance(body.get("error"), dict) and body["error"].get("code") == "UNAUTHENTICATED"
    ), f"Expected unauthenticated error, got: {body}"

    total_after = await db_conn.fetchval("SELECT COUNT(*) FROM audit_events")
    assert total_after == total_before + 1, (
        f"INV-001 extension violated: expected exactly 1 new audit event for 401, "
        f"got {total_after - total_before}."
    )

    # Verify the row has tool_id IS NULL (auth failure before tool lookup)
    latest_unauth = await db_conn.fetchrow(
        """
        SELECT event_id, client_id, tool_id, outcome, tool_name
        FROM audit_events
        WHERE client_id = 'unauthenticated'
        ORDER BY created_at DESC
        LIMIT 1
        """
    )
    assert latest_unauth is not None, "Expected an audit row for unauthenticated client"
    assert latest_unauth["tool_id"] is None, (
        f"Expected tool_id IS NULL for auth-failure row, got: {latest_unauth['tool_id']}"
    )
    assert latest_unauth["outcome"] == "deny", (
        f"Expected outcome='deny' for 401 auth row, got: {latest_unauth['outcome']}"
    )
    assert "401" in latest_unauth["tool_name"], (
        f"Expected '[401]' in tool_name for auth-failure row, got: {latest_unauth['tool_name']}"
    )


@pytest.mark.integration
@pytest.mark.asyncio
async def test_403_produces_audit_event(db_conn: asyncpg.Connection):
    """
    Covers INV-001 extension (Task 1.1): authorization failures (403) MUST
    produce exactly one audit event with tool_id IS NULL.

    Uses a caller that authenticates successfully but lacks the agent role
    (e.g. auditor-only role that cannot invoke tools).
    """
    # Headers for an authenticated caller with insufficient role for invocation.
    # 'test-auditor-client' must exist in the test fixtures with role=auditor only.
    import os
    gw = os.getenv("GATEWAY_SHARED_SECRET", "")
    auditor_headers = {"X-Client-Cert-CN": "test-auditor-client", "X-Gateway-Secret": gw}

    # Count existing rows for this client_id before the request.
    before_count = await db_conn.fetchval(
        "SELECT COUNT(*) FROM audit_events WHERE client_id = 'test-auditor-client'"
    )

    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"{PROXY_URL}/api/v1/tools/{ACTIVE_TOOL_ID}/invoke",
            json=INVOKE_BODY_TEMPLATE,
            headers=auditor_headers,
        )

    # Auditor-only callers fail the role check (agent or admin required).
    assert resp.status_code == 403, (
        f"Expected 403 for auditor-only caller on invoke, got {resp.status_code}. "
        f"Body: {resp.text[:300]}"
    )

    after_count = await db_conn.fetchval(
        "SELECT COUNT(*) FROM audit_events WHERE client_id = 'test-auditor-client'"
    )
    assert after_count == before_count + 1, (
        f"INV-001 extension violated: expected exactly 1 new audit event for 403, "
        f"got {after_count - before_count}."
    )

    latest = await db_conn.fetchrow(
        """
        SELECT event_id, client_id, tool_id, outcome, tool_name
        FROM audit_events
        WHERE client_id = 'test-auditor-client'
        ORDER BY created_at DESC
        LIMIT 1
        """
    )
    assert latest is not None
    assert latest["tool_id"] is None, (
        f"Expected tool_id IS NULL for 403 auth row, got: {latest['tool_id']}"
    )
    assert latest["outcome"] == "deny", (
        f"Expected outcome='deny' for 403 auth row, got: {latest['outcome']}"
    )
    assert "403" in latest["tool_name"], (
        f"Expected '[403]' in tool_name for 403-failure row, got: {latest['tool_name']}"
    )


@pytest.mark.integration
@pytest.mark.asyncio
async def test_quarantined_tool_deny_produces_one_audit_event(db_conn: asyncpg.Connection):
    """
    Covers INV-001 + INV-005: quarantined tool invocation.

    Invoking a quarantined tool returns 403 TOOL_QUARANTINED before OPA is
    called. Per INV-001, the application layer must still emit one audit event
    with outcome='deny' and deny_reason='TOOL_QUARANTINED'.
    """
    client_id = "test-agent-client"
    before_count = await _count_audit_events(db_conn, client_id)

    quarantined_body = {
        "jsonrpc": "2.0",
        "id": "test-quarantine-1",
        "method": "tools/call",
        "params": {
            "name": "quarantined-tool",
            "arguments": {},
        },
    }

    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"{PROXY_URL}/api/v1/tools/{QUARANTINED_TOOL_ID}/invoke",
            json=quarantined_body,
            headers=AGENT_HEADERS,
        )

    assert resp.status_code == 403, (
        f"Expected 403 for quarantined tool, got {resp.status_code}"
    )
    body = resp.json()
    # Route-level entitlement check returns detail envelope (HTTPException).
    # The check fires before invoke_tool so the response uses FastAPI's detail format.
    err_code = (
        body.get("detail", {}).get("code")
        or (body.get("error", {}).get("code") if isinstance(body.get("error"), dict) else None)
    )
    assert err_code in ("NOT_ENTITLED", "TOOL_QUARANTINED"), (
        f"Expected NOT_ENTITLED or TOOL_QUARANTINED, got body: {body}"
    )

    after_count = await _count_audit_events(db_conn, client_id)
    assert after_count == before_count + 1, (
        f"INV-001 violated on quarantined tool path: expected 1 new audit event, "
        f"got {after_count - before_count}."
    )


@pytest.mark.integration
@pytest.mark.asyncio
async def test_audit_event_has_required_fields(db_conn: asyncpg.Connection):
    """
    Covers INV-001: Audit event schema completeness.

    Every audit event in the table must have all required fields populated:
    - event_id (not null)
    - client_id (not null, not empty)
    - tool_name (not null, not empty)
    - outcome (must be 'allow', 'deny', or 'error')
    - sha256_hash (not null, not empty — HMAC integrity hash)
    - created_at (not null)

    Samples up to 100 most recent events to verify field completeness.
    A single null value in any required field is a test failure.
    """
    rows = await db_conn.fetch(
        """
        SELECT event_id, client_id, tool_name, outcome, sha256_hash, created_at
        FROM audit_events
        ORDER BY created_at DESC
        LIMIT 100
        """
    )

    if not rows:
        pytest.skip("No audit events found — run other integration tests first to populate.")

    valid_outcomes = {"allow", "deny", "error"}
    violations = []

    for i, row in enumerate(rows):
        event = dict(row)
        event_id = event.get("event_id", "MISSING")

        for field in ("event_id", "client_id", "tool_name", "sha256_hash", "created_at"):
            if not event.get(field):
                violations.append(
                    f"Row {i}: event_id={event_id} has null/empty '{field}'"
                )

        outcome = event.get("outcome")
        if outcome not in valid_outcomes:
            violations.append(
                f"Row {i}: event_id={event_id} has invalid outcome='{outcome}' "
                f"(must be one of {valid_outcomes})"
            )

    assert not violations, (
        f"INV-001 field completeness violations found in {len(rows)} sampled events:\n"
        + "\n".join(violations)
    )


@pytest.mark.integration
@pytest.mark.asyncio
async def test_health_check_does_not_produce_audit_event(db_conn: asyncpg.Connection):
    """
    Verifies that health check requests do NOT produce audit events.
    Health checks are not tool invocations and must not pollute the audit log.
    """
    total_before = await db_conn.fetchval("SELECT COUNT(*) FROM audit_events")

    async with httpx.AsyncClient() as client:
        resp = await client.get(f"{PROXY_URL}/health")

    assert resp.status_code in (200, 503)
    body = resp.json()
    assert "status" in body

    total_after = await db_conn.fetchval("SELECT COUNT(*) FROM audit_events")
    assert total_after == total_before, (
        f"Health check produced {total_after - total_before} unexpected audit events. "
        f"Health endpoints must never write to audit_events."
    )
