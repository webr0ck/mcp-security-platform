"""
Unit Tests — Task 1.1: Auth-failure (401/403) audit events fail-closed

Verifies:
1. AuditMiddleware emits an audit event for 401 responses.
2. AuditMiddleware emits an audit event for 403 responses.
3. AuditMiddleware raises (propagates to 500) when emission fails — NOT swallows.
4. Non-auth responses (200, 404, 500) do NOT trigger 401/403 audit path.
5. Attacker-controlled path tokens are redacted before recording (INV-002).
6. _SKIP_AUDIT_DB_WRITE flag prevents DB writes in unit tests (replaces type-guard).

INV-001 extension: auth-layer rejections are fail-closed.
"""
from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------

def _make_request(
    path: str = "/api/v1/tools/00000000-0000-0000-0000-000000000010/invoke",
    method: str = "POST",
    client_id: str = "unauthenticated",
) -> MagicMock:
    req = MagicMock()
    req.method = method
    req.url.path = path
    req.state.request_id = "req-test-001"
    req.state.client_id = client_id
    req.client = MagicMock()
    req.client.host = "10.0.0.1"
    # session_jti: absent for unauthenticated
    del req.state.session_jti  # simulate AttributeError → getattr returns None
    return req


def _make_response(status_code: int) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status_code
    resp.headers = {}
    return resp


# ---------------------------------------------------------------------------
# Test: 401 and 403 trigger audit emit
# ---------------------------------------------------------------------------

@pytest.mark.unit
@pytest.mark.asyncio
async def test_audit_middleware_emits_on_401():
    """AuditMiddleware must call _emit_audit_event for a 401 response."""
    from app.middleware.audit import AuditMiddleware
    import app.services.invocation as inv_mod

    app_mock = MagicMock()
    middleware = AuditMiddleware(app_mock)

    emit_calls: list[dict] = []

    async def fake_emit(**kwargs: Any) -> str:
        emit_calls.append(kwargs)
        return "fake-event-id"

    request = _make_request()
    response = _make_response(401)

    async def call_next(_req: Any) -> Any:
        return response

    with patch.object(inv_mod, "_emit_audit_event", new=fake_emit):
        result = await middleware.dispatch(request, call_next)

    assert result.status_code == 401
    assert len(emit_calls) == 1
    call = emit_calls[0]
    assert call["tool_id"] is None
    assert call["outcome"] == "deny"
    assert "HTTP_401" in call["deny_reasons"]


@pytest.mark.unit
@pytest.mark.asyncio
async def test_audit_middleware_emits_on_403():
    """AuditMiddleware must call _emit_audit_event for a 403 response."""
    from app.middleware.audit import AuditMiddleware
    import app.services.invocation as inv_mod

    app_mock = MagicMock()
    middleware = AuditMiddleware(app_mock)

    emit_calls: list[dict] = []

    async def fake_emit(**kwargs: Any) -> str:
        emit_calls.append(kwargs)
        return "fake-event-id"

    request = _make_request(client_id="test-auditor-client")
    response = _make_response(403)

    async def call_next(_req: Any) -> Any:
        return response

    with patch.object(inv_mod, "_emit_audit_event", new=fake_emit):
        result = await middleware.dispatch(request, call_next)

    assert result.status_code == 403
    assert len(emit_calls) == 1
    call = emit_calls[0]
    assert call["tool_id"] is None
    assert call["outcome"] == "deny"
    assert "HTTP_403" in call["deny_reasons"]


@pytest.mark.unit
@pytest.mark.asyncio
async def test_audit_middleware_does_not_emit_on_200():
    """AuditMiddleware must NOT call _emit_audit_event for a 200 response."""
    from app.middleware.audit import AuditMiddleware
    import app.services.invocation as inv_mod

    app_mock = MagicMock()
    middleware = AuditMiddleware(app_mock)

    emit_calls: list[dict] = []

    async def fake_emit(**kwargs: Any) -> str:
        emit_calls.append(kwargs)
        return "fake-event-id"

    request = _make_request()
    response = _make_response(200)
    response.headers = {}

    async def call_next(_req: Any) -> Any:
        return response

    with patch.object(inv_mod, "_emit_audit_event", new=fake_emit):
        await middleware.dispatch(request, call_next)

    assert len(emit_calls) == 0, "Must not emit for non-401/403 responses"


# ---------------------------------------------------------------------------
# Test: fail-closed — emission failure → 500 (not swallowed)
# ---------------------------------------------------------------------------

@pytest.mark.unit
@pytest.mark.asyncio
async def test_audit_middleware_401_fail_closed_on_emit_error():
    """
    When _emit_audit_event raises AuditEmissionError for a 401 response,
    AuditMiddleware must surface a 500 (NOT return the 401 silently).

    This is the core Task 1.1 invariant: no quiet brute-force channel.
    """
    from app.middleware.audit import AuditMiddleware
    from app.services.invocation import AuditEmissionError
    import app.services.invocation as inv_mod

    app_mock = MagicMock()
    middleware = AuditMiddleware(app_mock)

    async def failing_emit(**kwargs: Any) -> str:
        raise AuditEmissionError("DB connection refused")

    request = _make_request()
    response = _make_response(401)

    async def call_next(_req: Any) -> Any:
        return response

    with patch.object(inv_mod, "_emit_audit_event", new=failing_emit):
        result = await middleware.dispatch(request, call_next)

    # Must return 500, not 401 — the "never block response" comment is deleted.
    assert result.status_code == 500
    import json as _json
    body = _json.loads(result.body)
    assert body["error"]["code"] == "AUDIT_EMISSION_FAILED"


@pytest.mark.unit
@pytest.mark.asyncio
async def test_audit_middleware_403_fail_closed_on_emit_error():
    """Same fail-closed behaviour for 403 responses."""
    from app.middleware.audit import AuditMiddleware
    from app.services.invocation import AuditEmissionError
    import app.services.invocation as inv_mod

    app_mock = MagicMock()
    middleware = AuditMiddleware(app_mock)

    async def failing_emit(**kwargs: Any) -> str:
        raise AuditEmissionError("DB timeout")

    request = _make_request(client_id="test-auditor-client")
    response = _make_response(403)

    async def call_next(_req: Any) -> Any:
        return response

    with patch.object(inv_mod, "_emit_audit_event", new=failing_emit):
        result = await middleware.dispatch(request, call_next)

    assert result.status_code == 500


# ---------------------------------------------------------------------------
# Test: attacker-controlled path tokens are redacted (INV-002)
# ---------------------------------------------------------------------------

@pytest.mark.unit
@pytest.mark.asyncio
async def test_audit_middleware_redacts_jwt_in_path():
    """
    If the attacker encodes a JWT in the URL path, the recorded tool_name
    must have the JWT replaced with [REDACTED:jwt_token] before storage.

    Residual from plan: "recorded method/path strings are attacker-chosen and
    must pass redaction tests."
    """
    from app.middleware.audit import AuditMiddleware
    import app.services.invocation as inv_mod

    app_mock = MagicMock()
    middleware = AuditMiddleware(app_mock)

    emit_calls: list[dict] = []

    async def fake_emit(**kwargs: Any) -> str:
        emit_calls.append(kwargs)
        return "fake-event-id"

    # JWT-shaped path segment (three base64url parts with dots)
    jwt_path = "/api/v1/tools/eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.abc/invoke"
    request = _make_request(path=jwt_path)
    response = _make_response(401)

    async def call_next(_req: Any) -> Any:
        return response

    with patch.object(inv_mod, "_emit_audit_event", new=fake_emit):
        await middleware.dispatch(request, call_next)

    assert len(emit_calls) == 1
    recorded_tool_name = emit_calls[0]["tool_name"]
    assert "eyJhbGciOiJIUzI1NiJ9" not in recorded_tool_name, (
        f"JWT segment must be redacted in tool_name, got: {recorded_tool_name}"
    )
    assert "[REDACTED" in recorded_tool_name, (
        f"Expected [REDACTED] marker in tool_name, got: {recorded_tool_name}"
    )


# ---------------------------------------------------------------------------
# Test: _SKIP_AUDIT_DB_WRITE flag (replaces type-guard)
# ---------------------------------------------------------------------------

@pytest.mark.unit
@pytest.mark.asyncio
async def test_skip_audit_db_write_flag_prevents_db_insert():
    """
    When _SKIP_AUDIT_DB_WRITE = True, _emit_audit_event must return without
    attempting any DB INSERT, even for a legitimate UUID event_id / str hash.

    This is the explicit test-fixture contract that replaces the fragile
    type-guard (non-UUID event_id / non-string sha256_hash) that previously
    gated the INSERT as an emergent side-effect of mock return values.
    """
    import app.services.invocation as inv_mod

    # Save original flag value
    original = inv_mod._SKIP_AUDIT_DB_WRITE
    inv_mod._SKIP_AUDIT_DB_WRITE = True

    db_calls: list = []

    try:
        # Patch the database engine to detect if any INSERT is attempted
        engine_mock = MagicMock()
        conn_mock = AsyncMock()
        conn_mock.execute = AsyncMock(side_effect=lambda *a, **kw: db_calls.append(a))
        engine_mock.begin = MagicMock(return_value=AsyncMock(
            __aenter__=AsyncMock(return_value=conn_mock),
            __aexit__=AsyncMock(return_value=None),
        ))

        # Patch mcp_audit_logger to return a realistic event
        mock_event = MagicMock()
        mock_event.event_id = __import__("uuid").UUID("12345678-1234-5678-1234-567812345678")
        mock_event.event_type = MagicMock()
        mock_event.event_type.value = "TOOL_INVOCATION"
        mock_event.timestamp = MagicMock()
        mock_event.timestamp.isoformat.return_value = "2026-06-11T00:00:00+00:00"
        mock_event.platform_version = "1.0.0"
        mock_event.outcome = MagicMock()
        mock_event.outcome.value = "deny"

        mock_logger = MagicMock()
        mock_logger.emit.return_value = "a" * 64  # valid 64-char hex sha256_hash

        with patch.object(inv_mod, "_get_audit_logger", return_value=mock_logger):
            # Patch AuditEvent constructor
            with patch("mcp_audit_logger.AuditEvent", return_value=mock_event):
                with patch("app.core.database.engine", engine_mock):
                    result = await inv_mod._emit_audit_event(
                        tool_id="12345678-1234-5678-1234-567812345678",
                        tool_name="test-tool",
                        tool_version=None,
                        client_id="test-client",
                        outcome="deny",
                        deny_reasons=["test"],
                        request_id="req-001",
                        latency_ms=0,
                        anomaly_score=0.0,
                        opa_decision_id="dec_abc123",
                        is_testing=False,
                    )
    finally:
        inv_mod._SKIP_AUDIT_DB_WRITE = original

    # The function must return an event_id without hitting the DB
    assert result is not None
    assert len(db_calls) == 0, (
        f"_SKIP_AUDIT_DB_WRITE=True must prevent DB calls; got {len(db_calls)} calls"
    )
