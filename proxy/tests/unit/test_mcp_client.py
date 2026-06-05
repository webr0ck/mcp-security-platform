"""
In-process MCP-client contract tests for POST /api/v1/tools/{id}/invoke.

Unlike tests/integration/test_invoke.py (needs docker compose + seeded
fixtures), these run in CI with no services: the ASGI app is driven directly
and the DB / roles / invocation pipeline are mocked at their seams. They lock
the client<->proxy JSON-RPC 2.0 contract and the security invariants the
route is responsible for mapping to HTTP:

  INV-009  unauthenticated            -> 401 UNAUTHENTICATED
  RBAC     authed but wrong role      -> 403 FORBIDDEN (at RBAC middleware)
  contract malformed JSON-RPC         -> 400 VALIDATION_ERROR
  contract unknown tool               -> 404 NOT_FOUND
  INV-005  quarantined tool           -> 403, OPA never called (real pipeline)
  policy   OPA deny                   -> 403 invocation denied by policy
  INV-004  OPA unreachable            -> 503 OPA_UNAVAILABLE (fail closed)
  happy    allowed                    -> 200 JSON-RPC result + meta.audit_id
  INV-001  audit emission failure     -> 500 INTERNAL_ERROR (invocation aborted)
"""
from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest
from httpx import AsyncClient, ASGITransport

TOOL_ID = "00000000-0000-0000-0000-000000000010"
AGENT_HEADERS = {"X-Client-Cert-CN": "test-agent-client"}
RPC = {
    "jsonrpc": "2.0",
    "id": "req-1",
    "method": "tools/call",
    "params": {"name": "active-low-risk-tool", "arguments": {"path": "/tmp/x"}},
}


def _tool_row(status: str = "active"):
    return SimpleNamespace(
        tool_id=TOOL_ID, name="active-low-risk-tool", version="1.0.0",
        status=status, risk_level="low", upstream_url="http://upstream:9",
        # Credential injection metadata (FIND-002 fix — must match SELECT columns)
        injection_mode="none", service_name=None,
        inject_header="Authorization", inject_prefix="Bearer",
        kc_client_id=None, kc_token_audience=None,
    )


def _override_db(row):
    """Yield a fake AsyncSession whose execute().fetchone() returns `row`."""
    class _Res:
        def fetchone(self):
            return row

    class _DB:
        async def execute(self, *a, **k):
            return _Res()

    async def _gen():
        yield _DB()

    return _gen


_MISSING = object()  # distinct from None (None == "tool not found")


class _Ctx:
    """App with get_db overridden and _load_roles patched."""

    def __init__(self, row=_MISSING, roles=("agent",)):
        self._row = _tool_row() if row is _MISSING else row
        self._roles = list(roles)

    async def __aenter__(self):
        from app.main import app
        from app.core.database import get_db

        self._app = app
        app.dependency_overrides[get_db] = _override_db(self._row)
        self._p = patch("app.middleware.auth._load_roles",
                         new=AsyncMock(return_value=self._roles))
        self._p.start()
        self._client = AsyncClient(
            transport=ASGITransport(app=app), base_url="http://testserver"
        )
        return self._client

    async def __aexit__(self, *exc):
        await self._client.aclose()
        self._p.stop()
        self._app.dependency_overrides.clear()


@pytest.mark.unit
async def test_unauthenticated_returns_401():
    async with _Ctx() as c:
        r = await c.post(f"/api/v1/tools/{TOOL_ID}/invoke", json=RPC)
    assert r.status_code == 401
    # RFC 6750 §3.1: auth middleware returns {"error": "unauthenticated", ...}
    assert r.json()["error"] == "unauthenticated"


@pytest.mark.unit
async def test_wrong_role_is_403_forbidden():
    async with _Ctx(roles=["auditor"]) as c:
        r = await c.post(f"/api/v1/tools/{TOOL_ID}/invoke",
                         json=RPC, headers=AGENT_HEADERS)
    # Defense in depth: the RBAC middleware denies before the route handler.
    assert r.status_code == 403
    assert r.json()["error"]["code"] == "FORBIDDEN"


@pytest.mark.unit
async def test_malformed_jsonrpc_is_400():
    bad = {"jsonrpc": "1.0", "method": "tools/call", "id": "x"}
    async with _Ctx() as c:
        r = await c.post(f"/api/v1/tools/{TOOL_ID}/invoke",
                         json=bad, headers=AGENT_HEADERS)
    assert r.status_code == 400
    assert r.json()["detail"]["code"] == "VALIDATION_ERROR"


@pytest.mark.unit
async def test_unknown_tool_is_404():
    async with _Ctx(row=None) as c:  # fetchone -> None
        r = await c.post(f"/api/v1/tools/{TOOL_ID}/invoke",
                         json=RPC, headers=AGENT_HEADERS)
    assert r.status_code == 404
    assert r.json()["detail"]["code"] == "NOT_FOUND"


@pytest.mark.unit
async def test_quarantined_blocked_before_opa_inv005():
    """Real invocation pipeline: quarantine must short-circuit before OPA."""
    opa = AsyncMock()
    with patch("app.services.policy.evaluate_policy", opa):
        async with _Ctx(row=_tool_row(status="quarantined")) as c:
            r = await c.post(f"/api/v1/tools/{TOOL_ID}/invoke",
                             json=RPC, headers=AGENT_HEADERS)
    assert r.status_code == 403
    body = r.json()
    # The route-level entitlement check (status != "active") fires before invoke_tool,
    # so the response uses the HTTP detail envelope, not the JSON-RPC error envelope.
    assert body["detail"]["code"] == "NOT_ENTITLED"
    opa.assert_not_awaited()  # INV-005: OPA never consulted


@pytest.mark.unit
async def test_opa_deny_is_403():
    from app.services.policy import OPADenyError

    inv = AsyncMock(side_effect=OPADenyError(["rule:no_write"]))
    with patch("app.services.invocation.invoke_tool", inv):
        async with _Ctx() as c:
            r = await c.post(f"/api/v1/tools/{TOOL_ID}/invoke",
                             json=RPC, headers=AGENT_HEADERS)
    assert r.status_code == 403
    assert "rule:no_write" in r.json()["error"]["data"]["opa_reasons"]


@pytest.mark.unit
async def test_opa_unavailable_is_503_inv004():
    from app.services.policy import OPAUnavailableError

    inv = AsyncMock(side_effect=OPAUnavailableError("connect refused"))
    with patch("app.services.invocation.invoke_tool", inv):
        async with _Ctx() as c:
            r = await c.post(f"/api/v1/tools/{TOOL_ID}/invoke",
                             json=RPC, headers=AGENT_HEADERS)
    assert r.status_code == 503
    assert r.json()["error"]["code"] == "OPA_UNAVAILABLE"


@pytest.mark.unit
async def test_happy_path_returns_jsonrpc_result_with_audit_id():
    ok = {
        "jsonrpc": "2.0",
        "id": "req-1",
        "result": {"content": [{"type": "text", "text": "done"}]},
        "meta": {"audit_id": "aud-123"},
    }
    inv = AsyncMock(return_value=ok)
    with patch("app.services.invocation.invoke_tool", inv):
        async with _Ctx() as c:
            r = await c.post(f"/api/v1/tools/{TOOL_ID}/invoke",
                             json=RPC, headers=AGENT_HEADERS)
    assert r.status_code == 200
    body = r.json()
    assert body["jsonrpc"] == "2.0"
    assert body["result"]["content"][0]["text"] == "done"
    assert body["meta"]["audit_id"] == "aud-123"  # INV-001 audit linkage


@pytest.mark.unit
async def test_audit_emission_failure_aborts_with_500_inv001():
    inv = AsyncMock(side_effect=RuntimeError("audit event emission failed: db down"))
    with patch("app.services.invocation.invoke_tool", inv):
        async with _Ctx() as c:
            r = await c.post(f"/api/v1/tools/{TOOL_ID}/invoke",
                             json=RPC, headers=AGENT_HEADERS)
    assert r.status_code == 500
    assert r.json()["error"]["code"] == "INTERNAL_ERROR"
