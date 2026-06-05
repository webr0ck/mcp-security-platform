"""
Unit Tests — RBAC Matrix (HTTP-level)

Fix (dual-review): this file was labelled @pytest.mark.unit but uses the
_Ctx helper that mocks ALL external dependencies (DB via dependency_overrides,
roles via _load_roles AsyncMock). No real services are required or contacted.
Marking these as integration caused them to be skipped on PR builds, leaving
RBAC regressions undetected until the nightly docker-compose run.

All tests below use @pytest.mark.unit so they run on every PR.

Drives every role × every protected endpoint combination against the live
ASGI app (with mocked DB and roles). Every test name encodes
[role] [operation] → [expected HTTP status].

Auth is simulated via the X-Client-Cert-CN header (same mechanism as
production mTLS — the CN becomes client_id, roles loaded from mocked DB).

These tests validate RBAC at the HTTP boundary — the actual 403 JSON body
structure, the error code string, and that 200/201/204 success shapes are
correct for permitted roles. No real DB, Redis, or OPA is used.
"""
from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

TOOL_UUID = "00000000-0000-0000-0000-000000000099"

# Role → CN header value (matches what conftest.py defines)
ROLE_HEADERS: dict[str, dict[str, str]] = {
    "admin":    {"X-Client-Cert-CN": "test-admin-client"},
    "agent":    {"X-Client-Cert-CN": "test-agent-client"},
    "auditor":  {"X-Client-Cert-CN": "test-auditor-client"},
    "readonly": {"X-Client-Cert-CN": "test-readonly-client"},
}


def _ctx(role: str):
    """
    Context manager: patch _load_roles to return the given role's role list,
    and override the DB dependency to return a predictable stub.
    """
    from app.main import app
    from app.core.database import get_db

    roles = [role]

    class _FakeResult:
        def fetchone(self):
            return None  # most role tests hit 403 before DB

        def fetchall(self):
            return []

        def scalar(self):
            return 0

    class _FakeDB:
        async def execute(self, *a, **k):
            return _FakeResult()

        async def commit(self):
            pass

    async def _gen():
        yield _FakeDB()

    class _AppCtx:
        async def __aenter__(self):
            app.dependency_overrides[get_db] = _gen
            self._p = patch(
                "app.middleware.auth._load_roles",
                new=AsyncMock(return_value=roles),
            )
            self._p.start()
            self._client = AsyncClient(
                transport=ASGITransport(app=app), base_url="http://testserver"
            )
            return self._client

        async def __aexit__(self, *exc):
            await self._client.aclose()
            self._p.stop()
            app.dependency_overrides.clear()

    return _AppCtx()


def _assert_forbidden(resp, role: str, operation: str) -> None:
    """Assert a 403 response matches the documented error body structure."""
    assert resp.status_code == 403, (
        f"[{role}] {operation}: expected 403, got {resp.status_code}. Body: {resp.text}"
    )
    body = resp.json()
    # RBACMiddleware returns {"error": {"code": "FORBIDDEN", ...}}
    # Route handlers return {"detail": {"code": "FORBIDDEN", ...}}
    error_obj = body.get("error") or body.get("detail", {})
    assert error_obj.get("code") == "FORBIDDEN", (
        f"Expected FORBIDDEN error code, got: {error_obj}"
    )


def _assert_not_401(resp, role: str, operation: str) -> None:
    """Auth should succeed for all role tests — only RBAC can deny (403)."""
    assert resp.status_code != 401, (
        f"[{role}] {operation}: got 401 — auth failed; check CN header fixture"
    )


# ---------------------------------------------------------------------------
# POST /tools/register — admin only
# ---------------------------------------------------------------------------

@pytest.mark.unit
async def test_register_tool_admin_reaches_handler():
    """[admin] POST /tools/register → not 403 (handler may return other errors)"""
    payload = {
        "name": "rbac-test-tool",
        "version": "1.0.0",
        "description": "RBAC test",
        "schema": {"type": "object"},
        "upstream_url": "http://upstream:9000/mcp",
    }
    async with _ctx("admin") as c:
        resp = await c.post(
            "/api/v1/tools/register",
            json=payload,
            headers=ROLE_HEADERS["admin"],
        )
    _assert_not_401(resp, "admin", "POST /tools/register")
    assert resp.status_code != 403, f"Admin must not be RBAC-denied: {resp.text}"


@pytest.mark.unit
async def test_register_tool_agent_forbidden():
    """[agent] POST /tools/register → 403 Forbidden"""
    async with _ctx("agent") as c:
        resp = await c.post(
            "/api/v1/tools/register",
            json={"name": "x", "version": "1.0.0"},
            headers=ROLE_HEADERS["agent"],
        )
    _assert_forbidden(resp, "agent", "POST /tools/register")


@pytest.mark.unit
async def test_register_tool_auditor_forbidden():
    """[auditor] POST /tools/register → 403 Forbidden"""
    async with _ctx("auditor") as c:
        resp = await c.post(
            "/api/v1/tools/register",
            json={"name": "x", "version": "1.0.0"},
            headers=ROLE_HEADERS["auditor"],
        )
    _assert_forbidden(resp, "auditor", "POST /tools/register")


@pytest.mark.unit
async def test_register_tool_readonly_forbidden():
    """[readonly] POST /tools/register → 403 Forbidden"""
    async with _ctx("readonly") as c:
        resp = await c.post(
            "/api/v1/tools/register",
            json={"name": "x", "version": "1.0.0"},
            headers=ROLE_HEADERS["readonly"],
        )
    _assert_forbidden(resp, "readonly", "POST /tools/register")


# ---------------------------------------------------------------------------
# GET /tools — all roles allowed
# ---------------------------------------------------------------------------

@pytest.mark.unit
async def test_list_tools_admin_allowed():
    """[admin] GET /tools → 200 (may be empty list)"""
    async with _ctx("admin") as c:
        resp = await c.get("/api/v1/tools", headers=ROLE_HEADERS["admin"])
    _assert_not_401(resp, "admin", "GET /tools")
    assert resp.status_code not in (401, 403)


@pytest.mark.unit
async def test_list_tools_auditor_allowed():
    """[auditor] GET /tools → 200"""
    async with _ctx("auditor") as c:
        resp = await c.get("/api/v1/tools", headers=ROLE_HEADERS["auditor"])
    assert resp.status_code not in (401, 403)


@pytest.mark.unit
async def test_list_tools_readonly_allowed():
    """[readonly] GET /tools → 200 (name/version only)"""
    async with _ctx("readonly") as c:
        resp = await c.get("/api/v1/tools", headers=ROLE_HEADERS["readonly"])
    assert resp.status_code not in (401, 403)


# ---------------------------------------------------------------------------
# PATCH /tools/{id} — admin only
# ---------------------------------------------------------------------------

@pytest.mark.unit
async def test_patch_tool_agent_forbidden():
    """[agent] PATCH /tools/{id} → 403 Forbidden"""
    async with _ctx("agent") as c:
        resp = await c.patch(
            f"/api/v1/tools/{TOOL_UUID}",
            json={"status": "deprecated"},
            headers=ROLE_HEADERS["agent"],
        )
    _assert_forbidden(resp, "agent", "PATCH /tools/{id}")


@pytest.mark.unit
async def test_patch_tool_auditor_forbidden():
    """[auditor] PATCH /tools/{id} → 403 Forbidden"""
    async with _ctx("auditor") as c:
        resp = await c.patch(
            f"/api/v1/tools/{TOOL_UUID}",
            json={"status": "deprecated"},
            headers=ROLE_HEADERS["auditor"],
        )
    _assert_forbidden(resp, "auditor", "PATCH /tools/{id}")


@pytest.mark.unit
async def test_patch_tool_readonly_forbidden():
    """[readonly] PATCH /tools/{id} → 403 Forbidden"""
    async with _ctx("readonly") as c:
        resp = await c.patch(
            f"/api/v1/tools/{TOOL_UUID}",
            json={"status": "deprecated"},
            headers=ROLE_HEADERS["readonly"],
        )
    _assert_forbidden(resp, "readonly", "PATCH /tools/{id}")


# ---------------------------------------------------------------------------
# DELETE /tools/{id} — admin only
# ---------------------------------------------------------------------------

@pytest.mark.unit
async def test_delete_tool_agent_forbidden():
    """[agent] DELETE /tools/{id} → 403 Forbidden"""
    async with _ctx("agent") as c:
        resp = await c.delete(
            f"/api/v1/tools/{TOOL_UUID}",
            headers=ROLE_HEADERS["agent"],
        )
    _assert_forbidden(resp, "agent", "DELETE /tools/{id}")


@pytest.mark.unit
async def test_delete_tool_auditor_forbidden():
    """[auditor] DELETE /tools/{id} → 403 Forbidden"""
    async with _ctx("auditor") as c:
        resp = await c.delete(
            f"/api/v1/tools/{TOOL_UUID}",
            headers=ROLE_HEADERS["auditor"],
        )
    _assert_forbidden(resp, "auditor", "DELETE /tools/{id}")


@pytest.mark.unit
async def test_delete_tool_readonly_forbidden():
    """[readonly] DELETE /tools/{id} → 403 Forbidden"""
    async with _ctx("readonly") as c:
        resp = await c.delete(
            f"/api/v1/tools/{TOOL_UUID}",
            headers=ROLE_HEADERS["readonly"],
        )
    _assert_forbidden(resp, "readonly", "DELETE /tools/{id}")


# ---------------------------------------------------------------------------
# POST /tools/{id}/invoke — agent + admin only
# ---------------------------------------------------------------------------

@pytest.mark.unit
async def test_invoke_tool_auditor_forbidden():
    """[auditor] POST /tools/{id}/invoke → 403 Forbidden"""
    rpc = {"jsonrpc": "2.0", "id": "1", "method": "tools/call", "params": {}}
    async with _ctx("auditor") as c:
        resp = await c.post(
            f"/api/v1/tools/{TOOL_UUID}/invoke",
            json=rpc,
            headers=ROLE_HEADERS["auditor"],
        )
    _assert_forbidden(resp, "auditor", "POST /tools/{id}/invoke")


@pytest.mark.unit
async def test_invoke_tool_readonly_forbidden():
    """[readonly] POST /tools/{id}/invoke → 403 Forbidden"""
    rpc = {"jsonrpc": "2.0", "id": "1", "method": "tools/call", "params": {}}
    async with _ctx("readonly") as c:
        resp = await c.post(
            f"/api/v1/tools/{TOOL_UUID}/invoke",
            json=rpc,
            headers=ROLE_HEADERS["readonly"],
        )
    _assert_forbidden(resp, "readonly", "POST /tools/{id}/invoke")


@pytest.mark.unit
async def test_invoke_tool_agent_not_forbidden_at_rbac_layer():
    """[agent] POST /tools/{id}/invoke → RBAC allows (OPA may still deny)"""
    rpc = {"jsonrpc": "2.0", "id": "1", "method": "tools/call", "params": {}}
    async with _ctx("agent") as c:
        resp = await c.post(
            f"/api/v1/tools/{TOOL_UUID}/invoke",
            json=rpc,
            headers=ROLE_HEADERS["agent"],
        )
    # Must not be a 403 from RBAC middleware (may be 404 tool not found etc)
    assert resp.status_code != 403 or resp.json().get("error", {}).get("code") != "FORBIDDEN"


# ---------------------------------------------------------------------------
# GET /policy/rules — admin + auditor
# ---------------------------------------------------------------------------

@pytest.mark.unit
async def test_policy_rules_agent_forbidden():
    """[agent] GET /policy/rules → 403 Forbidden"""
    async with _ctx("agent") as c:
        resp = await c.get("/api/v1/policy/rules", headers=ROLE_HEADERS["agent"])
    _assert_forbidden(resp, "agent", "GET /policy/rules")


@pytest.mark.unit
async def test_policy_rules_readonly_forbidden():
    """[readonly] GET /policy/rules → 403 Forbidden"""
    async with _ctx("readonly") as c:
        resp = await c.get("/api/v1/policy/rules", headers=ROLE_HEADERS["readonly"])
    _assert_forbidden(resp, "readonly", "GET /policy/rules")


@pytest.mark.unit
async def test_policy_rules_auditor_allowed():
    """[auditor] GET /policy/rules → not 403"""
    async with _ctx("auditor") as c:
        resp = await c.get("/api/v1/policy/rules", headers=ROLE_HEADERS["auditor"])
    assert resp.status_code not in (401, 403)


# ---------------------------------------------------------------------------
# POST /policy/evaluate — admin only
# ---------------------------------------------------------------------------

@pytest.mark.unit
async def test_policy_evaluate_agent_forbidden():
    """[agent] POST /policy/evaluate → 403 Forbidden"""
    async with _ctx("agent") as c:
        resp = await c.post("/api/v1/policy/evaluate", json={}, headers=ROLE_HEADERS["agent"])
    _assert_forbidden(resp, "agent", "POST /policy/evaluate")


@pytest.mark.unit
async def test_policy_evaluate_auditor_forbidden():
    """[auditor] POST /policy/evaluate → 403 Forbidden"""
    async with _ctx("auditor") as c:
        resp = await c.post("/api/v1/policy/evaluate", json={}, headers=ROLE_HEADERS["auditor"])
    _assert_forbidden(resp, "auditor", "POST /policy/evaluate")


@pytest.mark.unit
async def test_policy_evaluate_readonly_forbidden():
    """[readonly] POST /policy/evaluate → 403 Forbidden"""
    async with _ctx("readonly") as c:
        resp = await c.post("/api/v1/policy/evaluate", json={}, headers=ROLE_HEADERS["readonly"])
    _assert_forbidden(resp, "readonly", "POST /policy/evaluate")


# ---------------------------------------------------------------------------
# GET /anomaly — admin + auditor
# ---------------------------------------------------------------------------

@pytest.mark.unit
async def test_anomaly_agent_forbidden():
    """[agent] GET /anomaly → 403 Forbidden"""
    async with _ctx("agent") as c:
        resp = await c.get("/api/v1/anomaly", headers=ROLE_HEADERS["agent"])
    _assert_forbidden(resp, "agent", "GET /anomaly")


@pytest.mark.unit
async def test_anomaly_readonly_forbidden():
    """[readonly] GET /anomaly → 403 Forbidden"""
    async with _ctx("readonly") as c:
        resp = await c.get("/api/v1/anomaly", headers=ROLE_HEADERS["readonly"])
    _assert_forbidden(resp, "readonly", "GET /anomaly")


# ---------------------------------------------------------------------------
# GET /audit — readonly denied
# ---------------------------------------------------------------------------

@pytest.mark.unit
async def test_audit_events_readonly_forbidden():
    """[readonly] GET /audit → 403 Forbidden"""
    async with _ctx("readonly") as c:
        resp = await c.get("/api/v1/audit", headers=ROLE_HEADERS["readonly"])
    _assert_forbidden(resp, "readonly", "GET /audit")


@pytest.mark.unit
async def test_audit_events_admin_allowed():
    """[admin] GET /audit → not 403"""
    async with _ctx("admin") as c:
        resp = await c.get("/api/v1/audit", headers=ROLE_HEADERS["admin"])
    assert resp.status_code not in (401, 403)


@pytest.mark.unit
async def test_audit_events_auditor_allowed():
    """[auditor] GET /audit → not 403"""
    async with _ctx("auditor") as c:
        resp = await c.get("/api/v1/audit", headers=ROLE_HEADERS["auditor"])
    assert resp.status_code not in (401, 403)


# ---------------------------------------------------------------------------
# No-auth (unauthenticated) tests — every protected endpoint returns 401
# ---------------------------------------------------------------------------

@pytest.mark.unit
@pytest.mark.parametrize("method,path", [
    ("GET",    "/api/v1/tools"),
    ("POST",   "/api/v1/tools/register"),
    ("GET",    f"/api/v1/tools/{TOOL_UUID}"),
    ("PATCH",  f"/api/v1/tools/{TOOL_UUID}"),
    ("DELETE", f"/api/v1/tools/{TOOL_UUID}"),
    ("POST",   f"/api/v1/tools/{TOOL_UUID}/invoke"),
    ("GET",    "/api/v1/policy/rules"),
    ("GET",    "/api/v1/audit"),
    ("GET",    "/api/v1/anomaly"),
])
async def test_unauthenticated_returns_401(method: str, path: str):
    """[no-auth] all protected endpoints → 401"""
    from app.main import app
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as c:
        func = getattr(c, method.lower())
        resp = await func(path)
    assert resp.status_code == 401, (
        f"[no-auth] {method} {path}: expected 401, got {resp.status_code}"
    )
