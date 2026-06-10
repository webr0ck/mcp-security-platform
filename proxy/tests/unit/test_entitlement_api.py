"""
Unit tests — Entitlement CRUD API (Phase 2.2)

Tests cover:
  - _require_server_owner: platform_admin bypass, owner/manager pass, others 403/404
  - _emit_entitlement_audit: success and failure paths
  - EntitlementGrantBody: validation (principal_type enum, empty principal_id)
  - RBAC matrix: which roles are allowed at each route (middleware level)
  - INV-001: audit emit is called before the response for every mutation

All DB interactions are mocked — no real connection required.
"""
from __future__ import annotations

import datetime
import pytest
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------

def _make_request(
    roles: list[str] | None = None,
    client_id: str = "caller-001",
    request_id: str = "req-001",
) -> MagicMock:
    req = MagicMock()
    req.state = SimpleNamespace(
        client_roles=roles if roles is not None else [],
        client_id=client_id,
        request_id=request_id,
    )
    return req


SERVER_ID = "aaaaaaaa-0000-0000-0000-000000000001"
ENT_ID = "bbbbbbbb-0000-0000-0000-000000000002"
PRINCIPAL_ID = "agent-007"


# ---------------------------------------------------------------------------
# EntitlementGrantBody validation
# ---------------------------------------------------------------------------

class TestEntitlementGrantBody:
    @pytest.mark.unit
    def test_valid_human(self):
        from app.routers.entitlements import EntitlementGrantBody
        body = EntitlementGrantBody(principal_id="user-1", principal_type="human")
        assert body.principal_type == "human"

    @pytest.mark.unit
    def test_valid_agent(self):
        from app.routers.entitlements import EntitlementGrantBody
        body = EntitlementGrantBody(principal_id="agent-1", principal_type="agent")
        assert body.principal_type == "agent"

    @pytest.mark.unit
    def test_valid_kc_group(self):
        from app.routers.entitlements import EntitlementGrantBody
        body = EntitlementGrantBody(principal_id="group-1", principal_type="kc_group")
        assert body.principal_type == "kc_group"

    @pytest.mark.unit
    def test_invalid_principal_type_rejected(self):
        from pydantic import ValidationError
        from app.routers.entitlements import EntitlementGrantBody
        with pytest.raises(ValidationError):
            EntitlementGrantBody(principal_id="x", principal_type="robot")

    @pytest.mark.unit
    def test_empty_principal_id_rejected(self):
        from pydantic import ValidationError
        from app.routers.entitlements import EntitlementGrantBody
        with pytest.raises(ValidationError):
            EntitlementGrantBody(principal_id="   ", principal_type="human")

    @pytest.mark.unit
    def test_principal_id_stripped(self):
        from app.routers.entitlements import EntitlementGrantBody
        body = EntitlementGrantBody(principal_id="  trimmed  ", principal_type="agent")
        assert body.principal_id == "trimmed"


# ---------------------------------------------------------------------------
# _require_server_owner
# ---------------------------------------------------------------------------

class TestRequireServerOwner:
    """
    Tests the ownership guard without real DB.
    """

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_platform_admin_bypasses_db_check(self):
        """platform_admin never queries DB — short-circuits immediately."""
        from app.routers.entitlements import _require_server_owner
        req = _make_request(roles=["platform_admin"])
        # No mock needed — should return without DB interaction
        with patch("app.routers.entitlements.AsyncSessionLocal") as mock_session_cls:
            await _require_server_owner(SERVER_ID, req)
            mock_session_cls.assert_not_called()

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_legacy_admin_bypasses_db_check(self):
        """Legacy 'admin' role also bypasses the ownership check."""
        from app.routers.entitlements import _require_server_owner
        req = _make_request(roles=["admin"])
        with patch("app.routers.entitlements.AsyncSessionLocal") as mock_session_cls:
            await _require_server_owner(SERVER_ID, req)
            mock_session_cls.assert_not_called()

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_no_caller_id_raises_401(self):
        """Missing caller identity → 401."""
        from fastapi import HTTPException
        from app.routers.entitlements import _require_server_owner
        req = _make_request(roles=["server_owner"], client_id="")
        with pytest.raises(HTTPException) as exc_info:
            await _require_server_owner(SERVER_ID, req)
        assert exc_info.value.status_code == 401

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_server_not_found_raises_404(self):
        """Server does not exist → 404."""
        from fastapi import HTTPException
        from app.routers.entitlements import _require_server_owner

        req = _make_request(roles=["server_owner"], client_id="caller-1")

        mock_result = MagicMock()
        mock_result.fetchone.return_value = None  # server not found

        mock_db = AsyncMock()
        mock_db.execute = AsyncMock(return_value=mock_result)
        mock_db.__aenter__ = AsyncMock(return_value=mock_db)
        mock_db.__aexit__ = AsyncMock(return_value=False)

        with patch("app.routers.entitlements.AsyncSessionLocal", return_value=mock_db):
            with pytest.raises(HTTPException) as exc_info:
                await _require_server_owner(SERVER_ID, req)
        assert exc_info.value.status_code == 404

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_no_grant_raises_403(self):
        """Server exists but caller has no grant → 403."""
        from fastapi import HTTPException
        from app.routers.entitlements import _require_server_owner

        req = _make_request(roles=["user"], client_id="caller-1")

        srv_result = MagicMock()
        srv_result.fetchone.return_value = (1,)  # server exists
        grant_result = MagicMock()
        grant_result.fetchone.return_value = None  # no grant row

        call_count = 0

        async def _execute(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            return srv_result if call_count == 1 else grant_result

        mock_db = AsyncMock()
        mock_db.execute = _execute
        mock_db.__aenter__ = AsyncMock(return_value=mock_db)
        mock_db.__aexit__ = AsyncMock(return_value=False)

        with patch("app.routers.entitlements.AsyncSessionLocal", return_value=mock_db):
            with pytest.raises(HTTPException) as exc_info:
                await _require_server_owner(SERVER_ID, req)
        assert exc_info.value.status_code == 403

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_owner_grant_passes(self):
        """Caller with server_owner grant → no exception raised."""
        from app.routers.entitlements import _require_server_owner

        req = _make_request(roles=["server_owner"], client_id="caller-1")

        srv_result = MagicMock()
        srv_result.fetchone.return_value = (1,)  # server exists
        grant_result = MagicMock()
        grant_result.fetchone.return_value = (1,)  # grant row found

        call_count = 0

        async def _execute(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            return srv_result if call_count == 1 else grant_result

        mock_db = AsyncMock()
        mock_db.execute = _execute
        mock_db.__aenter__ = AsyncMock(return_value=mock_db)
        mock_db.__aexit__ = AsyncMock(return_value=False)

        with patch("app.routers.entitlements.AsyncSessionLocal", return_value=mock_db):
            # Should not raise
            await _require_server_owner(SERVER_ID, req)

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_manager_grant_passes(self):
        """Caller with manager role grant → no exception raised."""
        from app.routers.entitlements import _require_server_owner

        req = _make_request(roles=["manager"], client_id="caller-1")

        srv_result = MagicMock()
        srv_result.fetchone.return_value = (1,)
        grant_result = MagicMock()
        grant_result.fetchone.return_value = (1,)

        call_count = 0

        async def _execute(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            return srv_result if call_count == 1 else grant_result

        mock_db = AsyncMock()
        mock_db.execute = _execute
        mock_db.__aenter__ = AsyncMock(return_value=mock_db)
        mock_db.__aexit__ = AsyncMock(return_value=False)

        with patch("app.routers.entitlements.AsyncSessionLocal", return_value=mock_db):
            await _require_server_owner(SERVER_ID, req)


# ---------------------------------------------------------------------------
# _emit_entitlement_audit — INV-001 paths
# ---------------------------------------------------------------------------

class TestEmitEntitlementAudit:
    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_successful_emit_writes_to_db(self):
        """Successful audit emit executes an INSERT into audit_events."""
        from app.routers.entitlements import _emit_entitlement_audit

        mock_conn = AsyncMock()
        mock_conn.execute = AsyncMock()
        mock_conn.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_conn.__aexit__ = AsyncMock(return_value=False)

        with patch("app.routers.entitlements._db_engine") as mock_engine:
            mock_engine.begin.return_value = mock_conn
            await _emit_entitlement_audit(
                event_type="entitlement_granted",
                server_id=SERVER_ID,
                entitlement_id=ENT_ID,
                principal_id=PRINCIPAL_ID,
                principal_type="agent",
                actor="caller-001",
                request_id="req-001",
            )
            mock_conn.execute.assert_called_once()
            # Verify tool_name encodes event_type + server_id
            call_kwargs = mock_conn.execute.call_args
            bound_params = call_kwargs[0][1] if call_kwargs[0] else call_kwargs[1]
            assert "entitlement_granted" in bound_params["tool_name"]
            assert SERVER_ID in bound_params["tool_name"]

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_failed_emit_raises_runtime_error(self):
        """DB failure during audit emit raises RuntimeError (INV-001 — never silently skip)."""
        from app.routers.entitlements import _emit_entitlement_audit

        mock_conn = AsyncMock()
        mock_conn.execute = AsyncMock(side_effect=Exception("DB connection lost"))
        mock_conn.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_conn.__aexit__ = AsyncMock(return_value=False)

        with patch("app.routers.entitlements._db_engine") as mock_engine:
            mock_engine.begin.return_value = mock_conn
            with pytest.raises(RuntimeError, match="audit event emission failed"):
                await _emit_entitlement_audit(
                    event_type="entitlement_revoked",
                    server_id=SERVER_ID,
                    entitlement_id=ENT_ID,
                    principal_id=PRINCIPAL_ID,
                    principal_type="human",
                    actor="caller-001",
                    request_id="req-001",
                )

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_revoked_event_encodes_type(self):
        """tool_name for revoke events encodes 'entitlement_revoked'."""
        from app.routers.entitlements import _emit_entitlement_audit

        mock_conn = AsyncMock()
        mock_conn.execute = AsyncMock()
        mock_conn.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_conn.__aexit__ = AsyncMock(return_value=False)

        with patch("app.routers.entitlements._db_engine") as mock_engine:
            mock_engine.begin.return_value = mock_conn
            await _emit_entitlement_audit(
                event_type="entitlement_revoked",
                server_id=SERVER_ID,
                entitlement_id=ENT_ID,
                principal_id=PRINCIPAL_ID,
                principal_type="kc_group",
                actor="caller-001",
                request_id="req-001",
            )
            call_kwargs = mock_conn.execute.call_args
            bound_params = call_kwargs[0][1] if call_kwargs[0] else call_kwargs[1]
            assert "entitlement_revoked" in bound_params["tool_name"]


# ---------------------------------------------------------------------------
# RBAC matrix — entitlement routes (middleware level)
# ---------------------------------------------------------------------------

def _rbac_allowed(method: str, path: str, role: str) -> bool:
    from app.middleware.rbac import _resolve_allowed_roles
    roles = _resolve_allowed_roles(method, path)
    if roles is None:
        return True
    return role in roles


class TestEntitlementRBACMatrix:
    """
    Verify PATH_ROLE_MAP correctly gates each entitlement route.
    These tests exercise the middleware RBAC layer only — ownership checks
    in the handler are tested separately above.
    """

    MINE_PATH = "/api/v1/servers/mine"
    LIST_PATH = f"/api/v1/servers/{SERVER_ID}/entitlements"
    POST_PATH = f"/api/v1/servers/{SERVER_ID}/entitlements"
    DELETE_PATH = f"/api/v1/servers/{SERVER_ID}/entitlements/{ENT_ID}"

    # --- GET /mine ---

    @pytest.mark.unit
    def test_mine_server_owner_allowed(self):
        assert _rbac_allowed("GET", self.MINE_PATH, "server_owner")

    @pytest.mark.unit
    def test_mine_manager_allowed(self):
        assert _rbac_allowed("GET", self.MINE_PATH, "manager")

    @pytest.mark.unit
    def test_mine_platform_admin_allowed(self):
        assert _rbac_allowed("GET", self.MINE_PATH, "platform_admin")

    @pytest.mark.unit
    def test_mine_agent_denied(self):
        assert not _rbac_allowed("GET", self.MINE_PATH, "agent")

    @pytest.mark.unit
    def test_mine_auditor_denied(self):
        assert not _rbac_allowed("GET", self.MINE_PATH, "auditor")

    @pytest.mark.unit
    def test_mine_user_denied(self):
        assert not _rbac_allowed("GET", self.MINE_PATH, "user")

    # --- GET /{id}/entitlements ---

    @pytest.mark.unit
    def test_list_server_owner_allowed(self):
        assert _rbac_allowed("GET", self.LIST_PATH, "server_owner")

    @pytest.mark.unit
    def test_list_manager_allowed(self):
        assert _rbac_allowed("GET", self.LIST_PATH, "manager")

    @pytest.mark.unit
    def test_list_auditor_denied(self):
        # auditor is rejected at the RBAC layer for GET /{id}/entitlements.
        # The handler's _require_server_owner check also rejects auditors (they have
        # no server_owner/manager grant). Keeping RBAC and handler aligned avoids a
        # misleading double-rejection where RBAC passes but the handler returns 403.
        assert not _rbac_allowed("GET", self.LIST_PATH, "auditor")

    @pytest.mark.unit
    def test_list_platform_admin_allowed(self):
        assert _rbac_allowed("GET", self.LIST_PATH, "platform_admin")

    @pytest.mark.unit
    def test_list_agent_denied(self):
        assert not _rbac_allowed("GET", self.LIST_PATH, "agent")

    @pytest.mark.unit
    def test_list_user_denied(self):
        assert not _rbac_allowed("GET", self.LIST_PATH, "user")

    # --- POST /{id}/entitlements ---

    @pytest.mark.unit
    def test_post_server_owner_allowed(self):
        assert _rbac_allowed("POST", self.POST_PATH, "server_owner")

    @pytest.mark.unit
    def test_post_manager_allowed(self):
        assert _rbac_allowed("POST", self.POST_PATH, "manager")

    @pytest.mark.unit
    def test_post_platform_admin_allowed(self):
        assert _rbac_allowed("POST", self.POST_PATH, "platform_admin")

    @pytest.mark.unit
    def test_post_auditor_denied(self):
        """Auditor can read but not mutate entitlements."""
        assert not _rbac_allowed("POST", self.POST_PATH, "auditor")

    @pytest.mark.unit
    def test_post_agent_denied(self):
        assert not _rbac_allowed("POST", self.POST_PATH, "agent")

    @pytest.mark.unit
    def test_post_user_denied(self):
        assert not _rbac_allowed("POST", self.POST_PATH, "user")

    # --- DELETE /{id}/entitlements/{ent_id} ---

    @pytest.mark.unit
    def test_delete_server_owner_allowed(self):
        assert _rbac_allowed("DELETE", self.DELETE_PATH, "server_owner")

    @pytest.mark.unit
    def test_delete_manager_allowed(self):
        assert _rbac_allowed("DELETE", self.DELETE_PATH, "manager")

    @pytest.mark.unit
    def test_delete_platform_admin_allowed(self):
        assert _rbac_allowed("DELETE", self.DELETE_PATH, "platform_admin")

    @pytest.mark.unit
    def test_delete_auditor_denied(self):
        assert not _rbac_allowed("DELETE", self.DELETE_PATH, "auditor")

    @pytest.mark.unit
    def test_delete_agent_denied(self):
        assert not _rbac_allowed("DELETE", self.DELETE_PATH, "agent")

    @pytest.mark.unit
    def test_delete_user_denied(self):
        assert not _rbac_allowed("DELETE", self.DELETE_PATH, "user")


# ---------------------------------------------------------------------------
# _serialize_row
# ---------------------------------------------------------------------------

class TestSerializeRow:
    @pytest.mark.unit
    def test_datetime_converted_to_isoformat(self):
        from app.routers.entitlements import _serialize_row
        ts = datetime.datetime(2026, 6, 10, 12, 0, 0, tzinfo=datetime.timezone.utc)
        out = _serialize_row({"created_at": ts, "name": "test"})
        assert isinstance(out["created_at"], str)
        assert "2026-06-10" in out["created_at"]

    @pytest.mark.unit
    def test_none_preserved(self):
        from app.routers.entitlements import _serialize_row
        out = _serialize_row({"revoked_at": None})
        assert out["revoked_at"] is None

    @pytest.mark.unit
    def test_uuid_stringified(self):
        import uuid
        from app.routers.entitlements import _serialize_row
        uid = uuid.UUID("aaaaaaaa-0000-0000-0000-000000000001")
        out = _serialize_row({"ent_id": uid})
        assert isinstance(out["ent_id"], str)
        assert out["ent_id"] == "aaaaaaaa-0000-0000-0000-000000000001"


# ---------------------------------------------------------------------------
# INV-001: audit called before response in mutations
# ---------------------------------------------------------------------------

class TestINV001AuditBeforeResponse:
    """
    Verify that _emit_entitlement_audit is called synchronously during
    POST and DELETE handler execution, and that a RuntimeError from it
    surfaces as HTTP 500.

    These tests drive the handler functions directly with mocked DB
    and a mocked audit function.
    """

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_grant_new_entitlement_calls_audit(self):
        """POST (new INSERT path) calls _emit_entitlement_audit before returning 201."""
        from app.routers.entitlements import grant_entitlement, EntitlementGrantBody

        req = _make_request(roles=["platform_admin"])
        body = EntitlementGrantBody(principal_id=PRINCIPAL_ID, principal_type="agent")

        # Mock DB: no existing row → INSERT returns new row
        import uuid
        new_ent_id = uuid.UUID(ENT_ID)
        ts_now = datetime.datetime.now(datetime.timezone.utc)
        new_row_mapping = {
            "ent_id": new_ent_id,
            "principal_id": PRINCIPAL_ID,
            "principal_type": "agent",
            "granted_by": "caller-001",
            "granted_at": ts_now,
            "revoked_at": None,
        }

        existing_result = MagicMock()
        existing_result.fetchone.return_value = None  # no existing row

        insert_result = MagicMock()
        insert_result.mappings.return_value.fetchone.return_value = new_row_mapping

        call_count = 0

        async def _execute(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            return existing_result if call_count == 1 else insert_result

        mock_db = AsyncMock()
        mock_db.execute = _execute
        mock_db.commit = AsyncMock()
        mock_db.__aenter__ = AsyncMock(return_value=mock_db)
        mock_db.__aexit__ = AsyncMock(return_value=False)

        audit_called = []

        async def _fake_audit(**kwargs):
            audit_called.append(kwargs["event_type"])

        # Mock OPA data sync (Task 11)
        mock_opa_sync = AsyncMock()
        mock_opa_sync.push_grants = AsyncMock()

        with patch("app.routers.entitlements.AsyncSessionLocal", return_value=mock_db), \
             patch("app.routers.entitlements._require_server_owner", new=AsyncMock()), \
             patch("app.routers.entitlements._emit_entitlement_audit", side_effect=_fake_audit):
            response = await grant_entitlement(SERVER_ID, body, req, opa_data_sync=mock_opa_sync)

        assert len(audit_called) == 1
        assert audit_called[0] == "entitlement_granted"
        assert response.status_code == 201

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_grant_audit_failure_returns_500(self):
        """If _emit_entitlement_audit raises, handler returns 500 (INV-001)."""
        from fastapi import HTTPException
        from app.routers.entitlements import grant_entitlement, EntitlementGrantBody

        req = _make_request(roles=["platform_admin"])
        body = EntitlementGrantBody(principal_id=PRINCIPAL_ID, principal_type="human")

        import uuid
        new_ent_id = uuid.UUID(ENT_ID)
        ts_now = datetime.datetime.now(datetime.timezone.utc)
        new_row_mapping = {
            "ent_id": new_ent_id,
            "principal_id": PRINCIPAL_ID,
            "principal_type": "human",
            "granted_by": "caller-001",
            "granted_at": ts_now,
            "revoked_at": None,
        }

        existing_result = MagicMock()
        existing_result.fetchone.return_value = None

        insert_result = MagicMock()
        insert_result.mappings.return_value.fetchone.return_value = new_row_mapping

        call_count = 0

        async def _execute(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            return existing_result if call_count == 1 else insert_result

        mock_db = AsyncMock()
        mock_db.execute = _execute
        mock_db.commit = AsyncMock()
        mock_db.__aenter__ = AsyncMock(return_value=mock_db)
        mock_db.__aexit__ = AsyncMock(return_value=False)

        async def _failing_audit(**kwargs):
            raise RuntimeError("audit event emission failed: DB down")

        with patch("app.routers.entitlements.AsyncSessionLocal", return_value=mock_db), \
             patch("app.routers.entitlements._require_server_owner", new=AsyncMock()), \
             patch("app.routers.entitlements._emit_entitlement_audit", side_effect=_failing_audit):
            with pytest.raises(HTTPException) as exc_info:
                await grant_entitlement(SERVER_ID, body, req)

        assert exc_info.value.status_code == 500

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_revoke_calls_audit(self):
        """DELETE handler calls _emit_entitlement_audit with event_type='entitlement_revoked'."""
        from app.routers.entitlements import revoke_entitlement

        req = _make_request(roles=["platform_admin"])

        import uuid
        ts_now = datetime.datetime.now(datetime.timezone.utc)
        updated_row = MagicMock()
        updated_row.entitlement_id = uuid.UUID(ENT_ID)
        updated_row.principal_id = PRINCIPAL_ID
        updated_row.principal_type = "agent"
        updated_row.revoked_at = ts_now

        update_result = MagicMock()
        update_result.fetchone.return_value = updated_row

        mock_db = AsyncMock()
        mock_db.execute = AsyncMock(return_value=update_result)
        mock_db.commit = AsyncMock()
        mock_db.__aenter__ = AsyncMock(return_value=mock_db)
        mock_db.__aexit__ = AsyncMock(return_value=False)

        audit_called = []

        async def _fake_audit(**kwargs):
            audit_called.append(kwargs["event_type"])

        # Mock OPA data sync (Task 11)
        mock_opa_sync = AsyncMock()
        mock_opa_sync.push_grants = AsyncMock()

        with patch("app.routers.entitlements.AsyncSessionLocal", return_value=mock_db), \
             patch("app.routers.entitlements._require_server_owner", new=AsyncMock()), \
             patch("app.routers.entitlements._emit_entitlement_audit", side_effect=_fake_audit):
            response = await revoke_entitlement(SERVER_ID, ENT_ID, req, opa_data_sync=mock_opa_sync)

        assert len(audit_called) == 1
        assert audit_called[0] == "entitlement_revoked"
        assert response.status_code == 200

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_revoke_not_found_returns_404_no_audit(self):
        """Revoke of non-existent/already-revoked entitlement → 404, audit NOT called."""
        from fastapi import HTTPException
        from app.routers.entitlements import revoke_entitlement

        req = _make_request(roles=["platform_admin"])

        update_result = MagicMock()
        update_result.fetchone.return_value = None  # nothing updated

        mock_db = AsyncMock()
        mock_db.execute = AsyncMock(return_value=update_result)
        mock_db.commit = AsyncMock()
        mock_db.__aenter__ = AsyncMock(return_value=mock_db)
        mock_db.__aexit__ = AsyncMock(return_value=False)

        audit_called = []

        async def _fake_audit(**kwargs):
            audit_called.append(kwargs)

        with patch("app.routers.entitlements.AsyncSessionLocal", return_value=mock_db), \
             patch("app.routers.entitlements._require_server_owner", new=AsyncMock()), \
             patch("app.routers.entitlements._emit_entitlement_audit", side_effect=_fake_audit):
            with pytest.raises(HTTPException) as exc_info:
                await revoke_entitlement(SERVER_ID, ENT_ID, req)

        assert exc_info.value.status_code == 404
        assert len(audit_called) == 0, "Audit must not fire for a failed (404) operation"

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_idempotent_regrant_active_calls_audit(self):
        """Re-granting an already-active entitlement still emits an audit event."""
        from app.routers.entitlements import grant_entitlement, EntitlementGrantBody

        req = _make_request(roles=["platform_admin"])
        body = EntitlementGrantBody(principal_id=PRINCIPAL_ID, principal_type="agent")

        import uuid
        ent_uuid = uuid.UUID(ENT_ID)
        ts_now = datetime.datetime.now(datetime.timezone.utc)

        # Existing active row (revoked_at = None)
        existing_row = MagicMock()
        existing_row.entitlement_id = ent_uuid
        existing_row.revoked_at = None  # already active

        existing_result = MagicMock()
        existing_result.fetchone.return_value = existing_row

        # Fetch after the no-op
        current_row_mapping = {
            "ent_id": ent_uuid,
            "principal_id": PRINCIPAL_ID,
            "principal_type": "agent",
            "granted_by": "caller-001",
            "granted_at": ts_now,
            "revoked_at": None,
        }
        fetch_result = MagicMock()
        fetch_result.mappings.return_value.fetchone.return_value = current_row_mapping

        call_count = 0

        async def _execute(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            return existing_result if call_count == 1 else fetch_result

        mock_db = AsyncMock()
        mock_db.execute = _execute
        mock_db.commit = AsyncMock()
        mock_db.__aenter__ = AsyncMock(return_value=mock_db)
        mock_db.__aexit__ = AsyncMock(return_value=False)

        audit_called = []

        async def _fake_audit(**kwargs):
            audit_called.append(kwargs["event_type"])

        # Mock OPA data sync (Task 11)
        mock_opa_sync = AsyncMock()
        mock_opa_sync.push_grants = AsyncMock()

        with patch("app.routers.entitlements.AsyncSessionLocal", return_value=mock_db), \
             patch("app.routers.entitlements._require_server_owner", new=AsyncMock()), \
             patch("app.routers.entitlements._emit_entitlement_audit", side_effect=_fake_audit):
            response = await grant_entitlement(SERVER_ID, body, req, opa_data_sync=mock_opa_sync)

        assert len(audit_called) == 1
        assert audit_called[0] == "entitlement_granted"
        # Active re-grant → 200 (not 201)
        assert response.status_code == 200

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_idempotent_unrevoke_calls_audit(self):
        """Re-granting a revoked entitlement clears revoked_at and emits audit."""
        from app.routers.entitlements import grant_entitlement, EntitlementGrantBody

        req = _make_request(roles=["platform_admin"])
        body = EntitlementGrantBody(principal_id=PRINCIPAL_ID, principal_type="human")

        import uuid
        ent_uuid = uuid.UUID(ENT_ID)
        ts_now = datetime.datetime.now(datetime.timezone.utc)

        # Existing revoked row
        existing_row = MagicMock()
        existing_row.entitlement_id = ent_uuid
        existing_row.revoked_at = ts_now  # was revoked

        existing_result = MagicMock()
        existing_result.fetchone.return_value = existing_row

        # After un-revoke UPDATE + fetch
        current_row_mapping = {
            "ent_id": ent_uuid,
            "principal_id": PRINCIPAL_ID,
            "principal_type": "human",
            "granted_by": "caller-001",
            "granted_at": ts_now,
            "revoked_at": None,
        }
        update_result = MagicMock()  # UPDATE returning nothing
        fetch_result = MagicMock()
        fetch_result.mappings.return_value.fetchone.return_value = current_row_mapping

        call_count = 0

        async def _execute(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return existing_result   # SELECT existing
            elif call_count == 2:
                return update_result     # UPDATE revoked_at = NULL
            else:
                return fetch_result      # SELECT current state

        mock_db = AsyncMock()
        mock_db.execute = _execute
        mock_db.commit = AsyncMock()
        mock_db.__aenter__ = AsyncMock(return_value=mock_db)
        mock_db.__aexit__ = AsyncMock(return_value=False)

        audit_called = []

        async def _fake_audit(**kwargs):
            audit_called.append(kwargs["event_type"])

        # Mock OPA data sync (Task 11)
        mock_opa_sync = AsyncMock()
        mock_opa_sync.push_grants = AsyncMock()

        with patch("app.routers.entitlements.AsyncSessionLocal", return_value=mock_db), \
             patch("app.routers.entitlements._require_server_owner", new=AsyncMock()), \
             patch("app.routers.entitlements._emit_entitlement_audit", side_effect=_fake_audit):
            response = await grant_entitlement(SERVER_ID, body, req, opa_data_sync=mock_opa_sync)

        assert len(audit_called) == 1
        assert audit_called[0] == "entitlement_granted"
        assert response.status_code == 200
