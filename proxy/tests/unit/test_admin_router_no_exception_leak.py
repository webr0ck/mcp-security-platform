"""
R4.1: admin_credentials.py and admin_git.py must never put raw exception text
(DB/driver/filesystem/library internals) into a client-facing HTTPException
detail. Every internal-failure path must instead return a stable, generic
message plus a request_id, while the real exception is logged server-side.

Modeled on tests/unit/services/test_deny_map.py::TestNoInternalLeakage — same
"the exception text must not appear in the client-facing message" contract,
applied to the admin routers instead of the /mcp deny-map.
"""
from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException

# A distinctive marker that would only appear if the raw exception text leaked
# into a client response. Modeled on a real driver error to be realistic.
SECRET_MARKER = "password authentication failed for user 'history_x' at host db-internal-7.prod.local"


class _RaisingSessionCM:
    """Mimics `async with AsyncSessionLocal() as session:` where the DB call
    inside the block raises."""

    def __init__(self, exc: Exception):
        self._exc = exc

    async def __aenter__(self):
        raise self._exc

    async def __aexit__(self, *args):
        return False


def _raising_session_factory(exc: Exception):
    return lambda: _RaisingSessionCM(exc)


def _make_request(roles=("admin",), client_id="admin1", request_id="req-abc123"):
    req = MagicMock()
    req.state = SimpleNamespace(client_roles=list(roles), client_id=client_id, request_id=request_id)
    return req


def _assert_no_leak(exc_info, request_id="req-abc123"):
    detail = exc_info.value.detail
    assert exc_info.value.status_code == 500 or exc_info.value.status_code == 503
    rendered = str(detail)
    assert SECRET_MARKER not in rendered, f"raw exception text leaked into client detail: {rendered!r}"
    assert request_id in rendered, f"request_id missing from client detail: {rendered!r}"


# ---------------------------------------------------------------------------
# admin_credentials.py
# ---------------------------------------------------------------------------

class TestAdminCredentialsNoLeak:
    @pytest.mark.asyncio
    async def test_list_tools_db_failure_does_not_leak(self):
        from app.routers import admin_credentials

        request = _make_request()
        exc = RuntimeError(SECRET_MARKER)
        with patch("app.core.database.AsyncSessionLocal", _raising_session_factory(exc)):
            with pytest.raises(HTTPException) as exc_info:
                await admin_credentials.list_tools_with_credential_status(request)
        _assert_no_leak(exc_info)

    @pytest.mark.asyncio
    async def test_upload_credential_tool_lookup_failure_does_not_leak(self):
        from app.routers import admin_credentials

        request = _make_request()
        body = admin_credentials.CredentialUpload(secret="s3cr3t", credential_type="api_key")
        exc = RuntimeError(SECRET_MARKER)
        with patch("app.core.database.AsyncSessionLocal", _raising_session_factory(exc)):
            with pytest.raises(HTTPException) as exc_info:
                await admin_credentials.upload_credential(request, "tool-1", body)
        _assert_no_leak(exc_info)

    @pytest.mark.asyncio
    async def test_revoke_credential_db_failure_does_not_leak(self):
        from app.routers import admin_credentials

        request = _make_request()
        exc = RuntimeError(SECRET_MARKER)
        with patch("app.core.database.AsyncSessionLocal", _raising_session_factory(exc)):
            with pytest.raises(HTTPException) as exc_info:
                await admin_credentials.revoke_credential(request, "tool-1")
        _assert_no_leak(exc_info)

    @pytest.mark.asyncio
    async def test_update_injection_mode_db_failure_does_not_leak(self):
        from app.routers import admin_credentials

        request = _make_request()
        exc = RuntimeError(SECRET_MARKER)
        with patch("app.core.database.AsyncSessionLocal", _raising_session_factory(exc)):
            with pytest.raises(HTTPException) as exc_info:
                await admin_credentials.update_injection_mode(request, "tool-1", "none")
        _assert_no_leak(exc_info)

    @pytest.mark.asyncio
    async def test_encryption_failure_does_not_leak(self):
        from app.routers import admin_credentials

        request = _make_request()
        body = admin_credentials.CredentialUpload(secret="s3cr3t", credential_type="api_key")
        tool_row = SimpleNamespace(
            tool_id="tool-1", name="Tool One", service_name="tool-one",
            entra_tenant_id=None, entra_client_id=None,
        )
        mock_result = MagicMock()
        mock_result.fetchone.return_value = tool_row
        mock_db = AsyncMock()
        mock_db.execute = AsyncMock(return_value=mock_result)
        ok_factory = MagicMock()
        ok_factory.return_value.__aenter__ = AsyncMock(return_value=mock_db)
        ok_factory.return_value.__aexit__ = AsyncMock(return_value=False)

        exc = RuntimeError(SECRET_MARKER)
        with patch("app.core.database.AsyncSessionLocal", ok_factory), \
             patch(
                 "app.credential_broker.kms.load_master_secret_standalone",
                 AsyncMock(side_effect=exc),
             ):
            with pytest.raises(HTTPException) as exc_info:
                await admin_credentials.upload_credential(request, "tool-1", body)
        _assert_no_leak(exc_info)


# ---------------------------------------------------------------------------
# admin_git.py
# ---------------------------------------------------------------------------

class TestAdminGitNoLeak:
    @pytest.mark.asyncio
    async def test_put_token_kms_failure_does_not_leak(self):
        from app.routers import admin_git

        request = _make_request()
        body = admin_git.TokenUpdate(token="ghp_abcdefgh")
        exc = RuntimeError(SECRET_MARKER)
        with patch.object(admin_git.platform_secrets, "set_secret", AsyncMock(side_effect=exc)):
            with pytest.raises(HTTPException) as exc_info:
                await admin_git.put_token("github", body, request)
        _assert_no_leak(exc_info)
