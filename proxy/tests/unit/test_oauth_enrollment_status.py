"""
WP-A3 (CR-04) — GET /auth/status/{service} enrollment-status endpoint.

Applies to every approach-A adapter (m365, dex, bitbucket, entra_user_token,
external_oauth_user_token) since it reads credential_store generically by
service name via the same typed-principal dual-read the broker uses —
not specific to the new external_oauth mode.
"""
from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.routers.oauth import enrollment_status


def _request(client_id="alice@corp", principal_id=None, principal_type=None):
    req = MagicMock()
    req.state.client_id = client_id
    req.state.principal_id = principal_id
    req.state.principal_type = principal_type
    return req


def _mock_session(resolved_owner_key, credential_exists: bool):
    session = MagicMock()

    async def fake_execute(stmt, params=None):
        result = MagicMock()
        result.fetchone.return_value = (1,) if credential_exists else None
        return result

    session.execute = AsyncMock(side_effect=fake_execute)

    class _Ctx:
        async def __aenter__(self):
            return session
        async def __aexit__(self, *a):
            return False

    return _Ctx()


@pytest.mark.asyncio
async def test_enrolled_true_when_credential_row_exists():
    resolved = MagicMock()
    resolved.owner_key = "alice@corp"
    with patch("app.core.database.AsyncSessionLocal", return_value=_mock_session("alice@corp", True)), \
         patch(
             "app.credential_broker.principal_resolution.resolve_credential_owner",
             AsyncMock(return_value=resolved),
         ):
        resp = await enrollment_status("jira-cloud", _request())
    body = json.loads(resp.body)
    assert body["enrolled"] is True
    assert body["service"] == "jira-cloud"
    assert body["enrollment_url"].endswith("/auth/enroll/jira-cloud")


@pytest.mark.asyncio
async def test_not_enrolled_when_no_credential_row():
    resolved = MagicMock()
    resolved.owner_key = "alice@corp"
    with patch("app.core.database.AsyncSessionLocal", return_value=_mock_session("alice@corp", False)), \
         patch(
             "app.credential_broker.principal_resolution.resolve_credential_owner",
             AsyncMock(return_value=resolved),
         ):
        resp = await enrollment_status("jira-cloud", _request())
    body = json.loads(resp.body)
    assert body["enrolled"] is False


@pytest.mark.asyncio
async def test_cross_type_mismatch_reports_not_enrolled_not_an_error():
    from app.credential_broker.principal_resolution import CrossTypePrincipalMismatch

    with patch("app.core.database.AsyncSessionLocal", return_value=_mock_session("x", True)), \
         patch(
             "app.credential_broker.principal_resolution.resolve_credential_owner",
             AsyncMock(side_effect=CrossTypePrincipalMismatch(
                 caller_type="agent", row_type="human", bare_sub="alice@corp", service="jira-cloud"
             )),
         ):
        resp = await enrollment_status("jira-cloud", _request())
    body = json.loads(resp.body)
    assert body["enrolled"] is False


@pytest.mark.asyncio
async def test_unauthenticated_caller_rejected():
    from fastapi import HTTPException

    with pytest.raises(HTTPException) as exc_info:
        await enrollment_status("jira-cloud", _request(client_id=None))
    assert exc_info.value.status_code == 401
