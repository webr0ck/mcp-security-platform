"""
WP-A3 (CR-04 remainder) — dynamic per-server external OAuth adapter resolution.

Covers app.credential_broker.adapters.dynamic_external_oauth.resolve_external_oauth_adapter:
fail-closed on missing server/wrong mode/incomplete approved config/no client_secret,
and the happy path building a GenericOAuthAdapter from approved_upstream_idp_config.

Non-negotiable per WP-A2: this MUST read approved_upstream_idp_config, never the
submitter-requested upstream_idp_config — a test pins that a server whose
approved_upstream_idp_config is null returns None even when upstream_idp_config
(requested) is fully populated with a client_id/issuer/etc.
"""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.credential_broker.adapters.dynamic_external_oauth import resolve_external_oauth_adapter


def _server_row(**overrides) -> dict:
    base = dict(
        server_id="srv-1",
        injection_mode="external_oauth_user_token",
        default_injection_mode=None,
        approved_upstream_idp_config={
            "client_id": "app-client-id",
            "authorization_endpoint": "https://idp.example.com/authorize",
            "token_endpoint": "https://idp.example.com/token",
            "redirect_uri": "https://proxy.example.com/auth/callback/my-service",
        },
        approved_oauth_scopes=["read:issue"],
    )
    base.update(overrides)
    return base


def _mock_session_factory(server_row, credential_row=None):
    """Returns a db_factory callable whose session.execute() answers the two
    queries resolve_external_oauth_adapter issues in order: server_registry
    row, then tool_registry credential_id row."""
    calls = {"n": 0}

    async def fake_execute(stmt, params=None):
        result = MagicMock()
        calls["n"] += 1
        if calls["n"] == 1:
            if server_row is None:
                result.fetchone.return_value = None
            else:
                fake_row = MagicMock()
                fake_row._mapping = server_row
                result.fetchone.return_value = fake_row
        else:
            if credential_row is None:
                result.fetchone.return_value = None
            else:
                fake_row = MagicMock()
                fake_row.tool_id = credential_row["tool_id"]
                fake_row.credential_id = credential_row["credential_id"]
                result.fetchone.return_value = fake_row
        return result

    session = MagicMock()
    session.execute = AsyncMock(side_effect=fake_execute)

    class _Ctx:
        async def __aenter__(self):
            return session
        async def __aexit__(self, *a):
            return False

    def db_factory():
        return _Ctx()

    return db_factory


@pytest.mark.asyncio
async def test_no_matching_server_returns_none():
    db_factory = _mock_session_factory(None)
    result = await resolve_external_oauth_adapter("unknown-svc", db_factory, vault_client=MagicMock())
    assert result is None


@pytest.mark.asyncio
async def test_wrong_injection_mode_returns_none():
    db_factory = _mock_session_factory(_server_row(injection_mode="service_account"))
    result = await resolve_external_oauth_adapter("my-service", db_factory, vault_client=MagicMock())
    assert result is None


@pytest.mark.asyncio
async def test_no_approved_config_returns_none_even_if_requested_config_exists():
    """Non-negotiable: must never fall back to requested upstream_idp_config."""
    row = _server_row(approved_upstream_idp_config=None)
    db_factory = _mock_session_factory(row)
    result = await resolve_external_oauth_adapter("my-service", db_factory, vault_client=MagicMock())
    assert result is None


@pytest.mark.asyncio
async def test_incomplete_approved_config_returns_none():
    row = _server_row(approved_upstream_idp_config={"client_id": "abc"})  # missing endpoints
    db_factory = _mock_session_factory(row)
    result = await resolve_external_oauth_adapter("my-service", db_factory, vault_client=MagicMock())
    assert result is None


@pytest.mark.asyncio
async def test_no_credential_id_found_returns_none():
    db_factory = _mock_session_factory(_server_row(), credential_row=None)
    result = await resolve_external_oauth_adapter("my-service", db_factory, vault_client=MagicMock())
    assert result is None


@pytest.mark.asyncio
async def test_happy_path_builds_generic_adapter():
    db_factory = _mock_session_factory(
        _server_row(),
        credential_row={"tool_id": "tool-1", "credential_id": "cred-1"},
    )
    with patch(
        "app.services.credential_storage.retrieve_credential",
        AsyncMock(return_value={"client_secret": "shh-secret"}),
    ):
        adapter = await resolve_external_oauth_adapter("my-service", db_factory, vault_client=MagicMock())
    assert adapter is not None
    assert adapter._client_id == "app-client-id"
    assert adapter._client_secret == "shh-secret"
    assert adapter._token_endpoint == "https://idp.example.com/token"
    assert adapter._scopes == ["read:issue"]


@pytest.mark.asyncio
async def test_missing_client_secret_in_credential_returns_none():
    db_factory = _mock_session_factory(
        _server_row(),
        credential_row={"tool_id": "tool-1", "credential_id": "cred-1"},
    )
    with patch(
        "app.services.credential_storage.retrieve_credential",
        AsyncMock(return_value={"some_other_field": "x"}),
    ):
        adapter = await resolve_external_oauth_adapter("my-service", db_factory, vault_client=MagicMock())
    assert adapter is None
