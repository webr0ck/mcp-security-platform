from __future__ import annotations
import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock, MagicMock


@pytest.mark.unit
async def test_broker_resolve_approach_b_returns_credential():
    from app.credential_broker.broker import CredentialBroker
    from app.credential_broker.models import CredentialResult, Token

    future = datetime.now(timezone.utc) + timedelta(hours=1)
    mock_session = AsyncMock()
    mock_session.get = AsyncMock(return_value=None)
    mock_session.save = AsyncMock()

    mock_adapter = AsyncMock()
    mock_adapter.provision = AsyncMock(
        return_value=Token(value="auto-token", expires_at=future, token_id="tid-1")
    )

    broker = CredentialBroker.__new__(CredentialBroker)
    broker._session = mock_session
    broker._approach_b_adapters = {"grafana": mock_adapter}
    broker._approach_a_adapters = {}
    broker._kms = AsyncMock()
    broker._db_factory = MagicMock()
    broker._master_secret = None

    result = await broker.resolve(
        user_sub="alice@corp",
        service="grafana",
        session_id="sess-1",
        approach="B",
    )

    assert isinstance(result, CredentialResult)
    assert result.token == "auto-token"
    assert result.approach == "B"
    mock_session.save.assert_awaited_once()


@pytest.mark.unit
async def test_broker_resolve_returns_cached_session_token():
    from app.credential_broker.broker import CredentialBroker

    future = datetime.now(timezone.utc) + timedelta(hours=1)
    mock_session = AsyncMock()
    mock_session.get = AsyncMock(return_value={
        "value": "cached-token",
        "token_id": "tid-cached",
        "expires_at": future.isoformat(),
        "service": "grafana",
        "approach": "B",
    })

    broker = CredentialBroker.__new__(CredentialBroker)
    broker._session = mock_session
    broker._approach_b_adapters = {}
    broker._approach_a_adapters = {}
    broker._kms = AsyncMock()
    broker._db_factory = MagicMock()
    broker._master_secret = None

    result = await broker.resolve(
        user_sub="alice@corp",
        service="grafana",
        session_id="sess-1",
        approach="B",
    )
    assert result.token == "cached-token"


@pytest.mark.unit
async def test_broker_resolve_a_uses_session_factory():
    """_resolve_a must create a session from the factory, not hold a stale one."""
    from app.credential_broker.broker import CredentialBroker, CredentialNotEnrolledError
    from app.credential_broker.models import CredentialResult

    # session_factory is a callable; calling it returns an async context manager
    mock_session = AsyncMock()
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=False)
    # Simulate "no row" → expect CredentialNotEnrolledError
    mock_session.execute = AsyncMock(return_value=MagicMock(fetchone=MagicMock(return_value=None)))
    mock_session.commit = AsyncMock()

    mock_factory = MagicMock(return_value=mock_session)  # factory() → context manager

    broker = CredentialBroker.__new__(CredentialBroker)
    broker._session = AsyncMock()
    broker._approach_b_adapters = {}
    broker._approach_a_adapters = {}
    broker._kms = AsyncMock()
    broker._db_factory = mock_factory   # <-- new attribute name
    broker._master_secret = None
    broker._master_secret_fetched_at = None

    # Mock _get_master_secret so it doesn't call Vault
    broker._get_master_secret = AsyncMock(return_value=b"\x00" * 32)

    with pytest.raises(CredentialNotEnrolledError):
        await broker.resolve(
            user_sub="alice@corp",
            service="jira",
            session_id="sess-1",
            approach="A",
        )

    # Factory must have been called exactly once to create a session
    mock_factory.assert_called_once()
