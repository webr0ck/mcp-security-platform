"""Tests for the self-service auto-entitlement helper in auth.py."""
from unittest.mock import AsyncMock, patch

import pytest

from app.middleware.auth import _ensure_self_service_entitlement


@pytest.mark.asyncio
async def test_grants_entitlement_when_absent_and_not_cached():
    mock_redis = AsyncMock()
    mock_redis.get = AsyncMock(return_value=None)  # not cached
    mock_db_execute = AsyncMock()
    with patch("app.middleware.auth._get_cached_redis", return_value=mock_redis), \
         patch("app.core.database.AsyncSessionLocal") as mock_session_cls:
        mock_session = mock_session_cls.return_value.__aenter__.return_value
        mock_session.execute = mock_db_execute
        mock_session.commit = AsyncMock()
        await _ensure_self_service_entitlement("human:keycloak:bob@corp", "human")
    # An INSERT ... ON CONFLICT DO NOTHING should have run against entitlement
    assert mock_db_execute.await_count >= 1
    mock_redis.setex.assert_called_once()


@pytest.mark.asyncio
async def test_skips_db_when_already_cached():
    mock_redis = AsyncMock()
    mock_redis.get = AsyncMock(return_value=b"1")  # already ensured
    with patch("app.middleware.auth._get_cached_redis", return_value=mock_redis), \
         patch("app.core.database.AsyncSessionLocal") as mock_session_cls:
        await _ensure_self_service_entitlement("human:keycloak:bob@corp", "human")
        mock_session_cls.assert_not_called()
