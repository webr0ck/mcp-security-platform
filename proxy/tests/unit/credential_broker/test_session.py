from __future__ import annotations
import pytest
from unittest.mock import AsyncMock
from datetime import datetime, timezone, timedelta

@pytest.mark.unit
async def test_session_stores_and_retrieves_token():
    from app.credential_broker.session import SessionStore

    mock_redis = AsyncMock()
    mock_redis.set = AsyncMock()
    mock_redis.get = AsyncMock(return_value='{"value":"tok","token_id":"tid","expires_at":"2099-01-01T00:00:00+00:00","service":"grafana","approach":"B"}')

    store = SessionStore(redis=mock_redis)
    future = datetime.now(timezone.utc) + timedelta(hours=1)
    await store.save(
        session_id="sess-1",
        service="grafana",
        token="tok",
        token_id="tid",
        expires_at=future,
        approach="B",
    )
    mock_redis.set.assert_awaited_once()

    result = await store.get(session_id="sess-1", service="grafana")
    assert result is not None
    assert result["value"] == "tok"

@pytest.mark.unit
async def test_session_get_returns_none_on_miss():
    from app.credential_broker.session import SessionStore

    mock_redis = AsyncMock()
    mock_redis.get = AsyncMock(return_value=None)

    store = SessionStore(redis=mock_redis)
    result = await store.get(session_id="sess-1", service="unknown")
    assert result is None

@pytest.mark.unit
async def test_session_delete():
    from app.credential_broker.session import SessionStore

    mock_redis = AsyncMock()
    mock_redis.delete = AsyncMock()

    store = SessionStore(redis=mock_redis)
    await store.delete(session_id="sess-1", service="grafana")
    mock_redis.delete.assert_awaited_once_with("broker:sess-1:grafana")
