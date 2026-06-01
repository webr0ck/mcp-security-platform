"""
Tests that app lifespan wires broker_instance on startup and zeros
the master secret on shutdown.
"""
from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, MagicMock, patch


@pytest.fixture(autouse=True)
def _restore_broker_instance():
    """Restore broker_instance after each test to avoid state leak between tests."""
    import app.services.invocation as inv_svc
    original = inv_svc.broker_instance
    yield
    inv_svc.broker_instance = original


@pytest.mark.unit
async def test_lifespan_sets_broker_instance_when_factory_returns_broker():
    """After lifespan startup, invocation.broker_instance must equal what build_broker returned."""
    import app.services.invocation as inv_svc
    from app.main import lifespan, app

    mock_broker = MagicMock()
    mock_broker._master_secret = bytearray(b"\xff" * 32)
    mock_broker._zero = MagicMock()

    with patch("app.main.build_broker", return_value=mock_broker) as mock_build, \
         patch("app.main.redis_pool") as mock_pool, \
         patch("app.main.check_database_health", new_callable=AsyncMock, return_value=True):
        mock_pool.initialize = AsyncMock()
        mock_pool.close = AsyncMock()
        mock_pool.client = MagicMock()

        async with lifespan(app):
            assert inv_svc.broker_instance is mock_broker

    mock_build.assert_called_once()


@pytest.mark.unit
async def test_lifespan_sets_broker_instance_none_when_factory_returns_none():
    """When build_broker returns None (unconfigured Vault), broker_instance is None."""
    import app.services.invocation as inv_svc
    from app.main import lifespan, app

    with patch("app.main.build_broker", return_value=None), \
         patch("app.main.redis_pool") as mock_pool, \
         patch("app.main.check_database_health", new_callable=AsyncMock, return_value=True):
        mock_pool.initialize = AsyncMock()
        mock_pool.close = AsyncMock()
        mock_pool.client = MagicMock()

        async with lifespan(app):
            assert inv_svc.broker_instance is None


@pytest.mark.unit
async def test_lifespan_zeros_master_secret_on_shutdown():
    """Shutdown must zero the broker's master_secret bytearray (CB-008 bound)."""
    import app.services.invocation as inv_svc
    from app.main import lifespan, app

    master = bytearray(b"\xab" * 32)
    mock_broker = MagicMock()
    mock_broker._master_secret = master
    mock_broker._zero = MagicMock(side_effect=lambda buf: buf.__setitem__(slice(None), bytes(len(buf))))

    with patch("app.main.build_broker", return_value=mock_broker), \
         patch("app.main.redis_pool") as mock_pool, \
         patch("app.main.check_database_health", new_callable=AsyncMock, return_value=True):
        mock_pool.initialize = AsyncMock()
        mock_pool.close = AsyncMock()
        mock_pool.client = MagicMock()

        async with lifespan(app):
            pass  # yields and shuts down

    mock_broker._zero.assert_called_once_with(master)
    assert all(b == 0 for b in master), "master secret was not zeroed in-place"
