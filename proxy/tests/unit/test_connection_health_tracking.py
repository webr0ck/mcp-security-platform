from __future__ import annotations
import pytest
from unittest.mock import AsyncMock, MagicMock, patch


@pytest.mark.unit
async def test_record_connection_result_noop_without_server_id():
    """An unlinked tool (no server_id) must never touch the DB."""
    from app.services.invocation import _record_connection_result

    with patch("app.core.database.AsyncSessionLocal") as mock_session_cls:
        await _record_connection_result("", "http://x", success=False, error="boom")
        mock_session_cls.assert_not_called()


@pytest.mark.unit
async def test_record_connection_result_auto_flags_after_threshold():
    """Reaching _CONNECTION_FAILURE_THRESHOLD consecutive failures must flip
    debug_mode via the 'system:auto-health-check' sentinel — never on a single
    failure below threshold."""
    from app.services.invocation import _record_connection_result, _CONNECTION_FAILURE_THRESHOLD

    mock_session = AsyncMock()
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=False)
    mock_session.commit = AsyncMock()
    # First execute() (the UPDATE ... RETURNING) reports the count has just
    # reached threshold and debug_mode is currently false.
    mock_session.execute = AsyncMock(return_value=MagicMock(
        fetchone=MagicMock(return_value=MagicMock(
            connection_failure_count=_CONNECTION_FAILURE_THRESHOLD, debug_mode=False,
        ))
    ))

    with patch("app.core.database.AsyncSessionLocal", return_value=mock_session):
        await _record_connection_result("srv-1", "http://x", success=False, error="unreachable")

    # Two statements: the failure-count UPDATE...RETURNING, then the
    # debug_mode-flip UPDATE (since count >= threshold and debug_mode was false).
    assert mock_session.execute.await_count == 2
    flip_sql = mock_session.execute.await_args_list[1].args[0].text
    assert "debug_mode = true" in flip_sql
    assert "system:auto-health-check" in flip_sql


@pytest.mark.unit
async def test_record_connection_result_success_resets_counter_only():
    """A success must reset the failure counter and must NEVER touch
    debug_mode — recovery is a deliberate admin action, not automatic."""
    from app.services.invocation import _record_connection_result

    mock_session = AsyncMock()
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=False)
    mock_session.commit = AsyncMock()
    mock_session.execute = AsyncMock()

    with patch("app.core.database.AsyncSessionLocal", return_value=mock_session):
        await _record_connection_result("srv-1", "http://x", success=True)

    assert mock_session.execute.await_count == 1
    reset_sql = mock_session.execute.await_args_list[0].args[0].text
    assert "connection_failure_count = 0" in reset_sql
    assert "debug_mode" not in reset_sql


@pytest.mark.unit
async def test_record_connection_result_never_raises_on_db_failure():
    """Fire-and-forget contract: a DB error here must never propagate — it
    would otherwise turn a real tool success/failure into an unrelated 500."""
    from app.services.invocation import _record_connection_result

    with patch("app.core.database.AsyncSessionLocal", side_effect=RuntimeError("db down")):
        await _record_connection_result("srv-1", "http://x", success=False, error="x")  # must not raise
