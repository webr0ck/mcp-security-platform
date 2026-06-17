import pytest
from app.services import limits


def test_sensitivity_to_cutoff_map():
    assert limits.SENSITIVITY_CUTOFF == {"normal": 0.85, "lenient": 0.95, "off": 2.0}
    assert limits.cutoff_for_sensitivity("normal") == 0.85
    assert limits.cutoff_for_sensitivity("off") == 2.0
    assert limits.cutoff_for_sensitivity("bogus") == 0.85


@pytest.mark.asyncio
async def test_get_anomaly_cutoff_failclosed_on_error(monkeypatch):
    async def boom(_cid): raise RuntimeError("redis down")
    monkeypatch.setattr(limits, "_read_limits_row", boom)
    assert await limits.get_anomaly_cutoff("c1") == 0.85


@pytest.mark.asyncio
async def test_get_rate_limit_failclosed_to_role_default(monkeypatch):
    async def boom(_cid): raise RuntimeError("redis down")
    monkeypatch.setattr(limits, "_read_limits_row", boom)
    assert await limits.get_rate_limit("c1", role_default=120) == 120


@pytest.mark.asyncio
async def test_get_rate_limit_override_wins(monkeypatch):
    async def row(_cid): return {"rate_limit": 10, "anomaly_sensitivity": "normal"}
    monkeypatch.setattr(limits, "_read_limits_row", row)
    assert await limits.get_rate_limit("c1", role_default=120) == 10


@pytest.mark.asyncio
async def test_get_rate_limit_null_uses_role_default(monkeypatch):
    async def row(_cid): return {"rate_limit": None, "anomaly_sensitivity": "off"}
    monkeypatch.setattr(limits, "_read_limits_row", row)
    assert await limits.get_rate_limit("c1", role_default=120) == 120
    assert await limits.get_anomaly_cutoff("c1") == 2.0


def test_score_window_is_readonly():
    import inspect
    src = inspect.getsource(limits.score_window)
    assert "get_anomaly_window_with_timestamps" in src
    assert "push_anomaly_invocation" not in src
