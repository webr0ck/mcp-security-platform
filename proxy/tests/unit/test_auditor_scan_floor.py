"""PRD-0006 R-1 — mcp_checker code-scan risk floor (structural, monotonic)."""
from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, MagicMock, patch


def _session(row):
    m = MagicMock()
    m.__getitem__ = lambda s, k: row[k]
    result = MagicMock()
    result.mappings.return_value.first.return_value = (m if row is not None else None)
    session = AsyncMock()
    session.execute = AsyncMock(return_value=result)
    ctx = AsyncMock()
    ctx.__aenter__ = AsyncMock(return_value=session)
    ctx.__aexit__ = AsyncMock(return_value=False)
    return MagicMock(return_value=ctx)


@pytest.mark.unit
@pytest.mark.asyncio
async def test_floor_fires_on_blocked_scan():
    from app.services import auditor
    row = {"scan_status": "blocked", "scan_report": [], "scanned_at": None, "scan_commit": "abc"}
    with patch("app.core.database.AsyncSessionLocal", _session(row)):
        out = await auditor._scan_risk_floor("t1")
    assert out["floor"] > 0
    assert out["reason"] == "scan_status=blocked"


@pytest.mark.unit
@pytest.mark.asyncio
async def test_floor_fires_on_block_tier_finding():
    from app.services import auditor
    row = {"scan_status": "passed",
           "scan_report": [{"check": "crypto_stealer", "block": True}],
           "scanned_at": None, "scan_commit": None}
    with patch("app.core.database.AsyncSessionLocal", _session(row)):
        out = await auditor._scan_risk_floor("t2")
    assert out["floor"] > 0
    assert out["reason"] == "block_tier_finding"


@pytest.mark.unit
@pytest.mark.asyncio
async def test_no_floor_on_warning_only_scan():
    from app.services import auditor
    row = {"scan_status": "passed",
           "scan_report": [{"check": "tool_schema", "block": False}],
           "scanned_at": None, "scan_commit": None}
    with patch("app.core.database.AsyncSessionLocal", _session(row)):
        out = await auditor._scan_risk_floor("t3")
    assert out["floor"] == 0


@pytest.mark.unit
@pytest.mark.asyncio
async def test_no_server_link_is_manifest_only():
    """Direct POST /tools registration (no server row) -> floor 0, unchanged."""
    from app.services import auditor
    with patch("app.core.database.AsyncSessionLocal", _session(None)):
        out = await auditor._scan_risk_floor("t4")
    assert out["floor"] == 0


@pytest.mark.unit
@pytest.mark.asyncio
async def test_lookup_error_fails_safe_to_zero():
    from app.services import auditor
    boom = MagicMock(side_effect=RuntimeError("db down"))
    with patch("app.core.database.AsyncSessionLocal", boom):
        out = await auditor._scan_risk_floor("t5")
    assert out["floor"] == 0
