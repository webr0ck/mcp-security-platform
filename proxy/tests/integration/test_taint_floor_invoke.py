"""Integration: B-coarse taint floor through invoke_tool (PRD-0001 M2 / RFC-0001 §8.1).

Runs against real Postgres + Redis (inside the proxy container):
  pytest tests/integration/test_taint_floor_invoke.py -m integration

D1 (the headline "blocked action") needs no OPA/upstream — the deny fires at Step 1.6,
before both. D3 only asserts the taint gate does NOT block a clean session.
"""
from __future__ import annotations

import uuid

import pytest
from sqlalchemy import text

from app.core.config import settings
from app.core.database import AsyncSessionLocal
from app.core.redis_client import redis_pool
from app.services import taint_store
from app.services.invocation import TaintFloorDenyError, _lookup_server_trust, invoke_tool

pytestmark = pytest.mark.integration


@pytest.fixture
async def redis_ready():
    # `.client` raises when uninitialized; check the backing attr instead.
    if getattr(redis_pool, "_client", None) is None:
        await redis_pool.initialize()
    yield


async def _insert_tool(tool_id: str, name: str, required_integrity: int = 1, server_id=None):
    """Insert a real tool row so the audit_events.tool_id FK is satisfied."""
    async with AsyncSessionLocal() as db:
        await db.execute(
            text(
                "INSERT INTO tool_registry "
                "(tool_id, name, version, description, schema, upstream_url, "
                " registered_by, status, required_integrity, server_id) "
                "VALUES (:id, :name, '1.0.0', 'demo', '{}'::jsonb, "
                "'http://unused.invalid/mcp', 'test', 'active', :ri, :sid)"
            ),
            {"id": tool_id, "name": name, "ri": required_integrity, "sid": server_id},
        )
        await db.commit()


def _tool_record(name: str, tool_id: str, required_integrity: int = 1, server_id=None, injection_mode="none"):
    return {
        "tool_id": tool_id,
        "name": name,
        "version": "1.0.0",
        "status": "active",
        "risk_level": "high",
        "server_id": server_id,
        "upstream_url": "http://unused.invalid/mcp",
        "injection_mode": injection_mode,
        "required_integrity": required_integrity,
    }


def _req(name: str):
    return {
        "jsonrpc": "2.0",
        "id": "demo-1",
        "method": "tools/call",
        "params": {"name": name, "arguments": {}},
    }


async def test_d1_tainted_session_blocks_high_sink(redis_ready, monkeypatch):
    """D1: a tainted session is denied a high-sensitivity sink, with an INV-001 audit."""
    monkeypatch.setattr(settings, "TAINT_FLOOR_ENABLED", True)
    tid = str(uuid.uuid4())
    name = f"demo-high-sink-{uuid.uuid4().hex[:8]}"
    await _insert_tool(tid, name, required_integrity=1)
    principal = f"human:test:{uuid.uuid4()}"

    # Pre-taint the principal against REAL Redis (simulating a prior untrusted result).
    await taint_store.mark_tainted_for_principal(principal)
    assert await taint_store.is_tainted_for_principal(principal) is True

    with pytest.raises(TaintFloorDenyError):
        await invoke_tool(
            tool_record=_tool_record(name, tid, required_integrity=1, server_id=None),
            json_rpc_request=_req(name),
            client_id="test-agent",
            client_roles=["agent"],
            is_testing=False,
            request_id=str(uuid.uuid4()),
            principal_id=principal,
            principal_type="human",
        )

    # INV-001: the deny was audited synchronously with a taint_floor reason.
    async with AsyncSessionLocal() as db:
        row = (
            await db.execute(
                text(
                    "SELECT outcome, opa_reasons FROM audit_events "
                    "WHERE tool_name = :n AND outcome = 'deny' LIMIT 1"
                ),
                {"n": name},
            )
        ).mappings().fetchone()
    assert row is not None, "no deny audit row written for the taint-floor block"
    assert "taint_floor" in str(row["opa_reasons"])


async def test_d3_clean_session_passes_taint_gate(redis_ready, monkeypatch):
    """D3: a clean session is NOT blocked by the taint floor (may deny later for other reasons)."""
    monkeypatch.setattr(settings, "TAINT_FLOOR_ENABLED", True)
    tid = str(uuid.uuid4())
    name = f"demo-clean-{uuid.uuid4().hex[:8]}"
    await _insert_tool(tid, name, required_integrity=1)
    principal = f"human:test:{uuid.uuid4()}"  # never tainted
    assert await taint_store.is_tainted_for_principal(principal) is False

    try:
        await invoke_tool(
            tool_record=_tool_record(name, tid, required_integrity=1, server_id=None),
            json_rpc_request=_req(name),
            client_id="test-agent",
            client_roles=["agent"],
            is_testing=False,
            request_id=str(uuid.uuid4()),
            principal_id=principal,
            principal_type="human",
        )
    except TaintFloorDenyError:
        pytest.fail("clean session was wrongly denied by the taint floor")
    except Exception:
        pass  # OPA deny / upstream error past the gate is acceptable for this assertion


async def test_taint_store_roundtrip_real_redis(redis_ready):
    """The fail-closed store works against real Redis: fresh principal clean, marked -> tainted."""
    principal = f"human:test:{uuid.uuid4()}"
    assert await taint_store.is_tainted_for_principal(principal) is False
    await taint_store.mark_tainted_for_principal(principal)
    assert await taint_store.is_tainted_for_principal(principal) is True


async def test_lookup_server_trust_real_db():
    """_lookup_server_trust reads trust_tier from real server_registry; fail-closed on missing."""
    sid = str(uuid.uuid4())
    async with AsyncSessionLocal() as db:
        await db.execute(
            text(
                "INSERT INTO server_registry (server_id, name, upstream_url, owner_sub, trust_tier) "
                "VALUES (:sid, :name, 'http://demo.invalid', 'owner-test', 0)"
            ),
            {"sid": sid, "name": f"demo-untrusted-{uuid.uuid4().hex[:8]}"},
        )
        await db.commit()

    tier, _dim = await _lookup_server_trust(sid)
    assert tier == 0  # untrusted server

    # Unknown server_id -> fail-closed (None) -> caller treats as untrusted.
    missing_tier, _ = await _lookup_server_trust(str(uuid.uuid4()))
    assert missing_tier is None
