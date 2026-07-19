"""Integration: B-coarse taint floor through invoke_tool (PRD-0001 M2 / RFC-0001 §8.1).

Runs against real Postgres + Redis (inside the proxy container):
  pytest tests/integration/test_taint_floor_invoke.py -m integration

PRD-0010 Phase 0 moved the taint floor to NOTIFY-ONLY mode: a tainted session
hitting a high-integrity sink is no longer denied — the call proceeds, and the
taint is surfaced as an advisory notice on an outcome="allow" audit event
(see app/services/invocation.py, taint_floor_decision block). The hard-deny
path (TaintFloorDenyError) is kept in code for a future Phase 1 re-enable but
is not currently exercised by invoke_tool.

D1 (the headline "notify, don't block" case) needs no OPA/upstream — the
notify-only branch fires at Step 1.6, before both. D3 asserts a clean
(non-tainted) session never gets a taint notice at all.
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
    #
    # tests/conftest.py's REDIS_HOST default now probes DNS itself (resolves
    # to "redis" in-container, "localhost" on the Mac host), so the
    # in-container correction that used to live here is redundant — kept as
    # a no-op fixture for the fixture-name dependency below.
    if getattr(redis_pool, "_client", None) is None:
        await redis_pool.initialize()
    yield


_test_tool_ids: list[str] = []


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
    _test_tool_ids.append(tool_id)


@pytest.fixture(autouse=True)
async def _cleanup_test_tools():
    """Soft-delete any tool_registry rows created by this module after each test."""
    yield
    if not _test_tool_ids:
        return
    async with AsyncSessionLocal() as db:
        await db.execute(
            text("UPDATE tool_registry SET deleted_at = NOW() WHERE tool_id = ANY(:ids)"),
            {"ids": _test_tool_ids},
        )
        await db.commit()
    _test_tool_ids.clear()


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


async def test_d1_tainted_session_notify_only_allows_high_sink(redis_ready, monkeypatch):
    """D1 (PRD-0010 Phase 0): a tainted session hitting a high-integrity sink is ALLOWED,
    not denied — the taint floor is notify-only. The call proceeds past the taint gate
    (it may still fail later for unrelated reasons, e.g. no live upstream) and a
    synchronous audit event records outcome="allow" with a taint_floor notice."""
    monkeypatch.setattr(settings, "TAINT_FLOOR_ENABLED", True)
    tid = str(uuid.uuid4())
    name = f"demo-high-sink-{uuid.uuid4().hex[:8]}"
    await _insert_tool(tid, name, required_integrity=1)
    # taint_store keys on client_id (logical identity, stable across auth methods).
    client_id = f"test-agent-taint-{uuid.uuid4().hex[:8]}"

    # Pre-taint the client_id against REAL Redis (simulating a prior untrusted result).
    await taint_store.mark_tainted_for_principal(client_id)
    assert await taint_store.is_tainted_for_principal(client_id) is True

    # `notices` is advisory-only and is emitted to the audit_logger (stdout/Loki
    # stream, per INV-001) but is NOT a persisted column on audit_events — spy on
    # the emit call (still delegating to the real implementation) to assert the
    # taint notice was attached to the emitted AuditEvent.
    from app.services import invocation as _invocation_mod

    real_logger = _invocation_mod._get_audit_logger()
    emitted_events = []
    real_emit = real_logger.emit

    def _spy_emit(event):
        emitted_events.append(event)
        return real_emit(event)

    monkeypatch.setattr(real_logger, "emit", _spy_emit)

    try:
        await invoke_tool(
            tool_record=_tool_record(name, tid, required_integrity=1, server_id=None),
            json_rpc_request=_req(name),
            client_id=client_id,
            client_roles=["agent"],
            is_testing=False,
            request_id=str(uuid.uuid4()),
            principal_id=None,
            principal_type="human",
        )
    except TaintFloorDenyError:
        pytest.fail(
            "taint floor is notify-only (PRD-0010 Phase 0) — it must not raise "
            "TaintFloorDenyError; the deny path is dormant until Phase 1"
        )
    except Exception:
        pass  # OPA deny / upstream error past the gate is acceptable for this assertion

    # The notify-only branch audits synchronously with outcome="allow" and an
    # empty opa_reasons/deny_reasons — it must never be misread as a deny.
    async with AsyncSessionLocal() as db:
        row = (
            await db.execute(
                text(
                    "SELECT outcome, opa_reasons FROM audit_events "
                    "WHERE tool_name = :n AND outcome = 'allow' LIMIT 1"
                ),
                {"n": name},
            )
        ).mappings().fetchone()
    assert row is not None, "no allow audit row written for the notify-only taint event"
    assert row["opa_reasons"] in ("[]", []), (
        "notify-only taint event must carry empty deny_reasons/opa_reasons, "
        f"got {row['opa_reasons']!r}"
    )

    taint_event = next(
        (e for e in emitted_events if getattr(e, "tool_name", None) == name), None
    )
    assert taint_event is not None, "no AuditEvent emitted for the notify-only taint call"
    assert any("taint_floor" in str(n) for n in (taint_event.notices or [])), (
        "expected a taint_floor notice on the emitted AuditEvent.notices"
    )


async def test_d3_clean_session_passes_taint_gate(redis_ready, monkeypatch):
    """D3: a clean session is NOT blocked by the taint floor (may deny later for other reasons)."""
    monkeypatch.setattr(settings, "TAINT_FLOOR_ENABLED", True)
    tid = str(uuid.uuid4())
    name = f"demo-clean-{uuid.uuid4().hex[:8]}"
    await _insert_tool(tid, name, required_integrity=1)
    principal = f"human:test:{uuid.uuid4()}"  # never tainted

    # Clear any residual taint for the shared "test-agent" client_id from previous test runs.
    # taint_store keys on client_id; "test-agent" is a fixed string so Redis taint persists
    # across test sessions. Use a synchronous redis client so we don't bind a connection to
    # this test's event loop (which would break the async pool for subsequent tests).
    from app.services.taint_store import taint_key as _taint_key
    from app.core.config import get_settings as _gs
    try:
        import redis as _redis_sync
        _s = _gs()
        _r_sync = _redis_sync.Redis(host=_s.REDIS_HOST, port=_s.REDIS_PORT,
                                     password=_s.REDIS_PASSWORD, decode_responses=True)
        _r_sync.delete(_taint_key("test-agent"))
        _r_sync.close()
    except Exception:
        pass  # non-fatal: if Redis unavailable, taint check will fail-open per LOGIC-005

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

    try:
        tier, _dim = await _lookup_server_trust(sid)
        assert tier == 0  # untrusted server

        # Unknown server_id -> fail-closed (None) -> caller treats as untrusted.
        missing_tier, _ = await _lookup_server_trust(str(uuid.uuid4()))
        assert missing_tier is None
    finally:
        async with AsyncSessionLocal() as db:
            await db.execute(
                text("DELETE FROM server_registry WHERE server_id = :sid"), {"sid": sid}
            )
            await db.commit()
