"""
R6.1 — continuous attestation for self-hosted servers.

A self-hosted server was trusted forever on one point-in-time check: repo scanned,
reviewer approved, verification probes passed once at provide-url time. Changing the
registered URL was already guarded, but swapping what is served at the SAME url was
invisible, because tool discovery is idempotent-skip and never re-reads a name it has
already registered. Submit a clean repo, get approved, then serve something else.

THE COMPARISON MUST BE LIVE-VS-LIVE. The first implementation diffed a live probe
against tool_registry and reported drift for every tool of every server — registry
names are platform-side aliases and registry schemas are normalized rewrites, so the
two shapes are not comparable. Shipping it would have demoted the whole self-hosted
fleet on the first sweep. Unit fixtures that build both sides the same way CANNOT
catch that; it took running the sweep against the real lab. Hence
test_baseline_must_not_be_built_from_the_registry below, which pins the lesson.

Properties, and why each test exists:
  1. drift against the attested baseline demotes                 (the actual fix)
  2. an unreachable upstream does NOT demote                     (else one blip
     quarantines the whole fleet — a self-inflicted outage)
  3. no baseline yet -> record TOFU, never demote                (a first sweep must
     not mass-demote every pre-existing server)
"""
from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from app.services.server_lifecycle import live_schema_drift

pytestmark = pytest.mark.unit


_SCHEMA_A = {"type": "object", "properties": {"q": {"type": "string"}}}
_SCHEMA_B = {"type": "object", "properties": {"cmd": {"type": "string"}}}
_BASE = [{"name": "search", "schema": _SCHEMA_A}]


class TestDriftPredicate:
    def test_identical_is_not_drift(self):
        assert live_schema_drift(list(_BASE), list(_BASE)) == []

    def test_changed_schema_is_drift(self):
        assert live_schema_drift([{"name": "search", "schema": _SCHEMA_B}], _BASE) == ["search"]

    def test_vanished_tool_is_drift(self):
        assert live_schema_drift([], _BASE) == ["search"]

    def test_new_tool_is_drift(self):
        # Live-vs-live, so a tool appearing without review IS drift — the backend grew
        # capability the reviewer never saw. (Under the old registry-diff design this
        # had to be excluded, which is part of why that design was unsound.)
        live = _BASE + [{"name": "exec", "schema": _SCHEMA_B}]
        assert live_schema_drift(live, _BASE) == ["exec"]

    def test_key_order_is_not_drift(self):
        assert live_schema_drift(
            [{"name": "s", "schema": {"b": 2, "a": 1}}],
            [{"name": "s", "schema": {"a": 1, "b": 2}}],
        ) == [], "JSON key order must not count as drift"

    def test_baseline_accepts_a_json_string(self):
        # asyncpg may hand back jsonb as str depending on codec configuration.
        import json
        assert live_schema_drift(list(_BASE), json.dumps(_BASE)) == []

    def test_baseline_must_not_be_built_from_the_registry(self):
        # Regression pin for the bug that only the live lab caught. tool_registry stores
        # ALIASED names and NORMALIZED schemas; diffing those against a live probe
        # reports total drift. If someone re-points the baseline at snapshot_tool_schema
        # output, this fires.
        registry_shaped = [{"name": "echo-basic",
                            "schema": {"type": "object", "properties": {},
                                       "additionalProperties": False}}]
        live_shaped = [{"name": "echo_args", "schema": _SCHEMA_A}]
        assert live_schema_drift(live_shaped, registry_shaped) == ["echo-basic", "echo_args"], (
            "registry-shaped and live-shaped tool lists are not comparable — the "
            "attestation baseline must come from fetch_live_tool_schema, never from "
            "snapshot_tool_schema"
        )


def _row(**over):
    base = {"server_id": "srv-1", "name": "selfhosted-1",
            "upstream_url": "https://example.invalid/mcp", "upstream_allowlist_entry": None,
            "attested_tool_schema": _BASE, "attested_at": "2026-07-01T00:00:00Z"}
    base.update(over)
    return base


async def _sweep(*, live, row):
    """
    Run the sweep against one fake self-hosted server.

    Returns (request_change, record_baseline, drift_calls). The drift spy matters:
    asserting only "request_change was not awaited" does NOT prove the unreachable-skip
    works — with the None guard removed, the drift call raises, the per-server `except`
    swallows it, and the await count is 0 either way. Mutation testing caught exactly
    that. Asserting the drift check is never REACHED pins the real behaviour.
    """
    from app.services import rescan_scheduler as rs
    from app.services import server_lifecycle as sl

    session = AsyncMock()
    session.__aenter__ = AsyncMock(return_value=session)
    session.__aexit__ = AsyncMock(return_value=False)
    session.execute = AsyncMock(return_value=type(
        "R", (), {"mappings": lambda self: type("M", (), {"all": lambda self: [row]})()},
    )())

    req_change, record = AsyncMock(), AsyncMock()
    calls: list[tuple] = []
    _real = sl.live_schema_drift            # bind BEFORE patching, or the spy recurses

    def _spy(live_arg, base_arg):
        calls.append((live_arg, base_arg))
        return _real(live_arg, base_arg)

    with patch.object(rs, "AsyncSessionLocal", return_value=session), \
         patch("app.services.server_lifecycle.fetch_live_tool_schema",
               AsyncMock(return_value=live)), \
         patch("app.services.server_lifecycle.live_schema_drift", _spy), \
         patch("app.services.server_lifecycle.record_attestation_baseline", record), \
         patch("app.services.server_lifecycle.request_change_for_server", req_change):
        await rs._attest_self_hosted()
    return req_change, record, calls


class TestSweep:
    @pytest.mark.asyncio
    async def test_drift_demotes_the_server(self):
        req, rec, calls = await _sweep(live=[{"name": "search", "schema": _SCHEMA_B}], row=_row())
        assert calls, "the sweep never reached the drift check — the test proves nothing"
        assert req.await_count == 1, "a swapped backend was not demoted for re-review"
        # asserted_ip_only must be False: that path can AUTO-APPROVE on a schema match,
        # which is exactly the wrong outcome for a drift we just detected.
        assert req.await_args.kwargs["asserted_ip_only"] is False
        assert rec.await_count == 0, "a drifted surface must never be recorded as the baseline"

    @pytest.mark.asyncio
    async def test_unreachable_upstream_does_not_demote(self):
        req, rec, calls = await _sweep(live=None, row=_row())
        assert calls == [], (
            "the drift check ran against an unreachable upstream — the None guard is gone "
            "and only an incidental exception is preventing a demotion"
        )
        assert req.await_count == 0, (
            "an unreachable upstream was demoted — one network blip would take down the "
            "entire self-hosted fleet"
        )
        assert rec.await_count == 0

    @pytest.mark.asyncio
    async def test_missing_baseline_records_tofu_and_does_not_demote(self):
        req, rec, calls = await _sweep(
            live=[{"name": "anything", "schema": _SCHEMA_B}],
            row=_row(attested_tool_schema=None, attested_at=None),
        )
        assert rec.await_count == 1, "no baseline was recorded for a never-attested server"
        assert req.await_count == 0, (
            "a server with no baseline was demoted — the first sweep after deploy would "
            "demote every pre-existing self-hosted server at once"
        )
        assert calls == [], "drift was evaluated against a null baseline"

    @pytest.mark.asyncio
    async def test_clean_server_is_left_alone(self):
        req, rec, calls = await _sweep(live=list(_BASE), row=_row())
        assert calls, "the sweep never reached the drift check — the test proves nothing"
        assert req.await_count == 0
        assert rec.await_count == 0
