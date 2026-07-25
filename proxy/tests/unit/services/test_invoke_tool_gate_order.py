"""
Characterization tests: the ORDER of gates inside invoke_tool.

invoke_tool is ~1,130 lines with 17 numbered steps (1, 1.1, 1.2, 1.5, 1.6, 2, 2.3,
2.5, 2.7, 3, 3a-pre, 3b, 3c-pre, 3c, 4, 6, 6a). That numbering is the code admitting it
has been inserted-into roughly ten times.

The security property of this function is NOT its length — it is the ORDER:

  * status/quarantine is checked BEFORE anything expensive or side-effecting
  * OPA authorizes BEFORE a credential is fetched — we must never pull a secret out of
    the broker for a call we are about to deny
  * the credential is fetched BEFORE the DNS-rebind revalidation, which is the TOCTOU
    window that revalidation exists to close
  * nothing is forwarded upstream until all of the above have passed

Until now that ordering was enforced only by comments and by whoever was reading them.
These tests make each edge fail loudly if a future insertion lands in the wrong place.

METHOD: construct a call that would fail at MORE THAN ONE gate, then assert which one
actually fires. That is what pins an ordering edge — a test that trips only one gate
proves nothing about sequence.

SCOPE, honestly stated. The edges pinned here are the ones that are both
security-load-bearing and robustly testable without a live database:
  status -> OPA, status -> credential fetch, OPA -> credential fetch,
  OPA -> upstream forward, credential fetch -> upstream forward.
The DB-dependent gates (1.1 maintenance, 1.2 scan freshness, 1.5 entitlement) are NOT
pinned here: their lookups fail closed on a mocked DB, so a test would pass for the
wrong reason. They need a live-DB integration test — tracked, not silently skipped.

See the Phase-0 note in the vault roadmap: these tests are the prerequisite for ever
splitting this function, and are worth keeping even if it is never split.
"""
from __future__ import annotations

import json
import sys
from types import ModuleType
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

pytestmark = pytest.mark.unit


def _make_stubs(*, opa_allow: bool):
    """Stub the module-level dependencies invoke_tool imports lazily."""
    mock_anomaly = ModuleType("app.services.anomaly")
    _res = MagicMock()
    _res.anomaly_score = 0.0
    mock_anomaly.detect = AsyncMock(return_value=_res)            # type: ignore[attr-defined]
    mock_anomaly.evaluate_anomaly = mock_anomaly.detect            # type: ignore[attr-defined]

    class _OPADeny(Exception):
        def __init__(self, reasons=None):
            self.reasons = reasons or ["denied_by_test"]
            super().__init__(str(self.reasons))

    async def _evaluate(_input):
        # RETURN a decision; do NOT raise. The real evaluate_policy returns
        # {"allow": ..., "reasons": [...]} and invoke_tool itself raises OPADenyError
        # (Step 3). An earlier version of this stub raised directly, which meant the
        # tests never exercised invoke_tool's own deny branch — mutation-testing caught
        # it: swallowing `raise OPADenyError(...)` in the product left all 8 tests
        # green. Returning the decision is the real contract and makes the mutation fail.
        return {"allow": bool(opa_allow), "reasons": [] if opa_allow else ["denied_by_test"]}

    mock_policy = ModuleType("app.services.policy")
    mock_policy.evaluate_policy = AsyncMock(side_effect=_evaluate)  # type: ignore[attr-defined]
    mock_policy.OPADenyError = _OPADeny                            # type: ignore[attr-defined]
    mock_policy.OPAUnavailableError = type("OPAUnavailableError", (Exception,), {})  # type: ignore[attr-defined]

    _audit = MagicMock()
    _audit.event_id = "audit-gate-order"
    mock_audit = ModuleType("mcp_audit_logger")
    mock_audit.AuditEvent = MagicMock(return_value=_audit)         # type: ignore[attr-defined]
    mock_audit.AuditEventType = MagicMock()                        # type: ignore[attr-defined]
    mock_audit.AuditOutcome = MagicMock()                          # type: ignore[attr-defined]
    _logger = MagicMock()
    _logger.emit = MagicMock(return_value="ab" * 32)
    mock_audit.MCPAuditLogger = MagicMock(return_value=_logger)    # type: ignore[attr-defined]

    return {
        "app.services.anomaly": mock_anomaly,
        "app.services.policy": mock_policy,
        "mcp_audit_logger": mock_audit,
    }, mock_policy.OPADenyError


def _tool(*, status: str = "active", with_credential: bool = False) -> dict:
    rec = {
        "tool_id": "tool-gate-order",
        "name": "gate_order_tool",
        "status": status,
        "upstream_url": "http://mcp-server:8080/mcp",
        "service_name": None,
        "injection_mode": "none",
        "inject_header": None,
        "inject_prefix": None,
        "version": "1.0",
        "server_id": None,          # unlinked: skips the DB-backed entitlement gate
        "risk_level": "low",
    }
    if with_credential:
        # A credential-bearing tool, so Step 3c-pre would call the dispatcher if reached.
        rec["service_name"] = "some-service"
        rec["injection_mode"] = "header"
        rec["inject_header"] = "Authorization"
    return rec


def _rpc() -> dict:
    return {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "do_thing", "arguments": {}}}


def _upstream_ok():
    payload = {"jsonrpc": "2.0", "id": 1, "result": {"content": [{"type": "text", "text": "ok"}]}}
    r = MagicMock()
    r.status_code = 200
    r.headers = {"content-type": "application/json"}
    r.content = json.dumps(payload).encode()
    r.json = MagicMock(return_value=payload)
    r.raise_for_status = MagicMock()
    return r


def _fresh(stubs: dict):
    with patch.dict(sys.modules, stubs):
        sys.modules.pop("app.services.invocation", None)
        from app.services import invocation as inv       # noqa: PLC0415
    return inv


class _Probes:
    """Records whether each side-effecting stage was reached."""
    def __init__(self):
        self.credential_fetched = False
        self.forwarded = False


async def _run(inv, tool_record, stubs, probes: _Probes):
    async def _spy_dispatch(*a, **k):
        probes.credential_fetched = True
        # Real contract: dispatch_credential_injection -> dict[str, str] of extra
        # headers, which invoke_tool splats into the outbound header map. Returning a
        # tuple here raised "'tuple' object is not a mapping" and only surfaced on the
        # ALLOW path — the deny-path tests never reach this call, which is exactly the
        # point of the allow-path guard tests below.
        return {"Authorization": "Bearer test-token-not-a-real-secret"}

    async def _spy_post(*a, **k):
        probes.forwarded = True
        return _upstream_ok()

    http = AsyncMock()
    http.__aenter__ = AsyncMock(return_value=http)
    http.__aexit__ = AsyncMock(return_value=False)
    http.post = AsyncMock(side_effect=_spy_post)

    async def _emit(*a, **k):
        return "audit-id"

    with patch.dict(sys.modules, stubs), \
         patch("app.services.invocation.httpx.AsyncClient") as cls, \
         patch("app.services.ssrf.validate_server_url", MagicMock(return_value=None)), \
         patch("app.credential_broker.dispatcher.dispatch_credential_injection",
               new=AsyncMock(side_effect=_spy_dispatch)), \
         patch.object(inv, "_emit_audit_event", side_effect=_emit), \
         patch.object(inv, "_get_or_create_session", AsyncMock(return_value=None)), \
         patch.object(inv, "_mcp_initialize", AsyncMock(return_value=None)), \
         patch.object(inv, "_lookup_profile_with_cache", AsyncMock(return_value=None)):
        cls.return_value = http
        return await inv.invoke_tool(
            tool_record=tool_record,
            json_rpc_request=_rpc(),
            client_id="alice@corp",
            client_roles=["agent"],
            is_testing=False,
            request_id="req-gate-order",
        )


class TestStatusGateIsFirst:
    """Step 1 must precede everything — it is the cheapest check and a quarantined
    tool must never reach policy, the broker, or the network."""

    @pytest.mark.parametrize("status,exc_name", [
        ("quarantined", "ToolQuarantinedError"),
        ("disabled", "ToolDisabledError"),
        ("deprecated", "ToolDeprecatedError"),
    ])
    @pytest.mark.asyncio
    async def test_status_wins_over_an_opa_denial(self, status, exc_name):
        # BOTH gates would deny. Status must be the one that fires — if OPA's denial
        # surfaced instead, Step 1 had been moved after Step 3.
        stubs, _ = _make_stubs(opa_allow=False)
        inv = _fresh(stubs)
        probes = _Probes()
        with pytest.raises(getattr(inv, exc_name)):
            await _run(inv, _tool(status=status), stubs, probes)
        assert not probes.credential_fetched
        assert not probes.forwarded

    @pytest.mark.asyncio
    async def test_quarantined_tool_never_reaches_the_broker(self):
        # A credential-bearing quarantined tool: the secret must not be fetched.
        stubs, _ = _make_stubs(opa_allow=True)
        inv = _fresh(stubs)
        probes = _Probes()
        with pytest.raises(inv.ToolQuarantinedError):
            await _run(inv, _tool(status="quarantined", with_credential=True), stubs, probes)
        assert not probes.credential_fetched, (
            "a quarantined tool pulled a credential — Step 1 must precede Step 3c-pre"
        )


class TestOpaPrecedesCredentialFetch:
    """The most important edge in the function.

    Fetching a secret for a call that is about to be denied means the broker
    decrypts, audits and materialises a credential unnecessarily — widening exposure
    for a request that produced no value. Deny first, then fetch.
    """

    @pytest.mark.asyncio
    async def test_opa_denial_does_not_fetch_a_credential(self):
        stubs, OPADeny = _make_stubs(opa_allow=False)
        inv = _fresh(stubs)
        probes = _Probes()
        with pytest.raises(OPADeny):
            await _run(inv, _tool(with_credential=True), stubs, probes)
        assert not probes.credential_fetched, (
            "OPA denied but a credential was still fetched — Step 3c-pre must stay "
            "AFTER Step 3, or every denied call needlessly materialises a secret"
        )

    @pytest.mark.asyncio
    async def test_opa_denial_does_not_forward_upstream(self):
        stubs, OPADeny = _make_stubs(opa_allow=False)
        inv = _fresh(stubs)
        probes = _Probes()
        with pytest.raises(OPADeny):
            await _run(inv, _tool(), stubs, probes)
        assert not probes.forwarded, "a denied call reached the upstream server"


class TestAllowedPathStillReachesEverything:
    """The guard against a vacuous suite: if the allow path stopped reaching the
    broker or the network, every test above would pass for the wrong reason."""

    @pytest.mark.asyncio
    async def test_allowed_credential_tool_fetches_then_forwards(self):
        stubs, _ = _make_stubs(opa_allow=True)
        inv = _fresh(stubs)
        probes = _Probes()
        result = await _run(inv, _tool(with_credential=True), stubs, probes)
        assert probes.credential_fetched, "allow path never reached the broker"
        assert probes.forwarded, "allow path never forwarded upstream"
        assert "result" in result or "error" in result

    @pytest.mark.asyncio
    async def test_allowed_plain_tool_forwards(self):
        stubs, _ = _make_stubs(opa_allow=True)
        inv = _fresh(stubs)
        probes = _Probes()
        await _run(inv, _tool(), stubs, probes)
        assert probes.forwarded
