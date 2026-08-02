"""
Startup subsystem visibility in /health.

lifespan() starts eight background subsystems, each wrapped in
`except Exception: logger.warning(...)`. Fail-graceful startup is deliberate; the
problem was that a failure existed ONLY as a stdout line, so /health reported "ok"
while OPA grant reconciliation had silently stopped on a fail-closed platform.
"""
import pytest

from app.core import startup_state


@pytest.fixture(autouse=True)
def _clean():
    startup_state.reset()
    yield
    startup_state.reset()


class TestStartupState:
    def test_empty_by_default(self):
        assert startup_state.snapshot() == {}
        assert startup_state.degraded_required() == []

    def test_records_and_snapshots(self):
        startup_state.record("registry", "ok", required=True)
        snap = startup_state.snapshot()
        assert snap["registry"]["status"] == "ok"
        assert snap["registry"]["required"] is True

    def test_snapshot_is_a_copy(self):
        # A caller mutating the snapshot must not corrupt process state.
        startup_state.record("registry", "ok")
        startup_state.snapshot()["registry"]["status"] = "degraded"
        assert startup_state.snapshot()["registry"]["status"] == "ok"

    def test_only_required_degradations_are_alertable(self):
        startup_state.record("opa_data_sync", "degraded", "grants stale", required=True)
        startup_state.record("rescan_scheduler", "degraded", "boom")       # optional
        startup_state.record("trust_labeler", "disabled", "flag off")      # optional
        assert startup_state.degraded_required() == ["opa_data_sync"]

    def test_disabled_required_subsystem_still_alerts(self):
        # The credential broker with no VAULT_TOKEN is "disabled", not "degraded", but
        # every credential-injecting tool then fails closed at call time — an operator
        # must see that, so anything not-ok on a required subsystem counts.
        startup_state.record("credential_broker", "disabled", "VAULT_TOKEN empty", required=True)
        assert startup_state.degraded_required() == ["credential_broker"]

    def test_required_ok_does_not_alert(self):
        startup_state.record("opa_data_sync", "ok", required=True)
        assert startup_state.degraded_required() == []


class TestHealthReporting:
    """The /health contract: report degradation, do NOT restart-loop the pod for it."""

    @pytest.mark.asyncio
    async def test_degraded_subsystem_downgrades_status_but_keeps_200(self, monkeypatch):
        import app.routers.health as h

        async def _true():
            return True

        monkeypatch.setattr(h, "check_database_health", _true)
        monkeypatch.setattr(h.redis_pool, "ping", _true)
        monkeypatch.setattr(h, "_check_opa", _true)
        monkeypatch.setattr(h, "_check_ollama", _true)

        startup_state.record("opa_data_sync", "degraded", "grants stale", required=True)

        resp = await h.liveness()
        import json
        body = json.loads(resp.body)

        # Visible...
        assert body["status"] == "degraded"
        assert body["degraded_subsystems"] == ["opa_data_sync"]
        assert body["subsystems"]["opa_data_sync"]["detail"] == "grants stale"
        # ...but the proxy is still serving and denying correctly, so liveness must not
        # fail and restart-loop it. This is the whole point of the split.
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_all_ok_reports_ok(self, monkeypatch):
        import app.routers.health as h
        import json

        async def _true():
            return True

        monkeypatch.setattr(h, "check_database_health", _true)
        monkeypatch.setattr(h.redis_pool, "ping", _true)
        monkeypatch.setattr(h, "_check_opa", _true)
        monkeypatch.setattr(h, "_check_ollama", _true)
        startup_state.record("opa_data_sync", "ok", required=True)

        resp = await h.liveness()
        body = json.loads(resp.body)
        assert body["status"] == "ok"
        assert "degraded_subsystems" not in body
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_dead_critical_dependency_still_503s(self, monkeypatch):
        import app.routers.health as h

        async def _true():
            return True

        async def _false():
            return False

        monkeypatch.setattr(h, "check_database_health", _false)
        monkeypatch.setattr(h.redis_pool, "ping", _true)
        monkeypatch.setattr(h, "_check_opa", _true)
        monkeypatch.setattr(h, "_check_ollama", _true)

        resp = await h.liveness()
        assert resp.status_code == 503
