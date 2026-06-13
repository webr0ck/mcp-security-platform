"""
Tests for the Wazuh MCP server (lab/mcp-servers/wazuh/server.py).

These tests mock the Wazuh REST API to verify:
  - Tool dispatch and parameter validation
  - Sensitive key stripping (_strip_sensitive)
  - ALLOW_ACTIVE_RESPONSE=false blocks active response
  - JWT caching logic
  - Error handling (HTTP errors from Wazuh API)

Run from repo root:
  python3 -m pytest lab/tests/test_wazuh_mcp.py -v --tb=short

NOTE on the `mcp` package: this test host does not install the `mcp` package
(it's a container-only dependency). We stub it in sys.modules at import time,
before exec_module runs, so the top-level `from mcp.server.fastmcp import FastMCP`
resolves to a no-op MagicMock. All tool functions under test are pure Python and
never touch the real MCP runtime.
"""
from __future__ import annotations

import importlib
import importlib.util
import sys
import types
from unittest.mock import MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Stub the `mcp` package before any server import can fail on it.
# This must run at module-collection time, before _load_server is called.
# ---------------------------------------------------------------------------

def _install_mcp_stub() -> None:
    """
    Insert minimal stubs for `mcp` and `mcp.server.fastmcp` so that
    `from mcp.server.fastmcp import FastMCP` in server.py resolves without
    the real package being installed.  The FastMCP class is a MagicMock;
    the @mcp.tool() decorator returns the decorated function unchanged so
    all tool functions remain directly callable in tests.
    """
    if "mcp" in sys.modules:
        return

    # Root mcp package
    mcp_mod = types.ModuleType("mcp")

    # mcp.server sub-package
    mcp_server = types.ModuleType("mcp.server")

    # FastMCP stub: @mcp.tool() must return the function unchanged
    class _FastMCPStub:
        def __init__(self, *args, **kwargs):
            pass

        def tool(self):
            """Decorator that returns the function as-is."""
            def decorator(fn):
                return fn
            return decorator

        def get_asgi_app(self):
            return MagicMock()

    # mcp.server.fastmcp sub-module
    mcp_server_fastmcp = types.ModuleType("mcp.server.fastmcp")
    mcp_server_fastmcp.FastMCP = _FastMCPStub

    sys.modules["mcp"] = mcp_mod
    sys.modules["mcp.server"] = mcp_server
    sys.modules["mcp.server.fastmcp"] = mcp_server_fastmcp


_install_mcp_stub()


# ---------------------------------------------------------------------------
# Import the server module without starting uvicorn
# ---------------------------------------------------------------------------

def _load_server(monkeypatch, allow_active: bool = False, api_password: str = "testpass"):
    """
    Import server.py with env vars set, re-importing from scratch each time
    so module-level globals (ALLOW_ACTIVE_RESPONSE, WAZUH_API_PASSWORD, JWT
    cache) reflect the env vars for that test.
    """
    monkeypatch.setenv("WAZUH_API_URL", "https://wazuh-test:55000")
    monkeypatch.setenv("WAZUH_API_USER", "wazuh")
    monkeypatch.setenv("WAZUH_API_PASSWORD", api_password)
    monkeypatch.setenv("VERIFY_SSL", "false")
    monkeypatch.setenv("ALLOW_ACTIVE_RESPONSE", "true" if allow_active else "false")
    monkeypatch.setenv("HOST", "127.0.0.1")
    monkeypatch.setenv("PORT", "8001")

    mod_name = "lab_wazuh_server"
    if mod_name in sys.modules:
        del sys.modules[mod_name]

    spec = importlib.util.spec_from_file_location(
        mod_name,
        "lab/mcp-servers/wazuh/server.py",
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def srv(monkeypatch):
    return _load_server(monkeypatch)


@pytest.fixture()
def srv_ar(monkeypatch):
    """Server with active response enabled."""
    return _load_server(monkeypatch, allow_active=True)


def _mock_api(srv, path_responses: dict):
    """Patch srv._api to return canned responses by path prefix."""
    def fake_api(method, path, **kwargs):
        for prefix, resp in path_responses.items():
            if path.startswith(prefix):
                return resp
        raise ValueError(f"Unexpected _api call: {method} {path}")
    return patch.object(srv, "_api", side_effect=fake_api)


# ---------------------------------------------------------------------------
# _strip_sensitive
# ---------------------------------------------------------------------------

class TestStripSensitive:
    def test_removes_password_key(self, srv):
        data = {"user": "alice", "password": "s3cret", "ip": "10.0.0.1"}
        out = srv._strip_sensitive(data, srv._SENSITIVE_KEYS)
        assert "password" not in out
        assert out["user"] == "alice"

    def test_nested_strip(self, srv):
        data = {"agent": {"id": "001", "hash": "abc123", "name": "agent1"}}
        out = srv._strip_sensitive(data, srv._SENSITIVE_KEYS)
        assert "hash" not in out["agent"]
        assert out["agent"]["name"] == "agent1"

    def test_list_items_stripped(self, srv):
        data = [{"name": "r1", "md5": "aabbcc"}, {"name": "r2", "sha256": "ff"}]
        out = srv._strip_sensitive(data, srv._SENSITIVE_KEYS)
        assert all("md5" not in item and "sha256" not in item for item in out)

    def test_non_dict_passthrough(self, srv):
        assert srv._strip_sensitive("hello", srv._SENSITIVE_KEYS) == "hello"
        assert srv._strip_sensitive(42, srv._SENSITIVE_KEYS) == 42

    def test_none_value_passthrough(self, srv):
        """None values must pass through unchanged (not crash)."""
        out = srv._strip_sensitive(None, srv._SENSITIVE_KEYS)
        assert out is None

    def test_integer_value_in_dict(self, srv):
        """Integer values inside dicts must not be stripped or crash."""
        data = {"level": 7, "count": 3, "password": "s3cret"}
        out = srv._strip_sensitive(data, srv._SENSITIVE_KEYS)
        assert out["level"] == 7
        assert out["count"] == 3
        assert "password" not in out

    def test_nested_list_of_dicts(self, srv):
        """List of dicts nested under a key must be recursively stripped."""
        data = {
            "agents": [
                {"id": "001", "token": "abc", "name": "a1"},
                {"id": "002", "sha256": "xyz", "name": "a2"},
            ]
        }
        out = srv._strip_sensitive(data, srv._SENSITIVE_KEYS)
        for agent in out["agents"]:
            assert "token" not in agent
            assert "sha256" not in agent
        assert out["agents"][0]["name"] == "a1"
        assert out["agents"][1]["id"] == "002"


# ---------------------------------------------------------------------------
# wazuh_cluster_health
# ---------------------------------------------------------------------------

class TestClusterHealth:
    def test_happy_path(self, srv):
        cluster_resp = {"data": {"enabled": "no", "name": ""}}
        info_resp = {"data": {"version": "4.9.1", "openssl_support": "yes"}}
        with _mock_api(srv, {
            "/cluster/status": cluster_resp,
            "/manager/info": info_resp,
        }):
            result = srv.wazuh_cluster_health()
        assert result["manager_version"] == "4.9.1"
        assert result["cluster_enabled"] is False

    def test_api_error_returns_error_key(self, srv):
        with patch.object(srv, "_api", side_effect=Exception("connection refused")):
            result = srv.wazuh_cluster_health()
        assert "error" in result


# ---------------------------------------------------------------------------
# wazuh_list_agents
# ---------------------------------------------------------------------------

class TestListAgents:
    def test_happy_path(self, srv):
        resp = {
            "data": {
                "affected_items": [{"id": "001", "name": "host1", "status": "active"}],
                "total_affected_items": 1,
            }
        }
        with _mock_api(srv, {"/agents": resp}):
            result = srv.wazuh_list_agents(limit=10)
        assert result["total"] == 1
        assert result["agents"][0]["name"] == "host1"

    def test_limit_clamped_at_max(self, srv):
        resp = {"data": {"affected_items": [], "total_affected_items": 0}}
        captured = {}

        def fake_api(method, path, params=None, **kwargs):
            captured["params"] = params or {}
            return resp

        with patch.object(srv, "_api", side_effect=fake_api):
            srv.wazuh_list_agents(limit=9999)
        assert captured["params"]["limit"] <= srv.MAX_LIMIT

    def test_api_error(self, srv):
        with patch.object(srv, "_api", side_effect=Exception("timeout")):
            result = srv.wazuh_list_agents()
        assert "error" in result


# ---------------------------------------------------------------------------
# wazuh_get_agent_detail
# ---------------------------------------------------------------------------

class TestGetAgentDetail:
    def test_found(self, srv):
        """
        Verifies that _strip_sensitive is called on items[0] (the agent dict),
        not the raw API response wrapper. The test asserts top-level 'id' is
        present and top-level 'password' is absent — which proves stripping ran
        on the unwrapped agent object, since the wrapper has no 'id' or 'password'
        at its top level.
        """
        resp = {
            "data": {
                "affected_items": [{"id": "001", "name": "host1", "password": "hidden"}],
                "total_affected_items": 1,
            }
        }
        with _mock_api(srv, {"/agents/001": resp}):
            result = srv.wazuh_get_agent_detail("001")
        # Result is the unwrapped agent, not the API wrapper
        assert result.get("id") == "001"
        assert "password" not in result  # stripped at items[0] level

    def test_not_found(self, srv):
        resp = {"data": {"affected_items": [], "total_affected_items": 0}}
        with _mock_api(srv, {"/agents/999": resp}):
            result = srv.wazuh_get_agent_detail("999")
        assert "error" in result

    def test_api_error(self, srv):
        with patch.object(srv, "_api", side_effect=Exception("network error")):
            result = srv.wazuh_get_agent_detail("001")
        assert "error" in result


# ---------------------------------------------------------------------------
# wazuh_list_alerts
# ---------------------------------------------------------------------------

class TestListAlerts:
    def test_happy_path(self, srv):
        resp = {
            "data": {
                "affected_items": [{"type": "ossec", "description": "Login failed"}],
                "total_affected_items": 1,
            }
        }
        with _mock_api(srv, {"/manager/logs": resp}):
            result = srv.wazuh_list_alerts(limit=5)
        assert result["total"] == 1
        assert "alerts" in result

    def test_api_error(self, srv):
        with patch.object(srv, "_api", side_effect=Exception("broken")):
            result = srv.wazuh_list_alerts()
        assert "error" in result

    def test_level_gte_adds_level_param(self, srv):
        """When level_gte > 0, the 'level' range param must be forwarded to _api."""
        resp = {
            "data": {
                "affected_items": [{"type": "ossec", "description": "Critical"}],
                "total_affected_items": 1,
            }
        }
        captured = {}

        def fake_api(method, path, params=None, **kwargs):
            captured["params"] = params or {}
            return resp

        with patch.object(srv, "_api", side_effect=fake_api):
            result = srv.wazuh_list_alerts(level_gte=7, limit=10)

        assert "alerts" in result
        assert "total" in result
        # level range MUST reach the API (bug fix: params dict now forwarded)
        assert captured["params"].get("level") == "7-15"
        assert captured["params"].get("type_log") == "all"


# ---------------------------------------------------------------------------
# wazuh_search_alerts
# ---------------------------------------------------------------------------

class TestSearchAlerts:
    def test_happy_path(self, srv):
        resp = {
            "data": {
                "affected_items": [{"description": "SSH brute force"}],
                "total_affected_items": 1,
            }
        }
        with _mock_api(srv, {"/manager/logs": resp}):
            result = srv.wazuh_search_alerts(query="SSH", minutes=30, limit=10)
        assert result["query"] == "SSH"
        assert result["minutes"] == 30
        assert "alerts" in result
        assert "total" in result

    def test_note_field_present(self, srv):
        """
        The 'note' field communicates the manager-buffer limitation honestly.
        It must always be present in the response, even when no alerts match.
        """
        resp = {"data": {"affected_items": [], "total_affected_items": 0}}
        with _mock_api(srv, {"/manager/logs": resp}):
            result = srv.wazuh_search_alerts(query="anything")
        assert "note" in result
        assert "indexer" in result["note"].lower() or "buffer" in result["note"].lower()

    def test_api_error(self, srv):
        with patch.object(srv, "_api", side_effect=Exception("indexer down")):
            result = srv.wazuh_search_alerts(query="test")
        assert "error" in result

    def test_minutes_clamped_at_max(self, srv):
        resp = {"data": {"affected_items": [], "total_affected_items": 0}}
        captured = {}

        def fake_api(method, path, params=None, **kwargs):
            captured["resp"] = resp
            return resp

        with patch.object(srv, "_api", side_effect=fake_api):
            result = srv.wazuh_search_alerts(query="x", minutes=99999, limit=5)
        # Function must not crash; minutes is clamped internally to 1440
        assert "alerts" in result

    def test_limit_applied_to_results(self, srv):
        """Result list must not exceed the requested limit."""
        items = [{"description": f"alert {i}"} for i in range(20)]
        resp = {"data": {"affected_items": items, "total_affected_items": 20}}
        with _mock_api(srv, {"/manager/logs": resp}):
            result = srv.wazuh_search_alerts(query="alert", limit=5)
        assert len(result["alerts"]) <= 5


# ---------------------------------------------------------------------------
# wazuh_list_decoders
# ---------------------------------------------------------------------------

class TestListDecoders:
    def test_happy_path(self, srv):
        resp = {
            "data": {
                "affected_items": [
                    {"name": "apache", "file": "apache.xml", "position": 0},
                    {"name": "sshd", "file": "sshd.xml", "position": 1},
                ],
                "total_affected_items": 2,
            }
        }
        with _mock_api(srv, {"/decoders": resp}):
            result = srv.wazuh_list_decoders()
        assert result["total"] == 2
        assert "decoders" in result
        assert result["decoders"][0]["name"] == "apache"

    def test_filename_filter_passed_as_glob(self, srv):
        """When filename is provided, it must be wrapped in '*...*' for glob matching."""
        resp = {"data": {"affected_items": [], "total_affected_items": 0}}
        captured = {}

        def fake_api(method, path, params=None, **kwargs):
            captured["params"] = params or {}
            return resp

        with patch.object(srv, "_api", side_effect=fake_api):
            srv.wazuh_list_decoders(filename="apache")

        assert captured["params"].get("filename") == "*apache*"

    def test_api_error(self, srv):
        with patch.object(srv, "_api", side_effect=Exception("connection reset")):
            result = srv.wazuh_list_decoders()
        assert "error" in result

    def test_limit_clamped(self, srv):
        resp = {"data": {"affected_items": [], "total_affected_items": 0}}
        captured = {}

        def fake_api(method, path, params=None, **kwargs):
            captured["params"] = params or {}
            return resp

        with patch.object(srv, "_api", side_effect=fake_api):
            srv.wazuh_list_decoders(limit=9999)

        assert captured["params"]["limit"] <= srv.MAX_LIMIT


# ---------------------------------------------------------------------------
# wazuh_get_rules
# ---------------------------------------------------------------------------

class TestGetRules:
    def test_happy_path(self, srv):
        resp = {
            "data": {
                "affected_items": [
                    {"id": 5501, "level": 7, "description": "Login failed", "groups": ["authentication"]}
                ],
                "total_affected_items": 1,
            }
        }
        with _mock_api(srv, {"/rules": resp}):
            result = srv.wazuh_get_rules(level_gte=7)
        assert result["total"] == 1
        assert result["rules"][0]["level"] == 7

    def test_limit_clamped(self, srv):
        resp = {"data": {"affected_items": [], "total_affected_items": 0}}
        captured = {}

        def fake_api(method, path, params=None, **kwargs):
            captured["params"] = params or {}
            return resp

        with patch.object(srv, "_api", side_effect=fake_api):
            srv.wazuh_get_rules(limit=500)
        assert captured["params"]["limit"] <= srv.MAX_LIMIT


# ---------------------------------------------------------------------------
# wazuh_run_active_response
# ---------------------------------------------------------------------------

class TestActiveResponse:
    def test_blocked_when_disabled(self, srv):
        result = srv.wazuh_run_active_response("001", "restart-ossec")
        assert "error" in result
        assert "disabled" in result["error"]

    def test_allowed_when_enabled(self, srv_ar):
        resp = {"message": "Active response sent"}
        with _mock_api(srv_ar, {"/active-response/001": resp}):
            result = srv_ar.wazuh_run_active_response("001", "restart-ossec")
        assert result["status"] == "triggered"
        assert result["agent_id"] == "001"

    def test_invalid_command_rejected(self, srv_ar):
        result = srv_ar.wazuh_run_active_response("001", "rm -rf /")
        assert "error" in result
        assert "invalid command" in result["error"]

    def test_api_error(self, srv_ar):
        with patch.object(srv_ar, "_api", side_effect=Exception("API down")):
            result = srv_ar.wazuh_run_active_response("001", "restart-ossec")
        assert "error" in result

    def test_api_non200_returns_error(self, srv_ar):
        """
        When allow_active=True but the Wazuh API call itself raises (e.g. due to
        raise_for_status on a 4xx/5xx), the tool must catch the exception and
        return an error dict rather than propagating the exception to the caller.
        """
        import httpx
        # Simulate an httpx HTTPStatusError (what raise_for_status raises)
        fake_request = MagicMock()
        fake_response = MagicMock()
        fake_response.status_code = 403
        http_err = httpx.HTTPStatusError(
            "403 Forbidden", request=fake_request, response=fake_response
        )
        with patch.object(srv_ar, "_api", side_effect=http_err):
            result = srv_ar.wazuh_run_active_response("001", "restart-ossec")
        assert "error" in result

    def test_empty_command_rejected(self, srv_ar):
        """Empty string command should fail the isalnum guard."""
        result = srv_ar.wazuh_run_active_response("001", "")
        assert "error" in result

    def test_command_with_only_dashes_rejected(self, srv_ar):
        """A command that is purely dashes/underscores with no alphanum chars is rejected."""
        result = srv_ar.wazuh_run_active_response("001", "---")
        assert "error" in result

    def test_hyphenated_command_accepted(self, srv_ar):
        """Valid hyphenated command names (e.g. 'restart-ossec') must be accepted."""
        resp = {"message": "OK"}
        with _mock_api(srv_ar, {"/active-response/001": resp}):
            result = srv_ar.wazuh_run_active_response("001", "restart-ossec")
        assert result.get("status") == "triggered"


# ---------------------------------------------------------------------------
# JWT caching
# ---------------------------------------------------------------------------

class TestJwtCache:
    def test_password_required_when_no_env(self, monkeypatch):
        """
        When WAZUH_API_PASSWORD is empty and no Authorization header is injected,
        _get_jwt must raise RuntimeError before any HTTP call is made.
        The tool (wazuh_cluster_health) catches the exception and returns {"error": ...}.

        Implementation note: the FakeClient below intentionally raises if any
        HTTP method is called. The test verifies the error appears BEFORE
        reaching the network, not after.
        """
        srv = _load_server(monkeypatch, api_password="")

        import httpx as _httpx

        class FakeClient:
            def __enter__(self):
                return self
            def __exit__(self, *a):
                pass
            def get(self, url, auth=None):
                raise AssertionError("should not reach Wazuh API — password check must fire first")
            def request(self, *a, **kw):
                raise AssertionError("should not reach Wazuh API — password check must fire first")

        with patch("httpx.Client", return_value=FakeClient()):
            result = srv.wazuh_cluster_health()

        assert "error" in result
        # The RuntimeError message from _get_jwt must propagate into the error string
        assert "password" in result["error"].lower() or "WAZUH_API_PASSWORD" in result["error"]

    def test_injected_bearer_bypasses_password_check(self, monkeypatch):
        """
        When the context var _request_auth carries a 'Bearer <token>', _get_jwt
        must return that token without checking WAZUH_API_PASSWORD and without
        making any HTTP call to /security/user/authenticate.
        """
        srv = _load_server(monkeypatch, api_password="")

        # Set the context var to a pre-injected token
        token_str = "Bearer injected-test-token-abc123"
        srv._request_auth.set(token_str)

        calls = []

        def fake_api(method, path, **kwargs):
            calls.append((method, path))
            if path == "/cluster/status":
                return {"data": {"enabled": "no", "name": ""}}
            if path == "/manager/info":
                return {"data": {"version": "4.9.1", "openssl_support": "yes"}}
            raise ValueError(f"Unexpected: {method} {path}")

        with patch.object(srv, "_api", side_effect=fake_api):
            result = srv.wazuh_cluster_health()

        # Tool should succeed; the injected token avoided the password error
        assert "error" not in result
        assert result["manager_version"] == "4.9.1"

    def test_cached_jwt_reused(self, monkeypatch):
        """
        Once _jwt_token is set and _jwt_expires_at is in the future, _get_jwt
        must return the cached token without a second HTTP call.
        """
        import time
        srv = _load_server(monkeypatch, api_password="testpass")

        # Pre-populate the cache
        srv._jwt_token = "cached-token-xyz"
        srv._jwt_expires_at = time.monotonic() + 800

        http_calls = []

        class FakeClient:
            def __enter__(self):
                return self
            def __exit__(self, *a):
                pass
            def get(self, url, **kwargs):
                http_calls.append(url)
                raise AssertionError("Should not hit authenticate endpoint when cache is valid")
            def request(self, method, url, headers=None, **kwargs):
                # Simulate a successful API response for cluster/status and manager/info
                m = MagicMock()
                m.raise_for_status = MagicMock()
                if "/cluster/status" in url:
                    m.json.return_value = {"data": {"enabled": "no", "name": ""}}
                elif "/manager/info" in url:
                    m.json.return_value = {"data": {"version": "4.9.1", "openssl_support": "yes"}}
                else:
                    m.json.return_value = {}
                return m

        with patch("httpx.Client", return_value=FakeClient()):
            result = srv.wazuh_cluster_health()

        assert not http_calls, "authenticate endpoint was called despite valid cache"
        assert "manager_version" in result


# ---------------------------------------------------------------------------
# agent_id validation (HIGH-2 fix: path traversal prevention)
# ---------------------------------------------------------------------------

class TestAgentIdValidation:
    def test_valid_agent_id_accepted(self, srv):
        resp = {
            "data": {
                "affected_items": [{"id": "001", "name": "host1"}],
                "total_affected_items": 1,
            }
        }
        with _mock_api(srv, {"/agents/001": resp}):
            result = srv.wazuh_get_agent_detail("001")
        assert result["id"] == "001"

    def test_path_traversal_rejected(self, srv):
        result = srv.wazuh_get_agent_detail("../security/users")
        assert "error" in result
        assert "invalid agent_id" in result["error"]

    def test_empty_agent_id_rejected(self, srv):
        result = srv.wazuh_get_agent_detail("")
        assert "error" in result

    def test_alpha_agent_id_rejected(self, srv):
        result = srv.wazuh_get_agent_detail("abc")
        assert "error" in result

    def test_active_response_path_traversal_rejected(self, srv_ar):
        result = srv_ar.wazuh_run_active_response("../manager/configuration", "restart-ossec")
        assert "error" in result
        assert "invalid agent_id" in result["error"]

    def test_numeric_string_with_leading_zeros_accepted(self, srv):
        resp = {"data": {"affected_items": [{"id": "007", "name": "bond"}], "total_affected_items": 1}}
        with _mock_api(srv, {"/agents/007": resp}):
            result = srv.wazuh_get_agent_detail("007")
        assert result["id"] == "007"


# ---------------------------------------------------------------------------
# Active response argument allowlist (MEDIUM-1 fix)
# ---------------------------------------------------------------------------

class TestActiveResponseArgValidation:
    def test_safe_args_accepted(self, srv_ar):
        resp = {"message": "done"}
        with _mock_api(srv_ar, {"/active-response/001": resp}):
            result = srv_ar.wazuh_run_active_response(
                "001", "firewall-drop", arguments=["10.0.0.1", "port-22"]
            )
        assert result["status"] == "triggered"

    def test_shell_injection_in_args_rejected(self, srv_ar):
        result = srv_ar.wazuh_run_active_response(
            "001", "firewall-drop", arguments=["10.0.0.1; rm -rf /"]
        )
        assert "error" in result
        assert "invalid argument" in result["error"]

    def test_too_many_args_rejected(self, srv_ar):
        result = srv_ar.wazuh_run_active_response(
            "001", "restart-ossec", arguments=["a"] * 11
        )
        assert "error" in result
        assert "too many arguments" in result["error"]

    def test_empty_args_list_accepted(self, srv_ar):
        resp = {"message": "done"}
        with _mock_api(srv_ar, {"/active-response/001": resp}):
            result = srv_ar.wazuh_run_active_response("001", "restart-ossec", arguments=[])
        assert result["status"] == "triggered"


# ---------------------------------------------------------------------------
# wazuh_list_decoders sensitive key stripping (MEDIUM-2 fix)
# ---------------------------------------------------------------------------

class TestDecoderStripping:
    def test_sensitive_keys_stripped_from_decoders(self, srv):
        resp = {
            "data": {
                "affected_items": [
                    {"name": "sshd", "file": "0005-sshd_decoders.xml", "token": "s3cret", "position": 0}
                ],
                "total_affected_items": 1,
            }
        }
        with _mock_api(srv, {"/decoders": resp}):
            result = srv.wazuh_list_decoders()
        assert "token" not in result["decoders"][0]
        assert result["decoders"][0]["name"] == "sshd"
