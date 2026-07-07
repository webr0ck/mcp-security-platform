"""
Unit tests — CR-06 (WP-B3 phase 6) machine-testable contract subset.

Covers app.services.contract_check.run_contract_check: valid initialize/
tools-list responses pass, shape violations are recorded (never raised),
and health/probe failures are recorded too. httpx calls are mocked — no
real server needed.
"""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from app.services import contract_check


def _mock_response(json_body: dict, status_code: int = 200) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status_code
    resp.headers = {"content-type": "application/json"}
    resp.json.return_value = json_body
    resp.raise_for_status = MagicMock()
    if status_code >= 400:
        resp.raise_for_status.side_effect = httpx.HTTPStatusError(
            "error", request=MagicMock(), response=resp,
        )
    return resp


class _FakeClient:
    """Sequenced fake httpx.AsyncClient — returns one canned response per call."""

    def __init__(self, responses: list):
        self._responses = list(responses)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def get(self, url, timeout=None):
        return self._responses.pop(0)

    async def post(self, url, json=None, headers=None, timeout=None):
        return self._responses.pop(0)


def _valid_initialize_response():
    return _mock_response({
        "jsonrpc": "2.0", "id": 1,
        "result": {
            "protocolVersion": "2024-11-05",
            "serverInfo": {"name": "test-server", "version": "1.0.0"},
            "capabilities": {},
        },
    })


def _valid_tools_list_response():
    return _mock_response({
        "jsonrpc": "2.0", "id": 2,
        "result": {"tools": [{"name": "echo", "description": "echoes input", "inputSchema": {}}]},
    })


def _health_response(status_code=200):
    return _mock_response({}, status_code=status_code)


@pytest.mark.asyncio
async def test_all_probes_pass():
    responses = [_health_response(), _valid_initialize_response(), _valid_tools_list_response()]
    with patch("httpx.AsyncClient", side_effect=lambda: _FakeClient([responses.pop(0)])):
        result = await contract_check.run_contract_check("http://127.0.0.1:8000/")

    assert result["health_ok"] is True
    assert result["initialize_ok"] is True
    assert result["tools_list_ok"] is True
    assert result["violations"] == []


@pytest.mark.asyncio
async def test_missing_protocol_version_is_a_violation_not_a_crash():
    bad_init = _mock_response({
        "jsonrpc": "2.0", "id": 1,
        "result": {"serverInfo": {"name": "test-server"}, "capabilities": {}},
    })
    responses = [_health_response(), bad_init, _valid_tools_list_response()]
    with patch("httpx.AsyncClient", side_effect=lambda: _FakeClient([responses.pop(0)])):
        result = await contract_check.run_contract_check("http://127.0.0.1:8000/")

    assert result["initialize_ok"] is False
    assert result["tools_list_ok"] is True
    assert any("initialize" in v for v in result["violations"])


@pytest.mark.asyncio
async def test_health_non_2xx_is_recorded_not_fatal():
    responses = [_health_response(status_code=503), _valid_initialize_response(), _valid_tools_list_response()]
    with patch("httpx.AsyncClient", side_effect=lambda: _FakeClient([responses.pop(0)])):
        result = await contract_check.run_contract_check("http://127.0.0.1:8000/")

    assert result["health_ok"] is False
    assert result["initialize_ok"] is True  # independent of health
    assert any("health" in v for v in result["violations"])


@pytest.mark.asyncio
async def test_tools_missing_name_field_violates_schema():
    bad_tools = _mock_response({
        "jsonrpc": "2.0", "id": 2,
        "result": {"tools": [{"description": "no name field"}]},
    })
    responses = [_health_response(), _valid_initialize_response(), bad_tools]
    with patch("httpx.AsyncClient", side_effect=lambda: _FakeClient([responses.pop(0)])):
        result = await contract_check.run_contract_check("http://127.0.0.1:8000/")

    assert result["tools_list_ok"] is False
    assert any("tools/list" in v for v in result["violations"])


@pytest.mark.asyncio
async def test_connection_error_never_raises():
    class _FailingClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        async def get(self, url, timeout=None):
            raise httpx.ConnectError("connection refused")

        async def post(self, url, json=None, headers=None, timeout=None):
            raise httpx.ConnectError("connection refused")

    with patch("httpx.AsyncClient", side_effect=lambda: _FailingClient()):
        result = await contract_check.run_contract_check("http://127.0.0.1:8000/")

    assert result["health_ok"] is False
    assert result["initialize_ok"] is False
    assert result["tools_list_ok"] is False
    assert len(result["violations"]) == 3
