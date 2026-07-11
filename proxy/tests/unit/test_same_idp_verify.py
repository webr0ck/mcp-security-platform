"""
Unit tests — WP-A6 Finding 2: same-IdP token-validation probe
(app/services/same_idp_verify.py).

A real deployed MCP server isn't available in unit tests, so these mock the
httpx transport and assert the probe's own logic: which requests it sends,
how it classifies a response as "rejected" vs not, and the overall verdict.
"""
from __future__ import annotations

from unittest.mock import AsyncMock, patch

import httpx
import jwt as pyjwt
import pytest

from app.services import same_idp_verify as svc

pytestmark = pytest.mark.unit


def _fake_client(responses: list[httpx.Response]):
    """Returns an async-context-manager stand-in whose .post() yields the
    given responses in order (one per probe call)."""
    client = AsyncMock()
    client.__aenter__.return_value = client
    client.__aexit__.return_value = False
    client.post = AsyncMock(side_effect=responses)
    return client


def _error_response(url: str) -> httpx.Response:
    return httpx.Response(200, json={"jsonrpc": "2.0", "error": {"code": -32001, "message": "unauthorized"}}, request=httpx.Request("POST", url))


def _success_response(url: str) -> httpx.Response:
    return httpx.Response(200, json={"jsonrpc": "2.0", "result": {"tools": []}}, request=httpx.Request("POST", url))


def _http_401(url: str) -> httpx.Response:
    return httpx.Response(401, request=httpx.Request("POST", url))


@pytest.mark.asyncio
async def test_all_three_probes_rejected_is_a_pass():
    url = "http://lab-echo:8000/mcp"
    responses = [_http_401(url), _error_response(url), _error_response(url)]
    with patch("httpx.AsyncClient", return_value=_fake_client(responses)):
        result = await svc.run_same_idp_verify_probe(server_url=url, approved_audience="lab-tickets")
    assert result.all_rejected is True
    assert {p.name for p in result.probes} == {"missing_token", "wrong_audience", "expired_token"}


@pytest.mark.asyncio
async def test_a_server_that_accepts_a_bad_token_fails_the_probe():
    """CORE ACCEPTANCE TEST: a server that does NOT validate audience must be
    caught — the probe must NOT report all_rejected=True."""
    url = "http://broken-server:8000/mcp"
    responses = [_http_401(url), _success_response(url), _error_response(url)]  # wrong_audience wrongly accepted
    with patch("httpx.AsyncClient", return_value=_fake_client(responses)):
        result = await svc.run_same_idp_verify_probe(server_url=url, approved_audience="lab-tickets")
    assert result.all_rejected is False
    wrong_aud = next(p for p in result.probes if p.name == "wrong_audience")
    assert wrong_aud.rejected is False


@pytest.mark.asyncio
async def test_missing_token_probe_sends_no_authorization_header():
    url = "http://lab-echo:8000/mcp"
    responses = [_http_401(url), _error_response(url), _error_response(url)]
    client = _fake_client(responses)
    with patch("httpx.AsyncClient", return_value=client):
        await svc.run_same_idp_verify_probe(server_url=url, approved_audience="lab-tickets")
    first_call_kwargs = client.post.call_args_list[0].kwargs
    assert "Authorization" not in first_call_kwargs.get("headers", {})


@pytest.mark.asyncio
async def test_wrong_audience_probe_token_has_mismatched_aud():
    url = "http://lab-echo:8000/mcp"
    responses = [_http_401(url), _error_response(url), _error_response(url)]
    client = _fake_client(responses)
    with patch("httpx.AsyncClient", return_value=client):
        await svc.run_same_idp_verify_probe(server_url=url, approved_audience="lab-tickets")
    second_call_kwargs = client.post.call_args_list[1].kwargs
    token = second_call_kwargs["headers"]["Authorization"].removeprefix("Bearer ")
    claims = pyjwt.decode(token, options={"verify_signature": False})
    assert claims["aud"] != "lab-tickets"


@pytest.mark.asyncio
async def test_expired_token_probe_has_exp_in_the_past():
    url = "http://lab-echo:8000/mcp"
    responses = [_http_401(url), _error_response(url), _error_response(url)]
    client = _fake_client(responses)
    with patch("httpx.AsyncClient", return_value=client):
        await svc.run_same_idp_verify_probe(server_url=url, approved_audience="lab-tickets")
    third_call_kwargs = client.post.call_args_list[2].kwargs
    token = third_call_kwargs["headers"]["Authorization"].removeprefix("Bearer ")
    claims = pyjwt.decode(token, options={"verify_signature": False, "verify_exp": False})
    assert claims["aud"] == "lab-tickets"  # correct audience, ONLY exp is wrong
    import time
    assert claims["exp"] < time.time()


@pytest.mark.asyncio
async def test_connection_failure_counts_as_not_rejected_not_a_crash():
    """An unreachable server must not be misreported as 'verified' — a
    connection error is infrastructure failure, not proof of validation."""
    url = "http://unreachable:8000/mcp"
    client = AsyncMock()
    client.__aenter__.return_value = client
    client.__aexit__.return_value = False
    client.post = AsyncMock(side_effect=httpx.ConnectError("no route", request=httpx.Request("POST", url)))
    with patch("httpx.AsyncClient", return_value=client):
        result = await svc.run_same_idp_verify_probe(server_url=url, approved_audience="lab-tickets")
    assert result.all_rejected is False
    assert all(not p.rejected for p in result.probes)
