"""PRD-0005 R-1 / SI-6 — LLM token fail-closed posture.

A configured-but-unobtainable token (Vault down / decrypt failure) MUST make the
auditor report llm_unavailable, and MUST NOT fall through to an unauthenticated
HTTP request. A token that IS obtainable must be sent as a Bearer header.
"""
from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from app.services.llm_config import LlmSettings

_EFF = LlmSettings(base_url="http://ollama:11434", model="m", timeout_seconds=5, enabled=True)


@pytest.mark.unit
@pytest.mark.asyncio
async def test_token_unobtainable_is_unavailable_no_http_call():
    """api_token() raising (decrypt/Vault failure) => llm_unavailable, no HTTP call."""
    from app.services import auditor

    http_ctor = MagicMock(side_effect=AssertionError("HTTP client must not be constructed"))
    with (
        patch("app.services.llm_config.effective", new=AsyncMock(return_value=_EFF)),
        patch("app.services.llm_config.api_token", new=AsyncMock(side_effect=RuntimeError("KMS down"))),
        patch("app.services.auditor.httpx.AsyncClient", new=http_ctor),
    ):
        result = await auditor.run_llm_analysis("t", "d", "{}")

    assert result["llm_unavailable"] is True
    http_ctor.assert_not_called()


@pytest.mark.unit
@pytest.mark.asyncio
async def test_token_present_is_sent_as_bearer():
    """A retrievable token is sent as an Authorization: Bearer header."""
    from app.services import auditor

    captured = {}

    class _Resp:
        def raise_for_status(self): pass
        def json(self): return {"response": "{}"}

    class _Client:
        def __init__(self, *a, **k): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def post(self, url, json=None, headers=None):
            captured["headers"] = headers
            return _Resp()

    with (
        patch("app.services.llm_config.effective", new=AsyncMock(return_value=_EFF)),
        patch("app.services.llm_config.api_token", new=AsyncMock(return_value="sk-tok")),
        patch("app.services.auditor.httpx.AsyncClient", new=_Client),
    ):
        result = await auditor.run_llm_analysis("t", "d", "{}")

    assert result.get("llm_unavailable") is not True
    assert captured["headers"] == {"Authorization": "Bearer sk-tok"}


@pytest.mark.unit
@pytest.mark.asyncio
async def test_no_token_sends_no_auth_header():
    """No token configured (local ollama) => no Authorization header, still works."""
    from app.services import auditor

    captured = {}

    class _Resp:
        def raise_for_status(self): pass
        def json(self): return {"response": "{}"}

    class _Client:
        def __init__(self, *a, **k): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def post(self, url, json=None, headers=None):
            captured["headers"] = headers
            return _Resp()

    with (
        patch("app.services.llm_config.effective", new=AsyncMock(return_value=_EFF)),
        patch("app.services.llm_config.api_token", new=AsyncMock(return_value=None)),
        patch("app.services.auditor.httpx.AsyncClient", new=_Client),
    ):
        await auditor.run_llm_analysis("t", "d", "{}")

    assert captured["headers"] is None
