"""
Unit tests — WP-A6 Finding 3: ServiceAdapter contract + GenericServiceAdapter
reference implementation.
"""
from __future__ import annotations

from unittest.mock import AsyncMock, patch

import httpx
import pytest

from app.credential_broker.adapters.generic_service_adapter import GenericServiceAdapter
from app.credential_broker.adapters.service_adapter import (
    ProviderConfigError,
    RuntimeContext,
    ServiceAdapter,
)

pytestmark = pytest.mark.unit


def test_generic_service_adapter_satisfies_protocol():
    """Structural conformance check — the reference implementation must
    satisfy the ServiceAdapter Protocol without any adaptation."""
    adapter = GenericServiceAdapter()
    assert isinstance(adapter, ServiceAdapter)


def test_generic_adapter_no_discovery_fields_required():
    adapter = GenericServiceAdapter()
    assert adapter.required_oauth_fields() == []
    assert adapter.default_scopes() == []


def test_generic_adapter_validate_provider_config_accepts_empty():
    adapter = GenericServiceAdapter()
    adapter.validate_provider_config({})  # must not raise


def test_generic_adapter_validate_provider_config_rejects_bad_shape():
    adapter = GenericServiceAdapter()
    with pytest.raises(ProviderConfigError):
        adapter.validate_provider_config({"api_base_url": 12345})


@pytest.mark.asyncio
async def test_generic_adapter_post_enrollment_discovery_is_noop():
    adapter = GenericServiceAdapter()
    result = await adapter.post_enrollment_discovery("fake-token", {})
    assert result == []


def test_generic_adapter_select_resource_is_noop():
    adapter = GenericServiceAdapter()
    assert adapter.select_resource([], None) is None


def test_generic_adapter_build_runtime_context():
    adapter = GenericServiceAdapter()
    ctx = adapter.build_runtime_context({"api_base_url": "https://api.example.com"}, None)
    assert isinstance(ctx, RuntimeContext)
    assert ctx.adapter == "generic"
    assert ctx.api_base_url == "https://api.example.com"
    # Non-secret contract: to_dict() must never carry anything credential-shaped.
    d = ctx.to_dict()
    assert "secret" not in d and "token" not in d and "refresh" not in d


@pytest.mark.asyncio
async def test_generic_adapter_verify_access_noop_true_when_no_probe_endpoint():
    adapter = GenericServiceAdapter()
    ctx = RuntimeContext(adapter="generic", api_base_url=None)
    assert await adapter.verify_access("fake-token", ctx) is True


@pytest.mark.asyncio
async def test_generic_adapter_verify_access_calls_probe_endpoint():
    adapter = GenericServiceAdapter()
    ctx = RuntimeContext(adapter="generic", api_base_url="https://api.example.com/me")

    mock_response = httpx.Response(200, request=httpx.Request("GET", ctx.api_base_url))
    mock_client = AsyncMock()
    mock_client.__aenter__.return_value = mock_client
    mock_client.__aexit__.return_value = False
    mock_client.get = AsyncMock(return_value=mock_response)

    with patch("httpx.AsyncClient", return_value=mock_client):
        ok = await adapter.verify_access("fake-token", ctx)
    assert ok is True
    mock_client.get.assert_awaited_once()
    _, kwargs = mock_client.get.call_args
    assert kwargs["headers"]["Authorization"] == "Bearer fake-token"


@pytest.mark.asyncio
async def test_generic_adapter_verify_access_false_on_4xx():
    adapter = GenericServiceAdapter()
    ctx = RuntimeContext(adapter="generic", api_base_url="https://api.example.com/me")
    mock_response = httpx.Response(401, request=httpx.Request("GET", ctx.api_base_url))
    mock_client = AsyncMock()
    mock_client.__aenter__.return_value = mock_client
    mock_client.__aexit__.return_value = False
    mock_client.get = AsyncMock(return_value=mock_response)

    with patch("httpx.AsyncClient", return_value=mock_client):
        ok = await adapter.verify_access("fake-token", ctx)
    assert ok is False


def test_safe_probe_endpoint_returns_api_base_url():
    adapter = GenericServiceAdapter()
    ctx = RuntimeContext(adapter="generic", api_base_url="https://api.example.com")
    assert adapter.safe_probe_endpoint(ctx) == "https://api.example.com"
