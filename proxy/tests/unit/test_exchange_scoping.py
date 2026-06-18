# proxy/tests/unit/test_exchange_scoping.py
import pytest
from unittest.mock import AsyncMock, patch
from app.credential_broker.dispatcher import _inject_kc_token_exchange, CredentialInjectionError


@pytest.mark.asyncio
async def test_non_allowlisted_audience_denied_before_exchange():
    """S-6(b): audience not in allowlist must be rejected BEFORE hitting KC."""
    exchange_called = False

    async def fake_exchange(*args, **kwargs):
        nonlocal exchange_called
        exchange_called = True
        return "fake-token"

    with patch("app.credential_broker.keycloak_client.exchange_token", fake_exchange):
        tool = {"tool_id": "t1", "kc_token_audience": "grafana"}
        with pytest.raises(CredentialInjectionError, match="allowlist"):
            await _inject_kc_token_exchange(
                tool_record=tool,
                user_kc_token="some.jwt.token",
                inject_header="Authorization",
                inject_prefix="Bearer",
            )

    assert exchange_called is False, "exchange_token must NOT be called for non-allowlisted audience"
