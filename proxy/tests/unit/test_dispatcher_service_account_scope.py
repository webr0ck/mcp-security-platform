"""
WP-A2 (CR-13): service_account mode's `scope` field is now validated against
SERVICE_ACCOUNT_ALLOWED_SCOPES before the Keycloak service-account token is
requested — independent of kc_token_exchange's audience allowlist.

Required regression coverage: existing lab service_account tools (lab-gitea,
lab-grafana-mcp, lab-wazuh) default to scope='openid' and must still invoke
green after this change.
"""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.credential_broker.dispatcher import (
    CredentialInjectionError,
    dispatch_credential_injection,
)

_DECRYPT = "app.credential_broker.approaches.approach_a.decrypt_credential"
_GET_SA_TOKEN = "app.credential_broker.keycloak_client.get_service_account_token"


def _tool(**over) -> dict:
    base = {
        "tool_id": "t-sa",
        "name": "lab-gitea",
        "service_name": "lab-gitea",
        "injection_mode": "service_account",
        "inject_header": "Authorization",
        "inject_prefix": "Bearer",
        "kc_client_id": "lab-gitea-client",
        # kc_token_audience is reused as the service_account `scope` field —
        # defaults to "openid" when unset (dispatcher.py behavior, unchanged).
    }
    base.update(over)
    return base


def _mock_broker():
    return patch("app.services.invocation.broker_instance", MagicMock())


@pytest.mark.asyncio
async def test_default_openid_scope_still_invokes_green():
    """Regression: no kc_token_audience set -> defaults to 'openid' -> must
    still pass the new scope-set validator and reach get_service_account_token."""
    with _mock_broker(), \
         patch(_DECRYPT, AsyncMock(return_value="client-secret")), \
         patch(_GET_SA_TOKEN, AsyncMock(return_value="sa-token-123")) as mock_get_token:
        headers = await dispatch_credential_injection(
            tool_record=_tool(),
            client_id="agent-1",
        )
    assert headers == {"Authorization": "Bearer sa-token-123"}
    mock_get_token.assert_awaited_once()
    _, kwargs = mock_get_token.call_args
    assert kwargs["scope"] == "openid"


@pytest.mark.asyncio
async def test_lab_grafana_and_wazuh_default_scope_pass():
    """Same regression for the other two named lab tools."""
    for name in ("lab-grafana-mcp", "lab-wazuh"):
        with _mock_broker(), \
             patch(_DECRYPT, AsyncMock(return_value="client-secret")), \
             patch(_GET_SA_TOKEN, AsyncMock(return_value="sa-token")):
            headers = await dispatch_credential_injection(
                tool_record=_tool(name=name, service_name=name),
                client_id="agent-1",
            )
        assert headers == {"Authorization": "Bearer sa-token"}


@pytest.mark.asyncio
async def test_disallowed_scope_rejected_fail_closed():
    """A scope token outside SERVICE_ACCOUNT_ALLOWED_SCOPES (e.g. 'admin')
    must fail closed before a token is ever requested from Keycloak."""
    with _mock_broker(), \
         patch(_DECRYPT, AsyncMock(return_value="client-secret")), \
         patch(_GET_SA_TOKEN, AsyncMock(return_value="sa-token")) as mock_get_token:
        with pytest.raises(CredentialInjectionError):
            await dispatch_credential_injection(
                tool_record=_tool(kc_token_audience="openid admin"),
                client_id="agent-1",
            )
    mock_get_token.assert_not_awaited()


@pytest.mark.asyncio
async def test_scope_validation_independent_of_audience_allowlist(monkeypatch):
    """Even if KC_TOKEN_EXCHANGE_ALLOWED_AUDIENCES is narrowed to something
    that does NOT include 'openid', service_account's scope='openid' must
    still pass — the two allowlists are independent dimensions."""
    from app.core.config import get_settings

    monkeypatch.setattr(
        get_settings(), "KC_TOKEN_EXCHANGE_ALLOWED_AUDIENCES", "lab-tickets", raising=False
    )
    with _mock_broker(), \
         patch(_DECRYPT, AsyncMock(return_value="client-secret")), \
         patch(_GET_SA_TOKEN, AsyncMock(return_value="sa-token")):
        headers = await dispatch_credential_injection(
            tool_record=_tool(),
            client_id="agent-1",
        )
    assert headers == {"Authorization": "Bearer sa-token"}
