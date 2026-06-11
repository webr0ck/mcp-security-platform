"""
Unit tests — Dispatcher injection mode handling (Tasks 3.4, 3.5)

Covers:
  Task 3.5 (AUTH-F11 / AUTH-R4):
    - oauth_user_token alias routes to the kc_token_exchange handler
    - kc_token_exchange canonical name works directly
    - The alias normalisation happens before enum parsing

  Task 3.4 (AUTH-R6):
    - passthrough mode is accepted by the dispatcher (returns {} without calling upstream)
    - entra_user_token is accepted by the dispatcher
    - ServerRegister model accepts passthrough and entra_user_token
    - ServerRegister rejects entra_user_token when ENTRA_TENANT_ID is not set
    - ServerCreate model accepts passthrough and entra_user_token
"""
from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from app.credential_broker.dispatcher import (
    CredentialInjectionError,
    InjectionMode,
    dispatch_credential_injection,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _tool(tool_id: str = "t-1", injection_mode: str | None = None) -> dict:
    return {
        "tool_id": tool_id,
        "name": "do_thing",
        "service_name": "test-svc",
        "injection_mode": injection_mode,
        "inject_header": "Authorization",
        "inject_prefix": "Bearer",
        "kc_token_audience": "upstream-api",
    }


def _mock_broker():
    sentinel = MagicMock()
    return patch("app.services.invocation.broker_instance", sentinel)


# ---------------------------------------------------------------------------
# Task 3.5: oauth_user_token alias → kc_token_exchange handler
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
@pytest.mark.unit
async def test_oauth_user_token_alias_routes_to_kc_exchange_handler():
    """
    oauth_user_token must route to the same handler as kc_token_exchange.
    The alias normalisation in dispatch_credential_injection must fire BEFORE
    InjectionMode() is evaluated.
    """
    tool = _tool(injection_mode="oauth_user_token")

    with _mock_broker(), patch(
        "app.credential_broker.dispatcher._inject_kc_token_exchange",
        new_callable=AsyncMock,
        return_value={"Authorization": "Bearer exchanged-token"},
    ) as mock_handler:
        result = await dispatch_credential_injection(tool, client_id="u-1", user_kc_token="kc-tok")

    mock_handler.assert_awaited_once()
    assert result == {"Authorization": "Bearer exchanged-token"}


@pytest.mark.asyncio
@pytest.mark.unit
async def test_kc_token_exchange_canonical_name_works():
    """
    kc_token_exchange (canonical name) must route to the kc_token_exchange handler.
    """
    tool = _tool(injection_mode="kc_token_exchange")

    with _mock_broker(), patch(
        "app.credential_broker.dispatcher._inject_kc_token_exchange",
        new_callable=AsyncMock,
        return_value={"Authorization": "Bearer kc-tok"},
    ) as mock_handler:
        result = await dispatch_credential_injection(tool, client_id="u-1", user_kc_token="kc-tok")

    mock_handler.assert_awaited_once()
    assert result == {"Authorization": "Bearer kc-tok"}


@pytest.mark.unit
def test_kc_token_exchange_is_in_injection_mode_enum():
    """InjectionMode enum must contain KC_TOKEN_EXCHANGE."""
    assert InjectionMode.KC_TOKEN_EXCHANGE.value == "kc_token_exchange"


@pytest.mark.unit
def test_oauth_user_token_is_still_in_injection_mode_enum():
    """OAUTH_USER_TOKEN alias must remain in InjectionMode enum for backwards compat."""
    assert InjectionMode.OAUTH_USER_TOKEN.value == "oauth_user_token"


# ---------------------------------------------------------------------------
# Task 3.4: passthrough mode accepted by the dispatcher
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
@pytest.mark.unit
async def test_passthrough_mode_accepted_returns_empty_dict():
    """
    passthrough mode: the dispatcher should return {} (no headers to inject).
    The inbound Authorization header forwarding is handled by invocation.py,
    not the dispatcher — dispatcher's job is to indicate no additional injection.
    """
    tool = _tool(injection_mode="passthrough")

    # Passthrough does NOT require broker — the broker guard in dispatch_credential_injection
    # runs for all non-NONE modes. For passthrough, the match arm returns {} before
    # any broker call, but the broker guard fires first. Patch broker to non-None.
    with _mock_broker():
        result = await dispatch_credential_injection(tool, client_id="u-1")

    assert result == {}


@pytest.mark.unit
def test_passthrough_is_in_injection_mode_enum():
    """InjectionMode enum must contain PASSTHROUGH (AUTH-R6, Task 3.4)."""
    assert InjectionMode.PASSTHROUGH.value == "passthrough"


# ---------------------------------------------------------------------------
# Task 3.4: ServerRegister model — passthrough and entra_user_token accepted
# ---------------------------------------------------------------------------

@pytest.mark.unit
def test_server_register_accepts_passthrough():
    """ServerRegister must accept passthrough as a valid injection_mode."""
    from app.routers.server_registry import ServerRegister
    model = ServerRegister(
        service_name="downstream-svc",
        upstream_url="https://downstream.example.com/mcp",
        injection_mode="passthrough",
    )
    assert model.injection_mode == "passthrough"


@pytest.mark.unit
def test_server_register_accepts_kc_token_exchange():
    """ServerRegister must accept kc_token_exchange as a valid injection_mode."""
    from app.routers.server_registry import ServerRegister
    model = ServerRegister(
        service_name="internal-svc",
        upstream_url="https://internal.example.com/mcp",
        injection_mode="kc_token_exchange",
    )
    assert model.injection_mode == "kc_token_exchange"


@pytest.mark.unit
def test_server_register_accepts_oauth_user_token_alias():
    """ServerRegister must accept the oauth_user_token alias for compat."""
    from app.routers.server_registry import ServerRegister
    model = ServerRegister(
        service_name="compat-svc",
        upstream_url="https://compat.example.com/mcp",
        injection_mode="oauth_user_token",
    )
    assert model.injection_mode == "oauth_user_token"


@pytest.mark.unit
def test_server_register_entra_user_token_requires_tenant_id(monkeypatch):
    """
    ServerRegister must reject entra_user_token when ENTRA_TENANT_ID is not set.
    Expected: ValueError (422 in the API layer) with a clear message.
    """
    import pydantic
    from app.routers.server_registry import ServerRegister

    # Patch settings to return empty ENTRA_TENANT_ID
    class _FakeSettings:
        ENTRA_TENANT_ID = ""

    with patch("app.core.config.get_settings", return_value=_FakeSettings()):
        with pytest.raises((ValueError, pydantic.ValidationError), match="ENTRA_TENANT_ID"):
            ServerRegister(
                service_name="m365-svc",
                upstream_url="https://graph.microsoft.com/mcp",
                injection_mode="entra_user_token",
            )


@pytest.mark.unit
def test_server_register_entra_client_credentials_requires_tenant_id(monkeypatch):
    """
    ServerRegister must reject entra_client_credentials when ENTRA_TENANT_ID is not set.
    """
    import pydantic
    from app.routers.server_registry import ServerRegister

    class _FakeSettings:
        ENTRA_TENANT_ID = ""

    with patch("app.core.config.get_settings", return_value=_FakeSettings()):
        with pytest.raises((ValueError, pydantic.ValidationError), match="ENTRA_TENANT_ID"):
            ServerRegister(
                service_name="m365-app",
                upstream_url="https://graph.microsoft.com/mcp",
                injection_mode="entra_client_credentials",
            )


@pytest.mark.unit
def test_server_register_entra_user_token_passes_when_tenant_id_set():
    """
    ServerRegister must accept entra_user_token when ENTRA_TENANT_ID is configured.
    """
    from app.routers.server_registry import ServerRegister

    class _FakeSettings:
        ENTRA_TENANT_ID = "my-tenant-id-123"

    with patch("app.core.config.get_settings", return_value=_FakeSettings()):
        model = ServerRegister(
            service_name="m365-svc",
            upstream_url="https://graph.microsoft.com/mcp",
            injection_mode="entra_user_token",
        )
    assert model.injection_mode == "entra_user_token"


@pytest.mark.unit
def test_server_register_rejects_unknown_mode():
    """ServerRegister must reject an unknown injection_mode with a clear error."""
    import pydantic
    from app.routers.server_registry import ServerRegister
    with pytest.raises((ValueError, pydantic.ValidationError)):
        ServerRegister(
            service_name="x",
            upstream_url="https://x.example.com/mcp",
            injection_mode="magic_beans",
        )


@pytest.mark.unit
def test_server_create_accepts_passthrough():
    """ServerCreate (admin API) must also accept passthrough."""
    from app.routers.server_registry import ServerCreate
    model = ServerCreate(
        name="my-server",
        upstream_url="https://downstream.example.com/mcp",
        injection_mode="passthrough",
    )
    assert model.injection_mode == "passthrough"


@pytest.mark.unit
def test_server_create_accepts_kc_token_exchange():
    """ServerCreate (admin API) must also accept kc_token_exchange."""
    from app.routers.server_registry import ServerCreate
    model = ServerCreate(
        name="my-server",
        upstream_url="https://internal.example.com/mcp",
        injection_mode="kc_token_exchange",
    )
    assert model.injection_mode == "kc_token_exchange"
