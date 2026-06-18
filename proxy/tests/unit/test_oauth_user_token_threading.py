"""
6.3 — RFC 8693 on-behalf-of: thread the caller's Keycloak access token into the
credential broker for oauth_user_token injection mode.

Goal (user requirement): users authenticate via OAuth/OIDC and hold NO upstream
secret — the proxy exchanges the caller's KC access token for an upstream-audience
token (RFC 8693). Two seams are pinned:

  1. invoke_tool() forwards user_kc_token to dispatch_credential_injection
     (previously hardcoded None, so oauth_user_token always failed closed).
  2. AuthMiddleware stashes the raw KC access token on request.state.user_kc_token
     ONLY for direct-OIDC callers (auth_method='oidc'); never for api_key / mtls /
     internal session JWT (those bearers are not KC subject tokens).
"""
from __future__ import annotations

import sys
from types import ModuleType
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


def _make_sys_stubs():
    mock_anomaly = ModuleType("app.services.anomaly")
    mock_anomaly.evaluate_anomaly = AsyncMock()
    mock_anomaly.detect = AsyncMock(return_value=MagicMock(anomaly_score=0.0))

    mock_policy = ModuleType("app.services.policy")
    mock_policy.evaluate_policy = AsyncMock(return_value={"allow": True, "reasons": []})
    mock_policy.OPADenyError = type("OPADenyError", (Exception,), {})
    mock_policy.OPAUnavailableError = type("OPAUnavailableError", (Exception,), {})

    audit_event = MagicMock()
    audit_event.event_id = "audit-evt-1"
    mock_audit_pkg = ModuleType("mcp_audit_logger")
    mock_audit_pkg.AuditEvent = MagicMock(return_value=audit_event)
    mock_audit_pkg.AuditEventType = MagicMock()
    mock_audit_pkg.AuditOutcome = MagicMock()
    mock_audit_pkg.MCPAuditLogger = MagicMock()

    return {
        "app.services.anomaly": mock_anomaly,
        "app.services.policy": mock_policy,
        "mcp_audit_logger": mock_audit_pkg,
    }


@pytest.mark.unit
async def test_invoke_tool_threads_user_kc_token_to_dispatcher():
    """invoke_tool must forward the caller's KC token to the credential dispatcher
    so oauth_user_token mode can perform the RFC 8693 exchange."""
    stubs = _make_sys_stubs()
    with patch.dict(sys.modules, stubs):
        from app.services import invocation as _inv_mod
        invoke_tool = _inv_mod.invoke_tool

    mock_response = MagicMock()
    mock_response.json = MagicMock(return_value={"jsonrpc": "2.0", "result": {}, "id": 1})

    async def fake_post(url, json, headers, timeout=30.0):
        return mock_response

    captured = {}

    async def fake_dispatch(tool_record, client_id, user_kc_token=None):
        captured["user_kc_token"] = user_kc_token
        return {"Authorization": "Bearer exchanged-upstream-token"}

    tool_record = {
        "tool_id": "t-obo",
        "name": "graph-api",
        "status": "active",
        "upstream_url": "http://graph:9/mcp",
        "service_name": "m365",
        "injection_mode": "oauth_user_token",
        "inject_header": "Authorization",
        "inject_prefix": "Bearer",
        "kc_token_audience": "https://graph.example",
    }

    with patch.dict(sys.modules, stubs), \
         patch("app.credential_broker.dispatcher.dispatch_credential_injection",
               AsyncMock(side_effect=fake_dispatch)), \
         patch("app.services.invocation._get_or_create_session",
               AsyncMock(return_value="sess")), \
         patch("app.services.invocation.httpx.AsyncClient") as mock_cls:
        mock_http = AsyncMock()
        mock_http.__aenter__ = AsyncMock(return_value=mock_http)
        mock_http.__aexit__ = AsyncMock(return_value=False)
        mock_http.post = AsyncMock(side_effect=fake_post)
        mock_cls.return_value = mock_http

        await invoke_tool(
            tool_record=tool_record,
            json_rpc_request={"jsonrpc": "2.0", "method": "tools/call", "id": 1, "params": {}},
            client_id="alice@corp",
            client_roles=["agent"],
            is_testing=False,
            request_id="req-obo",
            user_kc_token="caller-kc-access-token",
        )

    assert captured["user_kc_token"] == "caller-kc-access-token"


@pytest.mark.unit
async def test_dispatcher_oauth_user_token_uses_caller_token_as_subject():
    """The dispatcher must pass the caller's token as the RFC 8693 subject_token."""
    from app.credential_broker import dispatcher as disp

    captured = {}

    async def fake_exchange(subject_token, audience, **kw):
        captured["subject_token"] = subject_token
        captured["audience"] = audience
        return "exchanged-token"

    tool_record = {
        "tool_id": "t-obo",
        "name": "graph-api",
        "injection_mode": "oauth_user_token",
        "inject_header": "Authorization",
        "inject_prefix": "Bearer",
        "kc_token_audience": "lab-tickets",
    }

    with patch("app.credential_broker.keycloak_client.exchange_token",
               AsyncMock(side_effect=fake_exchange)), \
         patch("app.services.invocation.broker_instance", MagicMock()), \
         patch("app.credential_broker.keycloak_client.get_public_key_for_token",
               AsyncMock(return_value="mock-key")), \
         patch("app.credential_broker.token_assert.assert_exchanged_token", return_value=None), \
         patch("jwt.decode", return_value={"sub": "alice"}):
        headers = await disp.dispatch_credential_injection(
            tool_record=tool_record,
            client_id="alice@corp",
            user_kc_token="caller-kc-access-token",
        )

    assert captured["subject_token"] == "caller-kc-access-token"
    assert captured["audience"] == "lab-tickets"
    assert headers["Authorization"] == "Bearer exchanged-token"


@pytest.mark.unit
async def test_dispatcher_oauth_user_token_fails_closed_without_token():
    """No caller token → fail closed (never forward an unauthenticated upstream call)."""
    from app.credential_broker import dispatcher as disp
    from app.credential_broker.dispatcher import CredentialInjectionError

    tool_record = {
        "tool_id": "t-obo", "name": "graph-api", "injection_mode": "oauth_user_token",
        "inject_header": "Authorization", "inject_prefix": "Bearer",
        "kc_token_audience": "https://graph.example",
    }
    with pytest.raises(CredentialInjectionError):
        await disp.dispatch_credential_injection(
            tool_record=tool_record, client_id="alice@corp", user_kc_token=None,
        )


@pytest.mark.unit
async def test_auth_stashes_kc_token_only_for_oidc(monkeypatch):
    """AuthMiddleware must stash the raw KC access token on request.state for
    direct-OIDC callers (the bearer IS a KC subject token), and must NOT stash it
    for API-key callers (their bearer is an opaque key, unusable for exchange)."""
    from app.middleware import auth as auth_mod
    from starlette.requests import Request
    from starlette.responses import PlainTextResponse

    captured = {}

    async def call_next(request):
        captured["v"] = getattr(request.state, "user_kc_token", "MISSING")
        return PlainTextResponse("ok")

    def make_request(bearer: bytes):
        scope = {
            "type": "http", "method": "POST", "path": "/api/v1/tools/x/invoke",
            "headers": [(b"authorization", b"Bearer " + bearer)],
            "query_string": b"", "client": ("1.2.3.4", 1234),
            "server": ("testserver", 80), "scheme": "http",
        }
        return Request(scope)

    mw = auth_mod.AuthMiddleware(app=lambda *a, **k: None)
    monkeypatch.setattr(auth_mod.settings, "OIDC_ENABLED", True, raising=False)

    # Direct-OIDC caller → token stashed.
    with patch.object(auth_mod, "_validate_oidc_jwt",
                      AsyncMock(return_value=("alice@corp", ["agent"]))), \
         patch.object(auth_mod, "_load_roles", AsyncMock(return_value=["agent"])):
        await mw.dispatch(make_request(b"kc-access-token-123"), call_next)
    assert captured["v"] == "kc-access-token-123"

    # API-key caller (OIDC validation returns no subject) → NOT stashed.
    with patch.object(auth_mod, "_validate_oidc_jwt", AsyncMock(return_value=(None, []))), \
         patch.object(auth_mod, "_resolve_api_key", AsyncMock(return_value="svc-1")), \
         patch.object(auth_mod, "_load_roles", AsyncMock(return_value=["agent"])):
        await mw.dispatch(make_request(b"opaque-api-key"), call_next)
    assert captured["v"] is None
