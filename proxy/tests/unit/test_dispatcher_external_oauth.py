"""
WP-A3 (CR-04 remainder) — dispatcher branches for external_oauth_user_token /
external_oauth_client_credentials.

external_oauth_user_token mirrors entra_user_token's fail-closed/broker.resolve
shape exactly (same S-1 no-client-id guard, same CrossTypePrincipalMismatch ->
CrossTypePrincipalFallbackDenied translation). external_oauth_client_credentials
mirrors entra_client_credentials's credential_store lookup, but reads the token
endpoint from server_registry.approved_upstream_idp_config instead of a
hardcoded Microsoft URL.
"""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.credential_broker.dispatcher import (
    CredentialInjectionError,
    dispatch_credential_injection,
)


def _user_tool(**over) -> dict:
    base = {
        "tool_id": "t-ext-user",
        "name": "jira-tool",
        "service_name": "jira-cloud",
        "injection_mode": "external_oauth_user_token",
        "inject_header": "Authorization",
        "inject_prefix": "Bearer",
    }
    base.update(over)
    return base


def _cc_tool(**over) -> dict:
    base = {
        "tool_id": "t-ext-cc",
        "name": "generic-saas",
        "service_name": "generic-saas",
        "server_id": "srv-1",
        "credential_id": "cred-1",
        "injection_mode": "external_oauth_client_credentials",
        "inject_header": "Authorization",
        "inject_prefix": "Bearer",
    }
    base.update(over)
    return base


@pytest.mark.asyncio
class TestExternalOAuthUserToken:
    async def test_no_client_id_fails_closed(self):
        with pytest.raises(CredentialInjectionError):
            await dispatch_credential_injection(
                tool_record=_user_tool(), client_id="", user_kc_token=None,
            )

    async def test_happy_path_delegates_to_broker_resolve(self):
        mock_broker = MagicMock()
        mock_result = MagicMock()
        mock_result.token = "delegated-access-token"
        mock_broker.resolve = AsyncMock(return_value=mock_result)
        with patch("app.services.invocation.broker_instance", mock_broker):
            headers = await dispatch_credential_injection(
                tool_record=_user_tool(), client_id="alice@corp",
            )
        assert headers == {"Authorization": "Bearer delegated-access-token"}
        mock_broker.resolve.assert_awaited_once()
        _, kwargs = mock_broker.resolve.call_args
        assert kwargs["service"] == "jira-cloud"
        assert kwargs["approach"] == "A"

    async def test_not_enrolled_raises_enrollment_required(self):
        from app.credential_broker.broker import CredentialNotEnrolledError

        mock_broker = MagicMock()
        mock_broker.resolve = AsyncMock(
            side_effect=CredentialNotEnrolledError(user_sub="alice@corp", service="jira-cloud")
        )
        with patch("app.services.invocation.broker_instance", mock_broker):
            from app.credential_broker.dispatcher import CredentialEnrollmentRequiredError
            with pytest.raises(CredentialEnrollmentRequiredError) as exc_info:
                await dispatch_credential_injection(
                    tool_record=_user_tool(), client_id="alice@corp",
                )
        assert "jira-cloud" in exc_info.value.enrollment_url

    async def test_cross_type_mismatch_denied_not_silently_matched(self):
        from app.credential_broker.principal_resolution import CrossTypePrincipalMismatch
        from app.credential_broker.dispatcher import CrossTypePrincipalFallbackDenied

        mock_broker = MagicMock()
        mock_broker.resolve = AsyncMock(
            side_effect=CrossTypePrincipalMismatch(
                caller_type="agent", row_type="human", bare_sub="alice@corp", service="jira-cloud"
            )
        )
        with patch("app.services.invocation.broker_instance", mock_broker):
            with pytest.raises(CrossTypePrincipalFallbackDenied):
                await dispatch_credential_injection(
                    tool_record=_user_tool(), client_id="alice@corp",
                )


@pytest.mark.asyncio
class TestExternalOAuthClientCredentials:
    async def test_missing_credential_id_fails_closed(self):
        with pytest.raises(CredentialInjectionError):
            await dispatch_credential_injection(
                tool_record=_cc_tool(credential_id=None), client_id="agent-1",
            )

    async def test_happy_path_fetches_token_from_approved_endpoint(self):
        mock_broker = MagicMock()
        mock_broker.vault_client = MagicMock()
        mock_broker.db_pool = MagicMock()

        approved_row = MagicMock()
        approved_row.approved_upstream_idp_config = {
            "token_endpoint": "https://idp.example.com/token",
            "client_auth_method": "client_secret_post",
        }
        approved_row.approved_oauth_scopes = ["api.read"]

        mock_session = MagicMock()
        mock_result = MagicMock()
        mock_result.fetchone.return_value = approved_row
        mock_session.execute = AsyncMock(return_value=mock_result)

        class _Ctx:
            async def __aenter__(self):
                return mock_session
            async def __aexit__(self, *a):
                return False

        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json = MagicMock(return_value={"access_token": "cc-token-1"})
        mock_http = AsyncMock()
        mock_http.__aenter__ = AsyncMock(return_value=mock_http)
        mock_http.__aexit__ = AsyncMock(return_value=False)
        mock_http.post = AsyncMock(return_value=mock_resp)

        with patch("app.services.invocation.broker_instance", mock_broker), \
             patch(
                 "app.services.credential_storage.retrieve_credential",
                 AsyncMock(return_value={"client_id": "cc-id", "client_secret": "cc-secret"}),
             ), \
             patch("app.core.database.AsyncSessionLocal", return_value=_Ctx()), \
             patch("httpx.AsyncClient", return_value=mock_http):
            headers = await dispatch_credential_injection(
                tool_record=_cc_tool(), client_id="agent-1",
            )
        assert headers == {"Authorization": "Bearer cc-token-1"}
        # scope + grant_type present in the posted form; client creds in body
        # (client_secret_post), never a Basic header.
        _, post_kwargs = mock_http.post.call_args
        assert post_kwargs["data"]["client_id"] == "cc-id"
        assert post_kwargs["data"]["scope"] == "api.read"
        assert "auth" not in post_kwargs

    async def test_no_approved_token_endpoint_fails_closed(self):
        mock_broker = MagicMock()
        mock_broker.vault_client = MagicMock()
        mock_broker.db_pool = MagicMock()

        approved_row = MagicMock()
        approved_row.approved_upstream_idp_config = {}  # reviewer hasn't approved yet
        approved_row.approved_oauth_scopes = []

        mock_session = MagicMock()
        mock_result = MagicMock()
        mock_result.fetchone.return_value = approved_row
        mock_session.execute = AsyncMock(return_value=mock_result)

        class _Ctx:
            async def __aenter__(self):
                return mock_session
            async def __aexit__(self, *a):
                return False

        with patch("app.services.invocation.broker_instance", mock_broker), \
             patch(
                 "app.services.credential_storage.retrieve_credential",
                 AsyncMock(return_value={"client_id": "cc-id", "client_secret": "cc-secret"}),
             ), \
             patch("app.core.database.AsyncSessionLocal", return_value=_Ctx()):
            with pytest.raises(CredentialInjectionError):
                await dispatch_credential_injection(
                    tool_record=_cc_tool(), client_id="agent-1",
                )
