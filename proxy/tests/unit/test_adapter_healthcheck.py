"""
Unit tests for adapter healthcheck interface and approval flow integration.

Tests that healthcheck is called during server approval and failures block approval.
"""
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from types import SimpleNamespace


class TestAdapterHealthcheckInterface:
    """Test the healthcheck interface."""

    @pytest.mark.asyncio
    async def test_gitea_adapter_healthcheck_success(self):
        """Gitea healthcheck calls /api/v1/version, succeeds on 200."""
        from app.credential_broker.adapters.healthcheck import GiteaHealthcheck

        adapter = GiteaHealthcheck(upstream_url="http://gitea.example.com")

        with patch("app.credential_broker.adapters.healthcheck.httpx.AsyncClient") as mock_client_ctx:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {"version": "1.21.0"}

            mock_client = AsyncMock()
            mock_client.__aenter__.return_value = mock_client
            mock_client.__aexit__.return_value = None
            mock_client.get = AsyncMock(return_value=mock_response)

            mock_client_ctx.return_value = mock_client

            # Should not raise
            await adapter.healthcheck()

    @pytest.mark.asyncio
    async def test_gitea_adapter_healthcheck_failure_connection_error(self):
        """Gitea healthcheck raises HealthcheckFailed on connection error."""
        from app.credential_broker.adapters.healthcheck import GiteaHealthcheck, HealthcheckFailed

        adapter = GiteaHealthcheck(upstream_url="http://unreachable.example.com")

        with patch("app.credential_broker.adapters.healthcheck.httpx.AsyncClient") as mock_client_ctx:
            mock_client = AsyncMock()
            mock_client.__aenter__.return_value = mock_client
            mock_client.__aexit__.return_value = None
            mock_client.get = AsyncMock(side_effect=Exception("Connection refused"))

            mock_client_ctx.return_value = mock_client

            with pytest.raises(HealthcheckFailed) as exc_info:
                await adapter.healthcheck()
            assert "gitea" in str(exc_info.value).lower()

    @pytest.mark.asyncio
    async def test_gitea_adapter_healthcheck_failure_http_error(self):
        """Gitea healthcheck raises HealthcheckFailed on HTTP 500."""
        from app.credential_broker.adapters.healthcheck import GiteaHealthcheck, HealthcheckFailed

        adapter = GiteaHealthcheck(upstream_url="http://gitea.example.com")

        with patch("app.credential_broker.adapters.healthcheck.httpx.AsyncClient") as mock_client_ctx:
            mock_response = MagicMock()
            mock_response.status_code = 500
            mock_response.raise_for_status.side_effect = Exception("500 Server Error")

            mock_client = AsyncMock()
            mock_client.__aenter__.return_value = mock_client
            mock_client.__aexit__.return_value = None
            mock_client.get = AsyncMock(return_value=mock_response)

            mock_client_ctx.return_value = mock_client

            with pytest.raises(HealthcheckFailed):
                await adapter.healthcheck()

    @pytest.mark.asyncio
    async def test_m365_adapter_healthcheck_success(self):
        """M365 healthcheck calls /health, succeeds on 200."""
        from app.credential_broker.adapters.healthcheck import M365Healthcheck

        adapter = M365Healthcheck(upstream_url="https://graph.microsoft.com")

        with patch("app.credential_broker.adapters.healthcheck.httpx.AsyncClient") as mock_client_ctx:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {"status": "healthy"}

            mock_client = AsyncMock()
            mock_client.__aenter__.return_value = mock_client
            mock_client.__aexit__.return_value = None
            mock_client.get = AsyncMock(return_value=mock_response)

            mock_client_ctx.return_value = mock_client

            # Should not raise
            await adapter.healthcheck()

    @pytest.mark.asyncio
    async def test_m365_adapter_healthcheck_failure_connection_error(self):
        """M365 healthcheck raises HealthcheckFailed on connection error."""
        from app.credential_broker.adapters.healthcheck import M365Healthcheck, HealthcheckFailed

        adapter = M365Healthcheck(upstream_url="https://unreachable.microsoft.com")

        with patch("app.credential_broker.adapters.healthcheck.httpx.AsyncClient") as mock_client_ctx:
            mock_client = AsyncMock()
            mock_client.__aenter__.return_value = mock_client
            mock_client.__aexit__.return_value = None
            mock_client.get = AsyncMock(side_effect=Exception("Connection timeout"))

            mock_client_ctx.return_value = mock_client

            with pytest.raises(HealthcheckFailed) as exc_info:
                await adapter.healthcheck()
            assert "m365" in str(exc_info.value).lower()

    @pytest.mark.asyncio
    async def test_get_healthcheck_factory_gitea(self):
        """get_healthcheck factory returns GiteaHealthcheck for 'gitea'."""
        from app.credential_broker.adapters.healthcheck import get_healthcheck

        adapter = get_healthcheck(adapter_name="gitea", upstream_url="http://gitea.local")
        assert adapter.__class__.__name__ == "GiteaHealthcheck"
        assert adapter.upstream_url == "http://gitea.local"

    @pytest.mark.asyncio
    async def test_get_healthcheck_factory_m365(self):
        """get_healthcheck factory returns M365Healthcheck for 'm365'."""
        from app.credential_broker.adapters.healthcheck import get_healthcheck

        adapter = get_healthcheck(adapter_name="m365", upstream_url="https://graph.microsoft.com")
        assert adapter.__class__.__name__ == "M365Healthcheck"
        assert adapter.upstream_url == "https://graph.microsoft.com"

    def test_get_healthcheck_factory_unknown_adapter(self):
        """get_healthcheck raises ValueError for unknown adapter."""
        from app.credential_broker.adapters.healthcheck import get_healthcheck

        with pytest.raises(ValueError) as exc_info:
            get_healthcheck(adapter_name="unknown", upstream_url="http://unknown")
        assert "unknown" in str(exc_info.value).lower()


class TestApprovalFlowHealthcheck:
    """Test healthcheck integration into approval flow."""

    def _make_request(self, roles=("platform_admin",), client_id="admin1"):
        req = MagicMock()
        req.state = SimpleNamespace(client_roles=list(roles), client_id=client_id)
        return req

    @pytest.mark.asyncio
    async def test_approval_calls_healthcheck(self):
        """Approval handler calls healthcheck before UPDATE."""
        from fastapi import HTTPException
        from sqlalchemy.ext.asyncio import AsyncSession
        from app.routers.server_registry import approve_server, ApproveBody

        request = self._make_request()
        body = ApproveBody(consent_token="fake_token")
        server_id = "test-server-123"

        # Mock the database
        mock_db = AsyncMock(spec=AsyncSession)
        mock_url_result = MagicMock()
        mock_url_result.fetchone.return_value = ("http://gitea.local", "owner123")
        mock_db.execute = AsyncMock(return_value=mock_url_result)

        # Mock consent verification
        mock_consent_payload = MagicMock()
        mock_consent_payload.jti = "jti-123"

        with patch("app.routers.server_registry.AsyncSessionLocal") as mock_session_factory, \
             patch("app.routers.server_registry.validate_upstream_url_ssrf", new_callable=AsyncMock) as mock_ssrf:
            mock_session_factory.return_value.__aenter__.return_value = mock_db

            with patch("app.routers.server_registry.verify_approve_consent_token") as mock_verify:
                mock_verify.return_value = mock_consent_payload

                with patch("app.routers.server_registry.consume_consent_token") as mock_consume:
                    mock_consume.return_value = True

                    with patch("app.routers.server_registry.get_healthcheck") as mock_get_adapter:
                        mock_adapter = AsyncMock()
                        mock_adapter.healthcheck = AsyncMock()
                        mock_get_adapter.return_value = mock_adapter

                        # Update the mock to simulate the server having an adapter_name
                        # We need to mock the fetch to return: (upstream_url, owner_sub, adapter_name)
                        async def side_effect(query, params=None):
                            query_str = str(query)
                            if "upstream_url, owner_sub, adapter_name" in query_str:
                                # SELECT upstream_url, owner_sub, adapter_name
                                result = MagicMock()
                                result.fetchone.return_value = ("https://gitea.example.com", "owner123", "gitea", None)
                                return result
                            elif "UPDATE" in query_str:
                                result = MagicMock()
                                result.rowcount = 1
                                return result
                            return MagicMock()

                        mock_db.execute = AsyncMock(side_effect=side_effect)

                        response = await approve_server(server_id, body, request)

                        # Verify healthcheck was called
                        mock_adapter.healthcheck.assert_called_once()

                        # Verify response is successful
                        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_approval_blocked_on_healthcheck_failure(self):
        """Approval returns 422 when healthcheck fails."""
        from fastapi import HTTPException
        from sqlalchemy.ext.asyncio import AsyncSession
        from app.routers.server_registry import approve_server, ApproveBody

        request = self._make_request()
        body = ApproveBody(consent_token="fake_token")
        server_id = "test-server-123"

        # Mock the database
        mock_db = AsyncMock(spec=AsyncSession)

        mock_consent_payload = MagicMock()
        mock_consent_payload.jti = "jti-123"

        with patch("app.routers.server_registry.AsyncSessionLocal") as mock_session_factory, \
             patch("app.routers.server_registry.validate_upstream_url_ssrf", new_callable=AsyncMock):
            mock_session_factory.return_value.__aenter__.return_value = mock_db

            with patch("app.routers.server_registry.verify_approve_consent_token") as mock_verify:
                mock_verify.return_value = mock_consent_payload

                with patch("app.routers.server_registry.consume_consent_token") as mock_consume:
                    mock_consume.return_value = True

                    with patch("app.routers.server_registry.get_healthcheck") as mock_get_adapter:
                        from app.credential_broker.adapters.healthcheck import HealthcheckFailed

                        mock_adapter = AsyncMock()
                        mock_adapter.healthcheck = AsyncMock(side_effect=HealthcheckFailed("gitea", "Connection refused"))
                        mock_get_adapter.return_value = mock_adapter

                        async def side_effect(query, params=None):
                            query_str = str(query)
                            if "upstream_url, owner_sub, adapter_name" in query_str:
                                # SELECT upstream_url, owner_sub, adapter_name
                                result = MagicMock()
                                result.fetchone.return_value = ("https://gitea.example.com", "owner123", "gitea", None)
                                return result
                            return MagicMock()

                        mock_db.execute = AsyncMock(side_effect=side_effect)

                        with pytest.raises(HTTPException) as exc_info:
                            await approve_server(server_id, body, request)

                        assert exc_info.value.status_code == 422

    @pytest.mark.asyncio
    async def test_approval_skips_healthcheck_if_no_adapter_name(self):
        """Approval skips healthcheck if server has no adapter_name."""
        from fastapi import HTTPException
        from sqlalchemy.ext.asyncio import AsyncSession
        from app.routers.server_registry import approve_server, ApproveBody

        request = self._make_request()
        body = ApproveBody(consent_token="fake_token")
        server_id = "test-server-123"

        # Mock the database
        mock_db = AsyncMock(spec=AsyncSession)

        mock_consent_payload = MagicMock()
        mock_consent_payload.jti = "jti-123"

        with patch("app.routers.server_registry.AsyncSessionLocal") as mock_session_factory:
            mock_session_factory.return_value.__aenter__.return_value = mock_db

            with patch("app.routers.server_registry.verify_approve_consent_token") as mock_verify:
                mock_verify.return_value = mock_consent_payload

                with patch("app.routers.server_registry.consume_consent_token") as mock_consume:
                    mock_consume.return_value = True

                    with patch("app.routers.server_registry.get_healthcheck") as mock_get_adapter:
                        # Healthcheck should NOT be called
                        mock_get_adapter.side_effect = Exception("Should not be called")

                        async def side_effect(query, params=None):
                            query_str = str(query)
                            if "upstream_url, owner_sub, adapter_name" in query_str:
                                # SELECT upstream_url, owner_sub, adapter_name
                                # Return None for adapter_name to simulate no adapter
                                result = MagicMock()
                                result.fetchone.return_value = ("https://example.com", "owner123", None, None)
                                return result
                            elif "UPDATE" in query_str:
                                result = MagicMock()
                                result.rowcount = 1
                                return result
                            return MagicMock()

                        mock_db.execute = AsyncMock(side_effect=side_effect)

                        response = await approve_server(server_id, body, request)

                        # Verify response is successful (no healthcheck called)
                        assert response.status_code == 200
