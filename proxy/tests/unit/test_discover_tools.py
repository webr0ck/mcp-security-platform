"""
Unit Test — Tool Discovery and Server Linking (Task 13) + N3 SSRF fixes

Tests:
- PATCH /api/v1/tools/{tool_id} exposes server_id field in response.
- POST /api/v1/servers/{server_id}/discover-tools: DNS-rebind protection (N3 fix).

Full integration discovery tests (requires running services) are in
tests/integration/.

Run: pytest tests/unit/test_discover_tools.py -v
"""
from __future__ import annotations

import json
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4


def _gw() -> str:
    """Load GATEWAY_SHARED_SECRET from app settings."""
    try:
        from app.core.config import settings
        return settings.GATEWAY_SHARED_SECRET
    except Exception:
        return ""


_GW_SECRET = _gw()


# ===========================================================================
# Test: PATCH /tools/{tool_id} exposes server_id in response
# ===========================================================================

@pytest.mark.asyncio
async def test_patch_tools_response_includes_server_id():
    """
    Verify that get_tool() includes server_id in response dict.
    This is a unit test of the response builder, not the full HTTP flow.
    """
    from app.routers.tools import get_tool
    from fastapi import Request
    from sqlalchemy.ext.asyncio import AsyncSession

    tool_id = "test-id"
    server_id = str(uuid4())

    # Create mock request
    mock_request = MagicMock(spec=Request)
    mock_request.state.client_roles = ["admin"]
    mock_request.state.client_id = "test-admin"

    # Create mock DB session
    mock_db = AsyncMock(spec=AsyncSession)

    # Mock tool row with server_id
    tool_row = MagicMock()
    tool_row.tool_id = tool_id
    tool_row.name = "test-tool"
    tool_row.version = "1.0.0"
    tool_row.description = "Test tool"
    tool_row.status = "active"
    tool_row.risk_score = 5
    tool_row.risk_level = "low"
    tool_row.risk_reasons = json.dumps([])
    tool_row.tags = []
    tool_row.metadata = {}
    tool_row.registered_by = "test-admin-client"
    tool_row.created_at = MagicMock(isoformat=lambda: "2024-01-01T00:00:00Z")
    tool_row.updated_at = MagicMock(isoformat=lambda: "2024-01-01T00:00:00Z")
    tool_row.schema = json.dumps({"type": "object"})
    tool_row.upstream_url = "http://test:8000/mcp"
    tool_row.source_repo = None
    tool_row.source_commit = None
    tool_row.sbom_id = str(uuid4())
    tool_row.signature = "sig123"
    tool_row.server_id = server_id

    # Mock DB execute
    result = MagicMock()
    result.fetchone.return_value = tool_row
    mock_db.execute = AsyncMock(return_value=result)

    # Call the endpoint function directly
    response = await get_tool(tool_id, mock_request, mock_db)

    # Parse response (it's JSONResponse)
    body = json.loads(response.body)

    # Verify server_id is in response
    assert "server_id" in body, f"server_id must be in response, got keys: {body.keys()}"
    assert body["server_id"] == server_id, f"server_id mismatch: {body['server_id']} vs {server_id}"
    assert body["status"] == "active"
    assert body["name"] == "test-tool"


@pytest.mark.asyncio
async def test_patch_tools_response_includes_null_server_id():
    """
    Verify that get_tool() includes server_id=None for legacy tools without server_id.
    """
    from app.routers.tools import get_tool
    from fastapi import Request
    from sqlalchemy.ext.asyncio import AsyncSession

    tool_id = "test-id"

    # Create mock request
    mock_request = MagicMock(spec=Request)
    mock_request.state.client_roles = ["admin"]
    mock_request.state.client_id = "test-admin"

    # Create mock DB session
    mock_db = AsyncMock(spec=AsyncSession)

    # Mock tool row WITHOUT server_id (legacy tool)
    tool_row = MagicMock()
    tool_row.tool_id = tool_id
    tool_row.name = "legacy-tool"
    tool_row.version = "1.0.0"
    tool_row.description = "Legacy tool"
    tool_row.status = "active"
    tool_row.risk_score = 5
    tool_row.risk_level = "low"
    tool_row.risk_reasons = json.dumps([])
    tool_row.tags = []
    tool_row.metadata = {}
    tool_row.registered_by = "test-admin-client"
    tool_row.created_at = MagicMock(isoformat=lambda: "2024-01-01T00:00:00Z")
    tool_row.updated_at = MagicMock(isoformat=lambda: "2024-01-01T00:00:00Z")
    tool_row.schema = json.dumps({"type": "object"})
    tool_row.upstream_url = "http://legacy:8000/mcp"
    tool_row.source_repo = None
    tool_row.source_commit = None
    tool_row.sbom_id = str(uuid4())
    tool_row.signature = "sig123"
    tool_row.server_id = None  # No server_id

    # Mock DB execute
    result = MagicMock()
    result.fetchone.return_value = tool_row
    mock_db.execute = AsyncMock(return_value=result)

    # Call the endpoint function directly
    response = await get_tool(tool_id, mock_request, mock_db)

    # Parse response
    body = json.loads(response.body)

    # Verify server_id is in response as None
    assert "server_id" in body, "server_id field must be present"
    assert body["server_id"] is None, f"server_id should be None, got {body['server_id']}"


# ===========================================================================
# N3 fix — DNS-rebind / TOCTOU protection in discover_tools
# ===========================================================================


@pytest.mark.asyncio
async def test_discover_tools_dns_rebind_returns_400():
    """
    N3 fix: When revalidate_upstream_ip_at_invoke raises UpstreamRevalidationError
    (DNS rebind or TOCTOU detected), discover_tools must return HTTP 400 and
    never attempt an upstream HTTP connection.

    Covers: proxy/app/routers/tools.py — discover_tools SSRF revalidation block.
    """
    import json
    from unittest.mock import AsyncMock, MagicMock, patch
    from fastapi import Request
    from sqlalchemy.ext.asyncio import AsyncSession
    from app.routers.tools import discover_tools
    from app.services.server_onboarding import UpstreamRevalidationError

    server_id = str(uuid4())

    # Mock request: admin role
    mock_request = MagicMock(spec=Request)
    mock_request.state.client_roles = ["admin"]
    mock_request.state.client_id = "test-admin"

    # Mock DB session: return an approved server_row with upstream_allowlist_entry
    mock_db = AsyncMock(spec=AsyncSession)
    server_row = MagicMock()
    server_row.server_id = server_id
    server_row.upstream_url = "https://legit-looking.example.com/mcp"
    server_row.service_name = "test-service"
    server_row.status = "approved"
    server_row.upstream_allowlist_entry = "203.0.113.42/32"  # registered at approval time

    db_result = MagicMock()
    db_result.fetchone.return_value = server_row
    mock_db.execute = AsyncMock(return_value=db_result)

    with (
        # validate_server_url passes (URL looks fine statically)
        patch(
            "app.routers.tools.validate_server_url",
            return_value=None,
        ),
        # revalidate_upstream_ip_at_invoke raises — DNS rebind detected
        patch(
            "app.routers.tools.revalidate_upstream_ip_at_invoke",
            new_callable=AsyncMock,
            side_effect=UpstreamRevalidationError(
                "Resolved IP 10.0.0.1 does not match registered allowlist entry 203.0.113.42/32"
            ),
        ),
        # httpx.AsyncClient must never be called (patched at the httpx module level
        # because the function does `import httpx` locally)
        patch("httpx.AsyncClient") as mock_httpx_client,
    ):
        response = await discover_tools(server_id, mock_request, mock_db)

    # Assert HTTP 400
    assert response.status_code == 400, (
        f"Expected 400 on DNS-rebind, got {response.status_code}"
    )
    body = json.loads(response.body)
    assert body.get("code") == "UPSTREAM_REVALIDATION_FAILED", (
        f"Expected UPSTREAM_REVALIDATION_FAILED code, got: {body}"
    )
    # httpx.AsyncClient must not have been instantiated
    mock_httpx_client.assert_not_called()


@pytest.mark.asyncio
async def test_discover_tools_ssrf_validation_failure_returns_400():
    """
    N3 fix: When validate_server_url raises SSRFError (URL resolves to a
    private/blocked range), discover_tools must return HTTP 400.
    """
    import json
    from unittest.mock import AsyncMock, MagicMock, patch
    from fastapi import Request
    from sqlalchemy.ext.asyncio import AsyncSession
    from app.routers.tools import discover_tools
    from app.services.ssrf import SSRFError

    server_id = str(uuid4())

    mock_request = MagicMock(spec=Request)
    mock_request.state.client_roles = ["admin"]
    mock_request.state.client_id = "test-admin"

    mock_db = AsyncMock(spec=AsyncSession)
    server_row = MagicMock()
    server_row.server_id = server_id
    server_row.upstream_url = "https://metadata.internal/mcp"
    server_row.service_name = "evil-service"
    server_row.status = "approved"
    server_row.upstream_allowlist_entry = None

    db_result = MagicMock()
    db_result.fetchone.return_value = server_row
    mock_db.execute = AsyncMock(return_value=db_result)

    with (
        patch(
            "app.routers.tools.validate_server_url",
            side_effect=SSRFError("Host 'metadata.internal' resolves to blocked IP"),
        ),
        patch("httpx.AsyncClient") as mock_httpx_client,
    ):
        response = await discover_tools(server_id, mock_request, mock_db)

    assert response.status_code == 400, (
        f"Expected 400 on SSRF failure, got {response.status_code}"
    )
    body = json.loads(response.body)
    assert body.get("code") == "SSRF_VALIDATION_FAILED", (
        f"Expected SSRF_VALIDATION_FAILED code, got: {body}"
    )
    mock_httpx_client.assert_not_called()
