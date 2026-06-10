"""
Unit Test — Tool Discovery and Server Linking (Task 13)

Tests that PATCH /api/v1/tools/{tool_id} exposes server_id field in response.

Full discovery tests (POST /api/v1/servers/{server_id}/discover-tools) are
in integration tests since they require running services.

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
