"""Tests for the reviewer/admin MCP tools (list_pending_reviews, review_submission,
approve_submission, reject_submission)."""
import json
from unittest.mock import AsyncMock, patch

import httpx
import pytest

import server as ss  # mcp-servers/self-service/server.py


def _mock_response(status_code, json_body):
    return httpx.Response(status_code, json=json_body, request=httpx.Request("GET", "http://x"))


@pytest.mark.asyncio
async def test_list_pending_reviews_returns_queue():
    fake_queue = {"submissions": [{"server_id": "abc", "submission_status": "awaiting_review"}]}
    with patch("httpx.AsyncClient.get", new=AsyncMock(return_value=_mock_response(200, fake_queue))):
        result = await ss.list_pending_reviews()
    assert result == fake_queue


@pytest.mark.asyncio
async def test_review_submission_passes_through_detail():
    fake_detail = {"server_id": "abc", "repo": None, "config": {"injection_mode": "none"}}
    with patch("httpx.AsyncClient.get", new=AsyncMock(return_value=_mock_response(200, fake_detail))):
        result = await ss.review_submission("abc")
    assert result == fake_detail


@pytest.mark.asyncio
async def test_review_submission_not_found():
    with patch("httpx.AsyncClient.get", new=AsyncMock(return_value=_mock_response(404, {"detail": "not found"}))):
        result = await ss.review_submission("nonexistent")
    assert result == {"error": "not_found"}


@pytest.mark.asyncio
async def test_approve_submission_posts_notes():
    fake_result = {"server_id": "abc", "submission_status": "scaffold_ready"}
    with patch("httpx.AsyncClient.post", new=AsyncMock(return_value=_mock_response(200, fake_result))) as mock_post:
        result = await ss.approve_submission("abc", notes="looks good")
    assert result == fake_result
    call_kwargs = mock_post.call_args.kwargs
    assert json.loads(call_kwargs["content"])["notes"] == "looks good"


@pytest.mark.asyncio
async def test_reject_submission_error_shape():
    with patch("httpx.AsyncClient.post", new=AsyncMock(return_value=_mock_response(409, {"detail": "not awaiting review"}))):
        result = await ss.reject_submission("abc", notes="no")
    assert result["error"] == "api_error"
    assert "not awaiting review" in result["detail"]
