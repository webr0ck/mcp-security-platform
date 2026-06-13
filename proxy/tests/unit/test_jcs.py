"""Tests for the JCS (RFC 8785) canonicalization helpers."""
import json
import pytest
from app.services.jcs import jcs_tool_result, jcs_signed_input


class TestJcsToolResult:
    def test_basic_content_list(self):
        """Content list is serialized under 'content' key; structuredContent is explicit null."""
        content = [{"type": "text", "text": "hello"}]
        result = jcs_tool_result(content=content, structured_content=None)
        parsed = json.loads(result)
        assert parsed["content"] == content
        assert "structuredContent" in parsed
        assert parsed["structuredContent"] is None

    def test_structured_content_included(self):
        """When structuredContent is present it appears in the canonical bytes."""
        content = [{"type": "text", "text": "hi"}]
        sc = {"key": "value"}
        result = jcs_tool_result(content=content, structured_content=sc)
        parsed = json.loads(result)
        assert parsed["structuredContent"] == sc

    def test_returns_bytes(self):
        """Return type is bytes (for hashing)."""
        result = jcs_tool_result(content=[], structured_content=None)
        assert isinstance(result, bytes)

    def test_key_order_is_deterministic(self):
        """Keys must be in JCS canonical order (alphabetical), not insertion order."""
        content = [{"type": "text", "text": "x"}]
        result = jcs_tool_result(content=content, structured_content=None)
        parsed = json.loads(result)
        keys = list(parsed.keys())
        assert keys == sorted(keys)

    def test_not_using_sort_keys(self):
        """Regression: jcs.py must not use json.dumps(sort_keys=True)."""
        import app.services.jcs as jcs_module
        src = jcs_module.__file__
        with open(src) as f:
            source = f.read()
        assert "sort_keys" not in source, "jcs.py must not use json.dumps(sort_keys=True)"


class TestJcsSignedInput:
    def test_contains_all_fields(self):
        """Signed input contains all required fields."""
        label = {"source": "untrustedPublic", "integrity_rank": 0, "sensitivity": "low", "attribution": []}
        result = jcs_signed_input(
            label=label,
            content_hash="sha256:abc",
            nonce="xyz",
            signed_at="2026-06-13T12:00:00Z",
            result_id="rid-1",
            tool_name="web_search",
            server_id="srv-1",
        )
        parsed = json.loads(result)
        assert parsed["label"] == label
        assert parsed["content_hash"] == "sha256:abc"
        assert parsed["nonce"] == "xyz"
        assert parsed["signed_at"] == "2026-06-13T12:00:00Z"
        assert parsed["result_id"] == "rid-1"
        assert parsed["tool_name"] == "web_search"
        assert parsed["server_id"] == "srv-1"

    def test_returns_bytes(self):
        result = jcs_signed_input(
            label={}, content_hash="h", nonce="n",
            signed_at="t", result_id="r", tool_name="t", server_id="s",
        )
        assert isinstance(result, bytes)
