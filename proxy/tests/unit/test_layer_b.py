"""Unit tests for Layer B MIME-style in-band advisory wrapper (RFC-0001 §3)."""
from proxy.app.services.layer_b import wrap_content_layer_b, LAYER_B_BOUNDARY_PREFIX


def test_untrusted_text_content_is_wrapped():
    content = [{"type": "text", "text": "Hello from the web"}]
    result = wrap_content_layer_b(
        content=content, trust_tier=0, tool_name="web_search", server_id="search-server"
    )
    assert len(result) == 1
    text = result[0]["text"]
    assert LAYER_B_BOUNDARY_PREFIX in text
    assert "untrustedPublic" in text
    assert "Hello from the web" in text
    assert "web_search" in text


def test_trusted_content_is_not_wrapped():
    content = [{"type": "text", "text": "Internal data"}]
    result = wrap_content_layer_b(
        content=content, trust_tier=4, tool_name="crm_read", server_id="crm-server"
    )
    assert result == content


def test_non_text_content_items_are_not_wrapped():
    content = [{"type": "image", "data": "base64data", "mimeType": "image/png"}]
    result = wrap_content_layer_b(
        content=content, trust_tier=0, tool_name="screenshot", server_id="browser-server"
    )
    # non-text items pass through unchanged
    assert result == content


def test_mixed_content_wraps_only_text():
    content = [
        {"type": "text", "text": "Attacker text"},
        {"type": "image", "data": "imgdata", "mimeType": "image/png"},
    ]
    result = wrap_content_layer_b(
        content=content, trust_tier=0, tool_name="tool", server_id="s"
    )
    assert LAYER_B_BOUNDARY_PREFIX in result[0]["text"]
    assert result[1] == content[1]


def test_none_trust_tier_treated_as_untrusted():
    content = [{"type": "text", "text": "Unknown source"}]
    result = wrap_content_layer_b(
        content=content, trust_tier=None, tool_name="t", server_id="s"
    )
    assert LAYER_B_BOUNDARY_PREFIX in result[0]["text"]


def test_tier_1_is_wrapped():
    content = [{"type": "text", "text": "trusted public"}]
    result = wrap_content_layer_b(
        content=content, trust_tier=1, tool_name="t", server_id="s"
    )
    assert LAYER_B_BOUNDARY_PREFIX in result[0]["text"]
    assert "trustedPublic" in result[0]["text"]
