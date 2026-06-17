from app.routers import mcp_server  # imports standalone — no DB/app context needed


def test_registered_tools_query_excludes_hidden():
    sql = mcp_server.REGISTERED_TOOLS_QUERY
    assert "metadata" in sql and "hidden" in sql
    assert "status = 'active'" in sql and "deleted_at IS NULL" in sql
    assert "COALESCE(metadata->>'hidden', 'false') <> 'true'" in sql


def test_invoke_lookup_name_uses_subtool_for_tools_call():
    # tools/call → look up the sub-tool (arguments.name), not the alias tool_name
    assert mcp_server._invoke_lookup_name(
        tool_name="grafana-query", method="tools/call",
        arguments={"name": "delete_dashboard", "arguments": {}},
    ) == "delete_dashboard"
    # tools/list → look up the named server/alias as before
    assert mcp_server._invoke_lookup_name(
        tool_name="grafana-query", method="tools/list", arguments={},
    ) == "grafana-query"
    # tools/call without a sub-tool name is invalid
    assert mcp_server._invoke_lookup_name(
        tool_name="grafana-query", method="tools/call", arguments={},
    ) is None


def test_invoke_lookup_name_strip_and_none_robustness():
    # None arguments on tools/call is invalid
    assert mcp_server._invoke_lookup_name("grafana-query", "tools/call", None) is None
    # whitespace-only sub-tool name is invalid
    assert mcp_server._invoke_lookup_name("grafana-query", "tools/call", {"name": "   "}) is None
    # sub-tool name is stripped
    assert mcp_server._invoke_lookup_name(
        "grafana-query", "tools/call", {"name": "  delete_dashboard  "}
    ) == "delete_dashboard"
    # tools/list strips the alias name
    assert mcp_server._invoke_lookup_name("  x  ", "tools/list", {}) == "x"
