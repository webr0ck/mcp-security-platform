from app.routers import mcp_server  # imports standalone — no DB/app context needed


def test_registered_tools_query_excludes_hidden():
    sql = mcp_server.REGISTERED_TOOLS_QUERY
    assert "metadata" in sql and "hidden" in sql
    assert "status = 'active'" in sql and "deleted_at IS NULL" in sql
    assert "COALESCE(metadata->>'hidden', 'false') <> 'true'" in sql
