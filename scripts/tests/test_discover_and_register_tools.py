import importlib.util, pathlib

_spec = importlib.util.spec_from_file_location(
    "discover_mod",
    pathlib.Path(__file__).resolve().parents[1] / "discover_and_register_tools.py",
)
discover_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(discover_mod)


def test_per_tool_insert_inherits_alias_config_via_subselect():
    sql = discover_mod.per_tool_upsert_sql(
        tool={"name": "ping", "description": "liveness", "inputSchema": {"type": "object"}},
        upstream_url="http://lab-mcp-echo:8000/mcp", new_tool_status="active",
    )
    assert "'ping'" in sql
    assert "FROM tool_registry alias" in sql
    for col in ("alias.server_id", "alias.injection_mode", "alias.service_name",
                "alias.inject_header", "alias.inject_prefix", "alias.credential_id",
                "alias.source_repo"):
        assert col in sql, col
    assert "http://lab-mcp-echo:8000/mcp" in sql
    assert "ON CONFLICT (name, version)" in sql
    assert "per-tool" in sql
    assert "CASE WHEN EXCLUDED.status = 'active' AND tool_registry.status <> 'deprecated' THEN 'active'" in sql
    assert "ELSE tool_registry.status END" in sql


def test_per_tool_insert_uses_requested_status():
    sql = discover_mod.per_tool_upsert_sql(
        tool={"name": "delete_dashboard", "description": "", "inputSchema": {}},
        upstream_url="http://lab-mcp-grafana:8000/mcp", new_tool_status="quarantined",
    )
    assert "'quarantined'" in sql


def test_status_for_tool_is_flag_driven():
    assert discover_mod.status_for_tool(activate=True) == "active"
    assert discover_mod.status_for_tool(activate=False) == "quarantined"


def test_hide_alias_sql_defers_until_active_per_tool_exists():
    sql = discover_mod.hide_alias_sql("http://lab-mcp-echo:8000/mcp")
    assert "UPDATE tool_registry" in sql
    assert "'hidden'" in sql and "true" in sql
    assert "deleted_at" not in sql.split("WHERE")[0]   # not soft-deleting
    assert "status" not in sql.split("WHERE")[0]       # not changing alias status
    assert "EXISTS" in sql and "status = 'active'" in sql and "'per-tool'" in sql
