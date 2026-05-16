from __future__ import annotations
import pytest
import yaml
import tempfile
import os

SAMPLE_YAML = """
servers:
  grafana:
    url: "http://grafana:3000/mcp"
    enabled: true
    demand_activate: true
    credential:
      approach: B
      type: api_key
      inject_header: Authorization
      inject_prefix: "Bearer "
      adapter: grafana
  disabled-service:
    url: "http://disabled.internal/mcp"
    enabled: false
    demand_activate: true
    credential:
      approach: B
      type: api_key
      inject_header: X-Api-Key
      inject_prefix: ""
      adapter: netbox
"""

@pytest.mark.unit
def test_registry_loads_enabled_servers():
    from app.credential_broker.registry import Registry
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        f.write(SAMPLE_YAML)
        path = f.name
    try:
        reg = Registry(path)
        servers = reg.enabled_servers()
        assert "grafana" in servers
        assert "disabled-service" not in servers
    finally:
        os.unlink(path)

@pytest.mark.unit
def test_registry_returns_server_config():
    from app.credential_broker.registry import Registry, ServerConfig
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        f.write(SAMPLE_YAML)
        path = f.name
    try:
        reg = Registry(path)
        cfg = reg.get("grafana")
        assert isinstance(cfg, ServerConfig)
        assert cfg.url == "http://grafana:3000/mcp"
        assert cfg.credential["approach"] == "B"
    finally:
        os.unlink(path)

@pytest.mark.unit
def test_registry_reload_picks_up_changes():
    from app.credential_broker.registry import Registry
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        f.write(SAMPLE_YAML)
        path = f.name
    try:
        reg = Registry(path)
        assert "grafana" in reg.enabled_servers()

        with open(path, "w") as f2:
            updated = yaml.safe_load(SAMPLE_YAML)
            updated["servers"]["grafana"]["enabled"] = False
            yaml.dump(updated, f2)

        reg.reload()
        assert "grafana" not in reg.enabled_servers()
    finally:
        os.unlink(path)
