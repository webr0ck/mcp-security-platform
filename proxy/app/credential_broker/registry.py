from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

import yaml

logger = logging.getLogger(__name__)


@dataclass
class ServerConfig:
    name: str
    url: str
    enabled: bool
    demand_activate: bool
    credential: dict[str, Any]


class Registry:
    """
    Loads and hot-reloads mcps.yaml.
    Call reload() on a background interval (30s) to pick up changes.
    """

    def __init__(self, path: str) -> None:
        self._path = path
        self._servers: dict[str, ServerConfig] = {}
        self.reload()

    def reload(self) -> None:
        try:
            with open(self._path) as f:
                raw = yaml.safe_load(f)
            self._servers = {
                name: ServerConfig(
                    name=name,
                    url=cfg["url"],
                    enabled=cfg.get("enabled", True),
                    demand_activate=cfg.get("demand_activate", False),
                    credential=cfg.get("credential", {}),
                )
                for name, cfg in (raw.get("servers") or {}).items()
            }
            logger.info("registry_reloaded", extra={"count": len(self._servers)})
        except Exception as exc:
            logger.error("registry_reload_failed", extra={"error": str(exc)})

    def enabled_servers(self) -> dict[str, ServerConfig]:
        return {k: v for k, v in self._servers.items() if v.enabled}

    def get(self, name: str) -> ServerConfig | None:
        return self._servers.get(name)
