"""
MCP Security Platform — Adapter Plugin Registry

Self-registering discovery layer for credential adapters. This is what makes an
MCP server a drop-in "logical block": an adapter module declares HOW to build
itself and WHEN it is configured, and this registry wires it into both the
runtime credential broker (factory.build_broker) and the enrollment flow
(routers/oauth._get_adapter) with ZERO edits to those call sites.

Contract for an adapter module (see adapters/grafana.py for the canonical shape):

    from app.credential_broker.adapters.registry import register_adapter

    @register_adapter(name="grafana", approach="B", requires=("GRAFANA_ADMIN_TOKEN",))
    def _build(settings):
        return GrafanaAdapter(
            base_url=settings.GRAFANA_BASE_URL,
            service_account_id=settings.GRAFANA_SERVICE_ACCOUNT_ID,
            admin_token=settings.GRAFANA_ADMIN_TOKEN,
        )

  - name:     the service key the broker / registry look up (must match the
              server_registry.service_name's credential adapter binding).
  - approach: "A" (per-user OAuth refresh: build_auth_url/exchange_code/refresh)
              or "B" (gateway-provisioned token: provision/revoke).
  - requires: settings attributes that must ALL be truthy for the broker to
              include this adapter. Empty () means "always include".
  - build:    pure constructor — takes Settings, returns the adapter instance.
              Never gates; gating is expressed declaratively via `requires`.

Adding a new credentialed MCP server is therefore: (1) drop one adapter module
that controls only its own tool/credential logic, (2) approve a server_registry
row. No core file changes.
"""
from __future__ import annotations

import importlib
import logging
import pkgutil
from dataclasses import dataclass
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)

# Modules in the adapters package that are infrastructure, not credential
# adapters, and therefore never register a spec. Skipped during discovery so a
# transitive import error in one of them cannot take down broker assembly.
_NON_ADAPTER_MODULES = frozenset({"__init__", "base", "registry", "healthcheck"})

# Keyed by (approach, name) so re-importing a module is idempotent (the spec is
# overwritten in place rather than appended twice).
_SPECS: dict[tuple[str, str], "AdapterSpec"] = {}
_discovered = False


@dataclass(frozen=True)
class AdapterSpec:
    """A registered credential adapter: how to build it and when it is configured."""

    name: str
    approach: str  # "A" | "B"
    build: Callable[[Any], Any]
    requires: tuple[str, ...] = ()

    def is_configured(self, settings: Any) -> bool:
        """True when every required setting is present and truthy."""
        return all(getattr(settings, attr, "") for attr in self.requires)


def register_adapter(
    *, name: str, approach: str, requires: tuple[str, ...] = ()
) -> Callable[[Callable[[Any], Any]], Callable[[Any], Any]]:
    """Decorator: register a builder function as the adapter for `name`."""
    if approach not in ("A", "B"):
        raise ValueError(f"approach must be 'A' or 'B', got {approach!r}")

    def deco(build_fn: Callable[[Any], Any]) -> Callable[[Any], Any]:
        _SPECS[(approach, name)] = AdapterSpec(
            name=name, approach=approach, build=build_fn, requires=tuple(requires)
        )
        return build_fn

    return deco


def discover_adapters(force: bool = False) -> None:
    """Import every adapter module so its @register_adapter decorator runs.

    Idempotent: imports are cached by Python; the (approach, name) keying means a
    re-run overwrites rather than duplicates. A module that fails to import is
    logged and skipped — one broken adapter must not break the rest.
    """
    global _discovered
    if _discovered and not force:
        return
    from app.credential_broker import adapters as _pkg

    for mod in pkgutil.iter_modules(_pkg.__path__):
        if mod.name in _NON_ADAPTER_MODULES:
            continue
        try:
            importlib.import_module(f"{_pkg.__name__}.{mod.name}")
        except Exception as exc:  # pragma: no cover - defensive
            logger.error(
                "adapter_discovery_import_failed",
                extra={"module": mod.name, "error": str(exc)},
            )
    _discovered = True


def all_specs() -> list[AdapterSpec]:
    """Every registered adapter spec (triggers discovery on first call)."""
    discover_adapters()
    return list(_SPECS.values())


def get_spec(name: str, approach: Optional[str] = None) -> Optional[AdapterSpec]:
    """Look up a spec by service name (optionally constraining the approach)."""
    discover_adapters()
    if approach is not None:
        return _SPECS.get((approach, name))
    for (appr, nm), spec in _SPECS.items():
        if nm == name:
            return spec
    return None


def build_adapters(settings: Any) -> tuple[dict[str, Any], dict[str, Any]]:
    """Build the broker's adapter dicts from every CONFIGURED adapter.

    Returns (approach_a_adapters, approach_b_adapters), each keyed by service
    name. Adapters whose `requires` settings are unset are skipped — matching the
    previous hand-written factory gating exactly.
    """
    discover_adapters()
    approach_a: dict[str, Any] = {}
    approach_b: dict[str, Any] = {}
    for spec in _SPECS.values():
        if not spec.is_configured(settings):
            continue
        instance = spec.build(settings)
        target = approach_a if spec.approach == "A" else approach_b
        target[spec.name] = instance
    return approach_a, approach_b
