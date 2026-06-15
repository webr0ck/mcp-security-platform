"""
Tests for the adapter plugin registry (adapters/registry.py).

The decisive guarantee: a NEW credential adapter that self-registers via
@register_adapter is wired into both the runtime broker (factory.build_broker)
and the enrollment flow (oauth._get_adapter) with ZERO edits to those files.
That is what makes an MCP server a drop-in "logical block".
"""
from __future__ import annotations

import pytest
from unittest.mock import MagicMock, patch

from app.credential_broker.adapters import registry


@pytest.mark.unit
def test_all_known_adapters_discovered():
    """All six shipped adapters self-register with the correct approach."""
    specs = {(s.approach, s.name) for s in registry.all_specs()}
    assert ("B", "grafana") in specs
    assert ("B", "netbox") in specs
    assert ("B", "gitea") in specs
    assert ("A", "m365") in specs
    assert ("A", "bitbucket") in specs
    assert ("A", "dex") in specs


@pytest.mark.unit
def test_get_spec_resolves_by_name_and_optional_approach():
    assert registry.get_spec("m365").approach == "A"
    assert registry.get_spec("grafana").approach == "B"
    assert registry.get_spec("m365", approach="B") is None  # wrong approach
    assert registry.get_spec("does-not-exist") is None


@pytest.mark.unit
def test_requires_gating_skips_unconfigured_adapter():
    """An adapter whose `requires` settings are unset is skipped by the broker."""
    sentinel = object()

    @registry.register_adapter(name="acme-gate", approach="B", requires=("ACME_TOKEN",))
    def _build(settings):  # pragma: no cover - exercised below
        return sentinel

    try:
        settings = MagicMock()
        settings.ACME_TOKEN = "present"
        _a, b = registry.build_adapters(settings)
        assert b["acme-gate"] is sentinel

        settings.ACME_TOKEN = ""  # unconfigured -> excluded
        _a2, b2 = registry.build_adapters(settings)
        assert "acme-gate" not in b2
    finally:
        registry._SPECS.pop(("B", "acme-gate"), None)


@pytest.mark.unit
def test_new_adapter_autowires_through_factory_with_zero_core_edits():
    """End-to-end drop-in proof: a freshly-registered adapter appears in the
    broker built by factory.build_broker WITHOUT touching factory.py."""
    from app.credential_broker.factory import build_broker

    sentinel = object()

    @registry.register_adapter(name="acme-e2e", approach="B", requires=("ACME_TOKEN",))
    def _build(settings):
        return sentinel

    try:
        settings = MagicMock()
        settings.VAULT_TOKEN = "hvs.real-vault-token"
        settings.VAULT_ADDR = "https://vault:8200"
        settings.VAULT_CA_BUNDLE = ""
        settings.BROKER_SESSION_TTL_SECONDS = 28800
        # Gate every other Approach-B adapter off so only acme-e2e remains in B.
        settings.GRAFANA_ADMIN_TOKEN = ""
        settings.NETBOX_ADMIN_TOKEN = ""
        settings.GITEA_ADMIN_TOKEN = ""
        settings.ACME_TOKEN = "present"

        with patch("app.credential_broker.factory.AsyncSessionLocal"):
            broker = build_broker(settings, MagicMock())

        assert broker._approach_b_adapters.get("acme-e2e") is sentinel
    finally:
        registry._SPECS.pop(("B", "acme-e2e"), None)


@pytest.mark.unit
def test_register_adapter_rejects_bad_approach():
    with pytest.raises(ValueError):
        @registry.register_adapter(name="bad", approach="C")
        def _build(settings):  # pragma: no cover
            return None
