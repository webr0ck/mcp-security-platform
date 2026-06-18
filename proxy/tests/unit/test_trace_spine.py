"""Task 9 (PRD-0002): uniform trace fields emitted on every tool-call audit."""
import logging
import pytest
from unittest.mock import AsyncMock, MagicMock, patch


def _make_trace_fields(injection_mode: str, client_id: str, tool_name: str) -> dict:
    """Import from the module under test — this is the function we're adding."""
    from app.services.invocation import _compute_trace_fields
    return _compute_trace_fields(injection_mode=injection_mode, user_sub=client_id, tool_name=tool_name)


def test_service_mode_trace():
    f = _make_trace_fields("service", "alice", "grafana-query")
    assert f["injection_mode"] == "service"
    assert f["attribution_preserved"] is False
    assert f["idp_topology"] == "none"
    assert f["upstream_principal"] == "__service__"
    assert f["case_id"] == 2


def test_entra_client_credentials_trace():
    f = _make_trace_fields("entra_client_credentials", "alice", "m365-graph")
    assert f["injection_mode"] == "entra_client_credentials"
    assert f["attribution_preserved"] is False
    assert f["idp_topology"] == "second"
    assert f["upstream_principal"] == "__app__"
    assert f["case_id"] == 1


def test_user_mode_trace():
    f = _make_trace_fields("user", "alice", "netbox-query")
    assert f["injection_mode"] == "user"
    assert f["attribution_preserved"] is True
    assert f["idp_topology"] == "none"
    assert f["upstream_principal"] == "alice"
    assert f["case_id"] == 3


def test_kc_token_exchange_trace():
    f = _make_trace_fields("kc_token_exchange", "alice", "lab-tickets")
    assert f["injection_mode"] == "kc_token_exchange"
    assert f["attribution_preserved"] is True
    assert f["idp_topology"] == "same"
    assert f["upstream_principal"] == "alice"
    assert f["case_id"] == 4


def test_none_mode_trace():
    f = _make_trace_fields("none", "alice", "echo")
    assert f["attribution_preserved"] is False
    assert f["idp_topology"] == "none"
    assert f["case_id"] is None  # no assigned case
