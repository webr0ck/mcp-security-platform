"""Tests for typed principal namespace (v3 spec)."""
import pytest
from unittest.mock import patch


def test_oidc_session_builds_human_principal():
    from app.middleware.auth import _build_principal_id
    pid, ptype = _build_principal_id("oidc_session", "alice")
    assert ptype == "human"
    assert pid.startswith("human:")
    assert "alice" in pid


def test_mtls_builds_agent_principal():
    from app.middleware.auth import _build_principal_id
    pid, ptype = _build_principal_id("mtls", "svc.agent.local")
    assert ptype == "agent"
    assert pid.startswith("agent:")
    assert "svc.agent.local" in pid


def test_api_key_builds_human_principal():
    from app.middleware.auth import _build_principal_id
    pid, ptype = _build_principal_id("api_key", "u123")
    assert ptype == "human"
    assert "apikey" in pid
    assert "u123" in pid


def test_agent_and_human_namespaces_are_disjoint():
    from app.middleware.auth import _build_principal_id
    agent_pid, _ = _build_principal_id("mtls", "alice")
    human_pid, _ = _build_principal_id("oidc_session", "alice")
    assert agent_pid != human_pid


def test_oidc_direct_builds_human_principal():
    from app.middleware.auth import _build_principal_id
    pid, ptype = _build_principal_id("oidc", "bob@example.com")
    assert ptype == "human"
    assert pid.startswith("human:")
    assert "bob@example.com" in pid
