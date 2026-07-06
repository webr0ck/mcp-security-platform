"""Tests for typed principal namespace (v3 spec) and CR-10 typed propagation."""
import pytest
from unittest.mock import patch


def test_oidc_session_builds_human_principal():
    from app.middleware.auth import _build_principal_id
    pid, ptype, issuer, display_sub = _build_principal_id("oidc_session", "alice")
    assert ptype == "human"
    assert pid.startswith("human:")
    assert "alice" in pid
    assert display_sub == "alice"
    assert issuer


def test_mtls_builds_agent_principal():
    from app.middleware.auth import _build_principal_id
    pid, ptype, issuer, display_sub = _build_principal_id("mtls", "svc.agent.local")
    assert ptype == "agent"
    assert pid.startswith("agent:")
    assert "svc.agent.local" in pid
    assert display_sub == "svc.agent.local"


def test_api_key_builds_human_principal():
    from app.middleware.auth import _build_principal_id
    pid, ptype, issuer, display_sub = _build_principal_id("api_key", "u123")
    assert ptype == "human"
    assert "apikey" in pid
    assert "u123" in pid
    assert issuer == "apikey"
    assert display_sub == "u123"


def test_agent_and_human_namespaces_are_disjoint():
    from app.middleware.auth import _build_principal_id
    agent_pid, _, _, _ = _build_principal_id("mtls", "alice")
    human_pid, _, _, _ = _build_principal_id("oidc_session", "alice")
    assert agent_pid != human_pid


def test_oidc_direct_builds_human_principal():
    from app.middleware.auth import _build_principal_id
    pid, ptype, issuer, display_sub = _build_principal_id("oidc", "bob@example.com")
    assert ptype == "human"
    assert pid.startswith("human:")
    assert "bob@example.com" in pid
    assert display_sub == "bob@example.com"


def test_collision_three_principal_types_same_bare_sub_are_disjoint():
    """
    CR-10 core acceptance test: an OIDC user, an API-key caller, and an mTLS
    agent sharing the IDENTICAL bare subject string must resolve to three
    DISTINCT typed principal ids — the exact collision this package exists
    to kill.
    """
    from app.middleware.auth import _build_principal_id

    bare_sub = "shared-subject-123"
    oidc_pid, oidc_type, _, oidc_display = _build_principal_id("oidc_session", bare_sub)
    apikey_pid, apikey_type, _, apikey_display = _build_principal_id("api_key", bare_sub)
    mtls_pid, mtls_type, _, mtls_display = _build_principal_id("mtls", bare_sub)

    # All three share the same display subject (the bare, non-authoritative sub)...
    assert oidc_display == apikey_display == mtls_display == bare_sub
    # ...but their typed principal ids (the actual credential/entitlement key) differ.
    ids = {oidc_pid, apikey_pid, mtls_pid}
    assert len(ids) == 3, f"typed principal ids collided: {ids}"
    # And their types are distinguishable even though oidc/api_key share "human".
    assert mtls_type == "agent"
    assert oidc_type == "human" and apikey_type == "human"
    assert oidc_pid != apikey_pid  # human:issuer:sub vs human:apikey:sub
