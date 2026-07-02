"""AN-04 regression: auditor gets read-only portal access, never write access.

The acceptance test found carol (auditor) got 403 on /portal itself because
_require_portal_access only allowed {agent, admin}. Auditor is a first-class
read role per docs/RBAC.md. These checks pin the read/write split so a future
edit can't silently grant auditors write actions (credential upload / profile
enable-disable) or re-lock them out of the read views.
"""
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from app.routers.portal import (
    _require_portal_access,
    _require_portal_write,
    _is_auditor_only,
)


def _req(roles):
    return SimpleNamespace(state=SimpleNamespace(client_roles=roles))


def _denied(fn, roles):
    try:
        fn(_req(roles))
        return False
    except HTTPException as exc:
        assert exc.status_code == 403
        return True


# --- read access (view) ---
@pytest.mark.parametrize("roles", [["agent"], ["admin"], ["auditor"], ["auditor", "agent"]])
def test_view_allowed(roles):
    assert _require_portal_access(_req(roles)) is None  # no raise


@pytest.mark.parametrize("roles", [[], ["reviewer"], ["readonly"]])
def test_view_denied(roles):
    assert _denied(_require_portal_access, roles)


# --- write access ---
@pytest.mark.parametrize("roles", [["agent"], ["admin"], ["auditor", "admin"]])
def test_write_allowed(roles):
    assert _require_portal_write(_req(roles)) is None


@pytest.mark.parametrize("roles", [["auditor"], [], ["reviewer"]])
def test_write_denied(roles):
    assert _denied(_require_portal_write, roles)


# --- auditor-only detection drives read-only UI ---
def test_is_auditor_only():
    assert _is_auditor_only(_req(["auditor"])) is True
    assert _is_auditor_only(_req(["auditor", "agent"])) is False  # also an agent → full use
    assert _is_auditor_only(_req(["admin"])) is False
    assert _is_auditor_only(_req([])) is False
