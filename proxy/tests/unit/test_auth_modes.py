"""Unit tests for the canonical auth-mode model (Codex review CR-02)."""
from __future__ import annotations

import pytest


def test_auth_mode_values_are_superset_of_injection_mode():
    """AuthMode must stay a superset of InjectionMode's actual runtime values —
    the canonical model must never drift behind what the dispatcher enforces."""
    from app.services.auth_modes import AuthMode
    from app.credential_broker.dispatcher import InjectionMode

    auth_values = {m.value for m in AuthMode}
    injection_values = {m.value for m in InjectionMode}
    missing = injection_values - auth_values
    assert not missing, f"AuthMode is missing dispatcher-enforced values: {missing}"


def test_every_auth_mode_has_info():
    from app.services.auth_modes import AuthMode, AUTH_MODES

    for mode in AuthMode:
        assert mode in AUTH_MODES, f"{mode} has no AuthModeInfo entry"
        info = AUTH_MODES[mode]
        assert info.label and info.description
        assert info.status in ("supported", "admin_only", "alias", "roadmap")


def test_is_self_service_selectable_matches_supported_status():
    from app.services.auth_modes import AuthMode, AUTH_MODES, is_self_service_selectable

    for mode in AuthMode:
        expected = AUTH_MODES[mode].status == "supported"
        assert is_self_service_selectable(mode) == expected


# basic_auth left this list with CR-05: it now has a dispatcher branch
# (_inject_basic_auth) and is status="supported"/selectable.
@pytest.mark.parametrize("mode", ["passthrough",
                                   "external_oauth_client_credentials",
                                   "external_oauth_user_token"])
def test_non_self_service_modes_are_not_selectable(mode):
    from app.services.auth_modes import AuthMode, is_self_service_selectable

    assert not is_self_service_selectable(AuthMode(mode))
