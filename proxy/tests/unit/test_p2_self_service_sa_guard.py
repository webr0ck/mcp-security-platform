"""P1-2 regression: self-service profile mutation must reject service accounts.

A Keycloak client_credentials (service-account) token must never mutate a
profile — a service account that can self-enable MCPs or expand its own
allowed_functions turns an automated credential compromise directly into scope
expansion. Only interactive humans manage profiles. Enforced fail-closed by
_assert_not_service_account, which _assert_may_write and every /me self-mutation
route call.
"""
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from app.routers.profiles import _assert_not_service_account, _assert_may_write


def _req(is_sa: bool, client_id: str = "svc-account", roles=None):
    return SimpleNamespace(
        state=SimpleNamespace(
            is_service_account=is_sa,
            client_id=client_id,
            client_roles=roles or [],
        ),
        url=SimpleNamespace(path="/api/v1/profiles/me/mcps/search-kb/enable"),
    )


@pytest.mark.unit
def test_service_account_blocked_from_mutation():
    with pytest.raises(HTTPException) as exc:
        _assert_not_service_account(_req(is_sa=True))
    assert exc.value.status_code == 403
    assert exc.value.detail == "self_service_unavailable_for_service_accounts"


@pytest.mark.unit
def test_human_not_blocked():
    _assert_not_service_account(_req(is_sa=False))  # must not raise


@pytest.mark.unit
def test_missing_flag_defaults_open_for_humans():
    # request.state without is_service_account (e.g. non-OIDC path) must not raise.
    req = SimpleNamespace(state=SimpleNamespace(client_id="alice@corp"),
                          url=SimpleNamespace(path="/x"))
    _assert_not_service_account(req)


@pytest.mark.unit
def test_assert_may_write_rejects_service_account_even_as_self():
    # A service account editing its OWN profile is still barred (the privesc path).
    with pytest.raises(HTTPException) as exc:
        _assert_may_write(_req(is_sa=True, client_id="svc-1"), principal="svc-1")
    assert exc.value.status_code == 403
    assert exc.value.detail == "self_service_unavailable_for_service_accounts"
