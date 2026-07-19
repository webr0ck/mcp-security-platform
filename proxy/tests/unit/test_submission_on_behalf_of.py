"""
Unit tests — X-On-Behalf-Of trust bridge for self-service submission ownership (T2).

Covers app.routers.submission._effective_owner: a trusted service principal
(submission_service role) may attribute a submission to a real user's sub via
X-On-Behalf-Of; any other caller sending that header is rejected (fail closed),
never silently downgraded to acting as itself.
"""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from fastapi import HTTPException, Request

from app.routers import submission


def _fake_request(client_id: str, roles: list[str], headers: dict[str, str]) -> Request:
    req = MagicMock(spec=Request)
    req.state = MagicMock()
    req.state.client_id = client_id
    req.state.client_roles = roles
    req.headers = headers
    return req


def test_no_header_returns_caller_identity():
    req = _fake_request("alice", [], {})
    assert submission._effective_owner(req) == "alice"


def test_trusted_service_can_act_on_behalf_of_real_user():
    req = _fake_request(
        "self-service", ["submission_service"], {"x-on-behalf-of": "alice-sub"}
    )
    assert submission._effective_owner(req) == "alice-sub"


def test_untrusted_caller_spoofing_header_is_rejected():
    """A caller without the submission_service role that sends X-On-Behalf-Of
    must be rejected outright (fail closed) — never silently ignored and
    never allowed to impersonate another owner_sub."""
    req = _fake_request("mallory", ["agent"], {"x-on-behalf-of": "alice-sub"})
    with pytest.raises(HTTPException) as exc_info:
        submission._effective_owner(req)
    assert exc_info.value.status_code == 403


def test_trusted_role_without_header_acts_as_itself():
    """Holding submission_service alone grants no ambient impersonation —
    only an explicit X-On-Behalf-Of header (plus the role) delegates."""
    req = _fake_request("self-service", ["submission_service"], {})
    assert submission._effective_owner(req) == "self-service"


if __name__ == "__main__":
    # ponytail: smallest runnable check — pytest not required to sanity-check.
    r1 = _fake_request("alice", [], {})
    assert submission._effective_owner(r1) == "alice"
    r2 = _fake_request("self-service", ["submission_service"], {"x-on-behalf-of": "alice-sub"})
    assert submission._effective_owner(r2) == "alice-sub"
    r3 = _fake_request("mallory", ["agent"], {"x-on-behalf-of": "alice-sub"})
    try:
        submission._effective_owner(r3)
        raise SystemExit("expected HTTPException for spoofed on-behalf-of header")
    except HTTPException as exc:
        assert exc.status_code == 403
    print("OK")
