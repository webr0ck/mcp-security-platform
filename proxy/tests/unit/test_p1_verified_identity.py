"""P1-1 regression: OIDC identity must not be spoofable via an unverified email.

The credential broker derives a per-user KEK from the identity key, and
role_assignments / OPA grants are keyed on it. If a caller could present an
arbitrary (self-edited, unverified) email as their identity, they could inherit
a privileged identity's roles and decrypt its brokered credentials. The realm
sets verifyEmail=true (a changed email becomes unverified until re-proven), and
the proxy only accepts a verified email as the identity key — otherwise it falls
back to the immutable sub. This test pins that rule.
"""
import pytest

from app.middleware.auth import verified_oidc_identity


@pytest.mark.unit
def test_verified_email_becomes_identity():
    assert verified_oidc_identity("uuid-sub-1", "alice@corp", True) == "alice@corp"


@pytest.mark.unit
def test_unverified_email_falls_back_to_sub_not_email():
    # The spoofing scenario: caller claims a privileged email but it isn't verified.
    assert verified_oidc_identity("uuid-sub-1", "admin@corp", False) == "uuid-sub-1"


@pytest.mark.unit
def test_absent_email_uses_sub():
    assert verified_oidc_identity("uuid-sub-1", "", False) == "uuid-sub-1"
    assert verified_oidc_identity("uuid-sub-1", "", True) == "uuid-sub-1"
