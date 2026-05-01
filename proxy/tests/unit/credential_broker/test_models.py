from __future__ import annotations
import pytest
from datetime import datetime, timezone, timedelta


@pytest.mark.unit
def test_token_is_expired():
    from app.credential_broker.models import Token
    past = datetime.now(timezone.utc) - timedelta(seconds=1)
    t = Token(value="tok", expires_at=past, token_id="id1")
    assert t.is_expired is True


@pytest.mark.unit
def test_token_not_expired():
    from app.credential_broker.models import Token
    future = datetime.now(timezone.utc) + timedelta(hours=1)
    t = Token(value="tok", expires_at=future, token_id="id1")
    assert t.is_expired is False


@pytest.mark.unit
def test_token_zero_clears_value():
    from app.credential_broker.models import Token
    future = datetime.now(timezone.utc) + timedelta(hours=1)
    t = Token(value="secret-tok", expires_at=future, token_id="id1")
    t.zero()
    assert t.value == ""


@pytest.mark.unit
def test_credential_result_fields():
    from app.credential_broker.models import CredentialResult
    future = datetime.now(timezone.utc) + timedelta(hours=1)
    cr = CredentialResult(token="abc", expires_at=future, approach="B", service="grafana")
    assert cr.approach == "B"
    assert cr.service == "grafana"
    assert cr.token_id is None


@pytest.mark.unit
def test_credential_result_zero():
    from app.credential_broker.models import CredentialResult
    future = datetime.now(timezone.utc) + timedelta(hours=1)
    cr = CredentialResult(token="secret", expires_at=future, approach="A", service="m365")
    cr.zero()
    assert cr.token == ""
