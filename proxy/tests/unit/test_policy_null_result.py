"""
Unit tests — OPA null/undefined result handling in policy.py

Verifies INV-003 + INV-004: the pre-bundle-load race window where OPA returns
{"result": null} or {"result": {}} must be treated as deny, not crash or allow.

Run: pytest proxy/tests/unit/test_policy_null_result.py -v
"""
from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest


# ---------------------------------------------------------------------------
# Helpers — simulate what evaluate_policy does internally with the OPA body
# ---------------------------------------------------------------------------

def _parse_opa_body(body: dict) -> dict:
    """
    Reproduce the result-extraction logic from evaluate_policy so we can unit-test
    it without making real HTTP calls.

    Returns {"allow": bool, "reasons": list[str]}.
    """
    raw_result = body.get("result")
    result: dict = raw_result if isinstance(raw_result, dict) else {}
    allow: bool = bool(result.get("allow", False))
    reasons: list[str] = list(result.get("reasons", []))
    return {"allow": allow, "reasons": reasons}


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

@pytest.mark.unit
def test_opa_null_result_is_deny():
    """
    OPA returns {"result": null} during pre-bundle-load race window.
    INV-003 / INV-004: must be treated as deny (allow=False), never raise.
    """
    decision = _parse_opa_body({"result": None})
    assert decision["allow"] is False
    assert decision["reasons"] == []


@pytest.mark.unit
def test_opa_missing_allow_key_is_deny():
    """
    OPA returns {"result": {}} — result dict present but allow key absent.
    INV-003: default allow = false; missing key must yield allow=False.
    """
    decision = _parse_opa_body({"result": {}})
    assert decision["allow"] is False
    assert decision["reasons"] == []


@pytest.mark.unit
def test_opa_missing_result_key_is_deny():
    """
    OPA returns {} — result key entirely absent (unexpected response shape).
    INV-003: must yield allow=False rather than raising KeyError.
    """
    decision = _parse_opa_body({})
    assert decision["allow"] is False
    assert decision["reasons"] == []


@pytest.mark.unit
def test_opa_allow_false_explicit_is_deny():
    """
    OPA returns {"result": {"allow": false}} — normal deny path.
    Sanity-check that an explicit false is not accidentally coerced to True.
    """
    decision = _parse_opa_body({"result": {"allow": False, "reasons": ["policy_violation"]}})
    assert decision["allow"] is False
    assert "policy_violation" in decision["reasons"]


@pytest.mark.unit
def test_opa_allow_true_normal_path():
    """
    OPA returns {"result": {"allow": true}} — normal allow path unaffected.
    """
    decision = _parse_opa_body({"result": {"allow": True, "reasons": []}})
    assert decision["allow"] is True
    assert decision["reasons"] == []


@pytest.mark.unit
async def test_evaluate_policy_null_result_treated_as_deny():
    """
    End-to-end through evaluate_policy: when the mocked HTTP response body is
    {"result": null}, evaluate_policy must return {"allow": False, "reasons": []}.
    Verifies the fix is wired in the actual function, not just the helper above.
    """
    import httpx
    import json

    fake_response = httpx.Response(
        status_code=200,
        content=json.dumps({"result": None}).encode(),
        headers={"content-type": "application/json"},
    )

    with patch("httpx.AsyncClient.post", new=AsyncMock(return_value=fake_response)):
        from app.services.policy import evaluate_policy
        result = await evaluate_policy({"client_id": "test", "tool_name": "x"})

    assert result["allow"] is False
    assert result["reasons"] == []


@pytest.mark.unit
async def test_evaluate_policy_missing_allow_key_is_deny():
    """
    End-to-end: OPA returns {"result": {}} (allow key absent) →
    evaluate_policy must return allow=False.
    """
    import httpx
    import json

    fake_response = httpx.Response(
        status_code=200,
        content=json.dumps({"result": {}}).encode(),
        headers={"content-type": "application/json"},
    )

    with patch("httpx.AsyncClient.post", new=AsyncMock(return_value=fake_response)):
        from app.services.policy import evaluate_policy
        result = await evaluate_policy({"client_id": "test", "tool_name": "x"})

    assert result["allow"] is False
    assert result["reasons"] == []
