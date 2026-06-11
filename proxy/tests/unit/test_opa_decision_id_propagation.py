"""
Unit tests — Task 5.1 (LOG-F04): OPA decision_id propagation + INV-002 redaction

Verifies:
  1. evaluate_policy() captures the real decision_id from the OPA response body
     when decision logging is enabled (--set=decision_logs.console=true).
  2. evaluate_policy() falls back gracefully when decision_id is absent.
  3. The Promtail INV-002 redaction regex removes the "params" value from OPA
     decision log lines before they are shipped to Loki.
  4. An invocation with a token-shaped parameter must NOT appear raw in any
     Loki-bound OPA log line (INV-002 condition).

Run: pytest proxy/tests/unit/test_opa_decision_id_propagation.py -v
"""
from __future__ import annotations

import json
import re
from unittest.mock import AsyncMock, patch

import pytest

# ---------------------------------------------------------------------------
# The redaction regex used in promtail.yml (pipeline_stages.replace).
# Imported here as a constant so the test stays in sync with the config.
# If you update the regex in promtail.yml, update this constant too.
# ---------------------------------------------------------------------------
_PARAMS_REDACTION_REGEX = re.compile(
    r'"params"\s*:\s*(\{[^}]*\}|"[^"]*"|\[[^\]]*\]|[^,}]+)'
)
_PARAMS_REDACTION_REPLACEMENT = '"params":"[REDACTED:params]"'


def _apply_promtail_redaction(log_line: str) -> str:
    """
    Apply the same replace stage used in promtail.yml to a raw OPA decision log line.
    This mirrors what Promtail does before shipping to Loki.
    """
    return _PARAMS_REDACTION_REGEX.sub(_PARAMS_REDACTION_REPLACEMENT, log_line)


# ---------------------------------------------------------------------------
# Tests: evaluate_policy decision_id extraction
# ---------------------------------------------------------------------------

@pytest.mark.unit
async def test_evaluate_policy_returns_real_decision_id():
    """
    When OPA returns a decision_id in the response body (decision logging on),
    evaluate_policy must include it in the returned dict.
    Task 5.1: the caller (invocation.py) uses this instead of a local placeholder.
    """
    import httpx

    opa_response_body = {
        "decision_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
        "result": {"allow": True, "reasons": []},
    }
    fake_response = httpx.Response(
        status_code=200,
        content=json.dumps(opa_response_body).encode(),
        headers={"content-type": "application/json"},
    )

    with patch("httpx.AsyncClient.post", new=AsyncMock(return_value=fake_response)):
        from app.services.policy import evaluate_policy
        result = await evaluate_policy({"client_id": "agent-001", "tool_name": "ping"})

    assert result["allow"] is True
    assert result.get("decision_id") == "a1b2c3d4-e5f6-7890-abcd-ef1234567890", (
        "evaluate_policy must propagate OPA's real decision_id from the response body. "
        "This enables cross-stream correlation between audit_events and Loki mcp-opa-decisions."
    )


@pytest.mark.unit
async def test_evaluate_policy_decision_id_absent_returns_none():
    """
    When OPA does not return a decision_id (e.g. older OPA build or logging disabled),
    evaluate_policy must return None for the decision_id key — NOT raise.
    invocation.py falls back to a locally-generated placeholder in this case.
    """
    import httpx

    opa_response_body = {
        "result": {"allow": False, "reasons": ["tool_denied"]},
        # No decision_id key
    }
    fake_response = httpx.Response(
        status_code=200,
        content=json.dumps(opa_response_body).encode(),
        headers={"content-type": "application/json"},
    )

    with patch("httpx.AsyncClient.post", new=AsyncMock(return_value=fake_response)):
        from app.services.policy import evaluate_policy
        result = await evaluate_policy({"client_id": "agent-001", "tool_name": "ping"})

    assert result["allow"] is False
    assert result.get("decision_id") is None, (
        "When OPA does not return decision_id, evaluate_policy must return None "
        "(not raise KeyError). The caller handles the None→fallback logic."
    )


@pytest.mark.unit
async def test_evaluate_policy_decision_id_deny_path():
    """
    Decision_id must be captured on the DENY path as well.
    Both allow=True and allow=False audit events need the correlation ID.
    """
    import httpx

    opa_response_body = {
        "decision_id": "dead-beef-1234-5678-90ab-cdef01234567",
        "result": {"allow": False, "reasons": ["high_risk_tool"]},
    }
    fake_response = httpx.Response(
        status_code=200,
        content=json.dumps(opa_response_body).encode(),
        headers={"content-type": "application/json"},
    )

    with patch("httpx.AsyncClient.post", new=AsyncMock(return_value=fake_response)):
        from app.services.policy import evaluate_policy
        result = await evaluate_policy({"client_id": "agent-002", "tool_name": "exec_shell"})

    assert result["allow"] is False
    assert result.get("decision_id") == "dead-beef-1234-5678-90ab-cdef01234567"


# ---------------------------------------------------------------------------
# Tests: INV-002 promtail redaction of OPA decision log params
# ---------------------------------------------------------------------------

@pytest.mark.unit
def test_promtail_redaction_removes_params_object():
    """
    INV-002: OPA decision log containing a "params" JSON object must have
    the params value replaced with [REDACTED:params] before shipping to Loki.
    The decision_id and other fields must be preserved.
    """
    raw_log_line = json.dumps({
        "decision_id": "abc-123",
        "input": {
            "client_id": "agent-001",
            "tool_name": "secrets_fetch",
            "params": {"secret_name": "prod-db-password", "token": "ghp_ABC123XYZ"},
        },
        "result": {"allow": False},
        "timestamp": "2026-06-11T02:00:00Z",
    })

    redacted = _apply_promtail_redaction(raw_log_line)

    # Sensitive values must not appear in the redacted line
    assert "prod-db-password" not in redacted, (
        "INV-002: raw params content must not be present in Loki-bound log lines. "
        "Secret 'prod-db-password' found after redaction."
    )
    assert "ghp_ABC123XYZ" not in redacted, (
        "INV-002: token-shaped value in params must be redacted before shipping to Loki."
    )
    assert "[REDACTED:params]" in redacted, (
        "Redacted line must contain the sentinel [REDACTED:params] marker."
    )

    # Non-sensitive fields must be preserved for correlation
    assert "abc-123" in redacted, "decision_id must be preserved after redaction."
    assert "agent-001" in redacted, "client_id must be preserved after redaction."


@pytest.mark.unit
def test_promtail_redaction_token_shaped_param_not_in_loki():
    """
    INV-002 condition (from Task 5.1): an invocation with a token-shaped
    parameter must NOT appear raw in any Loki-bound OPA log line.

    This test simulates a caller passing an API key as a tool parameter.
    The redaction pipeline stage must strip it from the line before it reaches Loki.
    """
    # Simulate what OPA would log: the full input including raw params
    token = "AKIAIOSFODNN7EXAMPLE"   # AWS-key-shaped token for test purposes
    raw_opa_decision_log = json.dumps({
        "decision_id": "test-decision-id-001",
        "input": {
            "client_id": "test-agent",
            "tool_name": "s3_list_buckets",
            "params": {"aws_access_key": token, "region": "us-east-1"},
        },
        "result": {"allow": True},
        "timestamp": "2026-06-11T02:00:00Z",
    })

    # Apply the same replace stage Promtail runs before shipping to Loki
    loki_bound_line = _apply_promtail_redaction(raw_opa_decision_log)

    # The token must NOT appear in what Loki receives
    assert token not in loki_bound_line, (
        f"INV-002 VIOLATION: token-shaped value '{token}' found in Loki-bound "
        "OPA log line. The Promtail replace stage must redact 'params' values "
        "before the line is shipped to Loki."
    )
    assert "[REDACTED:params]" in loki_bound_line


@pytest.mark.unit
def test_promtail_redaction_preserves_non_params_fields():
    """
    Redaction must be surgical: only the 'params' value is replaced.
    decision_id, result, timestamp, client_id, tool_name must survive intact
    so OPA decision log lines remain useful for policy analysis.
    """
    raw_log_line = json.dumps({
        "decision_id": "keep-this-id",
        "input": {
            "client_id": "analyst-001",
            "tool_name": "read_file",
            "params": {"path": "/etc/shadow"},
        },
        "result": {"allow": False, "reasons": ["path_denied"]},
        "timestamp": "2026-06-11T02:30:00Z",
        "bundles": {"mcp": {"revision": "v1.2.3"}},
    })

    redacted = _apply_promtail_redaction(raw_log_line)

    assert "keep-this-id" in redacted
    assert "analyst-001" in redacted
    assert "read_file" in redacted
    assert "path_denied" in redacted
    assert "2026-06-11T02:30:00Z" in redacted
    assert "v1.2.3" in redacted
    # Sensitive path value must be gone
    assert "/etc/shadow" not in redacted


@pytest.mark.unit
def test_promtail_redaction_no_params_field_is_noop():
    """
    If an OPA log line does not contain a 'params' field (e.g. health-check
    or bundle-load log), the replace stage must not alter the line.
    """
    non_decision_line = json.dumps({
        "level": "info",
        "msg": "Bundle loaded",
        "revision": "v1.0.0",
        "timestamp": "2026-06-11T02:00:01Z",
    })

    redacted = _apply_promtail_redaction(non_decision_line)

    # No 'params' field → line must be unchanged
    assert redacted == non_decision_line
