"""
Integration Test — OPA Deny-by-Default (INV-003)

Verifies that OPA returns deny=false for any input that does not match
an explicit allow rule. Tests against the live OPA sidecar container.

Run: pytest tests/integration/test_opa_deny_by_default.py -m integration
Requires: docker compose up opa proxy
"""
import pytest
import httpx

OPA_URL = "http://localhost:8181"
AUTHZ_ENDPOINT = f"{OPA_URL}/v1/data/mcp/authz/allow"


@pytest.mark.integration
@pytest.mark.asyncio
async def test_opa_deny_by_default_empty_input():
    """OPA must deny when input is empty (no rules match)."""
    async with httpx.AsyncClient() as client:
        resp = await client.post(AUTHZ_ENDPOINT, json={"input": {}})
    assert resp.status_code == 200
    body = resp.json()
    # result.allow must be false (or undefined = false) per INV-003
    result = body.get("result", {})
    allow = result.get("allow", False)
    assert allow is False, f"Expected allow=false, got {allow}. INV-003 violated."


@pytest.mark.integration
@pytest.mark.asyncio
async def test_opa_deny_unknown_client():
    """OPA must deny a client with no grants configured."""
    input_data = {
        "client_id": "unknown-client-no-grants",
        "client_roles": ["agent"],
        "tool_id": "00000000-0000-0000-0000-000000000001",
        "tool_name": "file_reader",
        "tool_status": "active",
        "tool_risk_level": "low",
        "params": {},
        "anomaly_score": 0.0,
        "is_testing": False,
    }
    async with httpx.AsyncClient() as client:
        resp = await client.post(AUTHZ_ENDPOINT, json={"input": input_data})
    assert resp.status_code == 200
    result = resp.json().get("result", {})
    allow = result.get("allow", False)
    assert allow is False, f"Expected deny for unknown client, got allow={allow}. INV-003 violated."


@pytest.mark.integration
@pytest.mark.asyncio
async def test_opa_deny_quarantined_tool():
    """OPA must deny invocation of a quarantined tool regardless of grants."""
    input_data = {
        "client_id": "agent-001",
        "client_roles": ["agent"],
        "tool_id": "00000000-0000-0000-0000-000000000002",
        "tool_name": "dangerous_tool",
        "tool_status": "quarantined",
        "tool_risk_level": "critical",
        "params": {},
        "anomaly_score": 0.0,
        "is_testing": False,
    }
    async with httpx.AsyncClient() as client:
        resp = await client.post(AUTHZ_ENDPOINT, json={"input": input_data})
    assert resp.status_code == 200
    result = resp.json().get("result", {})
    allow = result.get("allow", False)
    reasons = list(result.get("reasons", []))
    assert allow is False, f"Quarantined tool must always be denied. Got allow={allow}."
    assert "tool_quarantined" in reasons, f"Expected 'tool_quarantined' in reasons, got {reasons}."


@pytest.mark.integration
@pytest.mark.asyncio
async def test_opa_deny_high_anomaly_score():
    """OPA must deny when anomaly score exceeds threshold (0.85)."""
    input_data = {
        "client_id": "agent-001",
        "client_roles": ["agent"],
        "tool_id": "00000000-0000-0000-0000-000000000003",
        "tool_name": "file_reader",
        "tool_status": "active",
        "tool_risk_level": "low",
        "params": {},
        "anomaly_score": 0.95,  # Exceeds threshold
        "is_testing": False,
    }
    async with httpx.AsyncClient() as client:
        resp = await client.post(AUTHZ_ENDPOINT, json={"input": input_data})
    assert resp.status_code == 200
    result = resp.json().get("result", {})
    allow = result.get("allow", False)
    reasons = list(result.get("reasons", []))
    assert allow is False, f"High anomaly score must be denied. Got allow={allow}."
    assert "anomaly_threshold_exceeded" in reasons, (
        f"Expected 'anomaly_threshold_exceeded' in reasons, got {reasons}."
    )
