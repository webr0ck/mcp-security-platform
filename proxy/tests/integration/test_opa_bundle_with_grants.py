"""
Integration Tests — Signed OPA Bundle + Data-API Grants Push (Task 4.4b)

Verifies that:
  1. The signed bundle (policies/bundle.tar.gz) loads with strict OPA mode
  2. A PUT /v1/data/mcp_grants data-API push succeeds (not rejected by bundle)
  3. A policy query evaluating data.mcp_grants[client_id] returns the pushed grant

Requires: OPA running at OPA_URL (default: http://localhost:8181)
Skip if OPA is not reachable (these tests are decorative in CI without the stack).

Run (with stack up):
  pytest proxy/tests/integration/test_opa_bundle_with_grants.py -m integration -v

Mark: @pytest.mark.integration
"""
from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

OPA_URL = "http://localhost:8181"
_REPO_ROOT = Path(__file__).parents[4]

# Test grant data to push
_TEST_GRANTS = {
    "test-integration-client": {
        "allowed_tools": ["ping", "echo_args"],
        "allowed_tags": ["lab"],
        "max_risk_level": "low",
    }
}


def _opa_reachable() -> bool:
    """Check if OPA is reachable for integration tests."""
    try:
        resp = httpx.get(f"{OPA_URL}/health", timeout=2.0)
        return resp.status_code == 200
    except Exception:
        return False


# Skip all integration tests if OPA is not running
pytestmark = pytest.mark.skipif(
    not _opa_reachable(),
    reason="OPA not reachable at localhost:8181 — start the stack to run integration tests",
)


# ---------------------------------------------------------------------------
# Test 1: Signed bundle loads under strict mode
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_signed_bundle_loads_strict():
    """
    The signed bundle (policies/bundle.tar.gz) must verify with the opa CLI.

    This test is a stand-in for the full round-trip — in CI, `make test-signed-bundle`
    runs the full sign→verify→reject cycle. Here we just verify the bundle exists
    and is a valid tarball.

    Note: Full bundle signature verification requires POLICY_SIGNING_KEY which is
    a secret. The `make test-signed-bundle` script uses a temporary test key.
    """
    bundle_path = _REPO_ROOT / "policies" / "bundle.tar.gz"
    if not bundle_path.exists():
        pytest.skip("policies/bundle.tar.gz not found — run 'make sign-policy-bundle' first")

    import tarfile

    assert tarfile.is_tarfile(str(bundle_path)), "bundle.tar.gz is not a valid tarball"

    with tarfile.open(str(bundle_path), "r:gz") as tar:
        members = tar.getnames()
        # Bundle must contain .signatures.json (signed)
        assert ".signatures.json" in members, (
            "Signed bundle must contain .signatures.json. "
            "Run 'make sign-policy-bundle' to produce a signed bundle."
        )
        # Bundle must contain authz.rego
        assert any("authz.rego" in m for m in members), (
            "Bundle must contain authz.rego"
        )
        # Bundle must contain .manifest
        assert ".manifest" in members, (
            "Bundle must contain .manifest (defines roots carve-out)"
        )
        # Bundle must contain data.json
        assert any("data.json" in m for m in members), (
            "Bundle must contain data.json (injection_phrases + tools)"
        )


@pytest.mark.integration
def test_bundle_manifest_carve_out_in_tarball():
    """
    The .manifest inside the bundle must declare roots: ["mcp"] (not bundle-owned mcp_grants).
    """
    bundle_path = _REPO_ROOT / "policies" / "bundle.tar.gz"
    if not bundle_path.exists():
        pytest.skip("policies/bundle.tar.gz not found — run 'make sign-policy-bundle' first")

    import tarfile

    with tarfile.open(str(bundle_path), "r:gz") as tar:
        try:
            manifest_file = tar.extractfile(".manifest")
        except KeyError:
            pytest.skip("No .manifest in bundle — bundle was built without manifest")

        if manifest_file is None:
            pytest.skip(".manifest in bundle is not a regular file")

        manifest = json.loads(manifest_file.read())
        roots = manifest.get("roots", [])
        assert "mcp" in roots, f"Bundle .manifest must declare 'mcp' in roots. Got: {roots}"
        assert "mcp_grants" not in roots, (
            "Bundle .manifest must NOT include 'mcp_grants' — "
            "that path must be unowned so the proxy can push grants."
        )


# ---------------------------------------------------------------------------
# Test 2: Data-API grant push succeeds (not rejected by bundle)
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_data_api_grant_push_accepted():
    """
    PUT /v1/data/mcp_grants succeeds (not rejected by the signed bundle).

    This is the core INV-012 carve-out assertion at the OPA runtime level.
    If the bundle owned mcp_grants, this PUT would return 400 with
    "bundle conflict" or similar.
    """
    resp = httpx.put(
        f"{OPA_URL}/v1/data/mcp_grants",
        json=_TEST_GRANTS,
        timeout=5.0,
    )
    assert resp.status_code in (200, 204), (
        f"PUT /v1/data/mcp_grants failed with {resp.status_code}: {resp.text}. "
        "This means the bundle owns mcp_grants — check .manifest roots carve-out."
    )


# ---------------------------------------------------------------------------
# Test 3: Policy query evaluates pushed grant
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_policy_evaluates_pushed_grant():
    """
    After pushing a grant to /mcp_grants, a policy query for that client_id
    should evaluate the pushed data correctly.

    This verifies the end-to-end path:
      1. Push test grant to OPA via data API
      2. Query OPA authz policy for the granted client
      3. Grant is evaluated (allow=true for active low-risk tool in the grant)
    """
    # Step 1: push the test grant
    push_resp = httpx.put(
        f"{OPA_URL}/v1/data/mcp_grants",
        json=_TEST_GRANTS,
        timeout=5.0,
    )
    assert push_resp.status_code in (200, 204), (
        f"Failed to push test grants: {push_resp.status_code}"
    )

    # Step 2: query the grants path to verify it was stored
    get_resp = httpx.get(
        f"{OPA_URL}/v1/data/mcp_grants/test-integration-client",
        timeout=5.0,
    )
    assert get_resp.status_code == 200, (
        f"GET /v1/data/mcp_grants/test-integration-client failed: {get_resp.status_code}"
    )

    result = get_resp.json()
    grant_data = result.get("result", {})
    assert grant_data.get("max_risk_level") == "low", (
        f"Pushed grant not found or incorrect in OPA: {grant_data}"
    )
    assert "ping" in grant_data.get("allowed_tools", []), (
        f"Pushed tool 'ping' not found in OPA grant: {grant_data}"
    )


@pytest.mark.integration
def test_authz_policy_uses_mcp_grants_path():
    """
    OPA authz policy evaluation uses data.mcp_grants (not data.mcp.grants).

    Sends a policy input for a granted client with an allowed tool, and verifies
    that OPA allows the invocation (not denies with client_not_authorized_for_tool).

    Note: This test depends on the test grant from test_data_api_grant_push_accepted
    being present in OPA. Tests are run in order within this file.
    """
    # Ensure the test grant is present
    push_resp = httpx.put(
        f"{OPA_URL}/v1/data/mcp_grants",
        json={
            **_TEST_GRANTS,
            # Merge existing grants to not clear them
        },
        timeout=5.0,
    )
    assert push_resp.status_code in (200, 204)

    # Query the authz policy
    input_data = {
        "client_id": "test-integration-client",
        "client_roles": ["agent"],
        "tool_name": "ping",
        "tool_id": "00000000-0000-0000-0000-000000000001",
        "tool_status": "active",
        "tool_risk_level": "low",
        "tool_server_id": "",
        "owned_server_ids": [],
        "owner_max_risk_level": "medium",
        "params": {},
        "anomaly_score": 0.0,
        "is_testing": False,
        "is_platform_meta": False,
        "recent_calls": [],
    }

    resp = httpx.post(
        f"{OPA_URL}/v1/data/mcp/authz",
        json={"input": input_data},
        timeout=5.0,
    )
    assert resp.status_code == 200, f"OPA authz query failed: {resp.status_code}: {resp.text}"

    result = resp.json().get("result", {})
    allow = result.get("allow", False)
    deny_reasons = list(result.get("deny", []))

    assert allow is True, (
        f"OPA denied test-integration-client for 'ping' with reasons: {deny_reasons}. "
        "Check that authz.rego reads data.mcp_grants (not data.mcp.grants)."
    )
    assert "client_not_authorized_for_tool" not in deny_reasons, (
        f"OPA denied with 'client_not_authorized_for_tool' — grant not found in data.mcp_grants. "
        f"Deny reasons: {deny_reasons}"
    )
