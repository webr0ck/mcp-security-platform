"""
Unit Tests — Grants DB Sync with OPA Bundle Roots Carve-out (Task 4.4b)

Verifies:
  1. After sync_grants_to_opa(), PUT /v1/data/mcp_grants is called (not /mcp/grants)
  2. The pushed data is a flat dict keyed by client_id
  3. INV-003: default allow = false is still present in authz.rego
  4. The bundle .manifest specifies roots: ["mcp"] (not [""] or [])
  5. data.json no longer contains mcp.grants (moved to client_grants table)

Run:
  pytest proxy/tests/unit/test_grants_db_sync.py -v
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest

from app.services.opa_data_sync import OPADataSync, _OPA_GRANTS_PATH
from app.services.policy import PolicyEngineError

# Repo root for checking policy files
# parents[0]=unit, parents[1]=tests, parents[2]=proxy, parents[3]=mcp-security-platform
_REPO_ROOT = Path(__file__).parents[3]
_AUTHZ_REGO = _REPO_ROOT / "policies" / "rego" / "authz.rego"
_DATA_JSON = _REPO_ROOT / "policies" / "rego" / "data.json"
_MANIFEST = _REPO_ROOT / "policies" / "rego" / ".manifest"


# ---------------------------------------------------------------------------
# INV-003: default allow = false must remain in authz.rego
# ---------------------------------------------------------------------------


def test_inv_003_default_allow_false_present():
    """
    INV-003: authz.rego must contain 'default allow := false'.

    This is a hard constraint — the absence of this line means OPA fails open.
    The test reads the file directly to detect accidental removal.
    """
    assert _AUTHZ_REGO.exists(), f"authz.rego not found at {_AUTHZ_REGO}"
    content = _AUTHZ_REGO.read_text()
    # Match either `:=` or `=` form (both are valid in Rego v1)
    import re
    match = re.search(r"default\s+allow\s*:?=\s*false", content)
    assert match is not None, (
        "INV-003 VIOLATED: 'default allow := false' not found in authz.rego. "
        "This is a hard constraint — OPA would fail open without it."
    )


# ---------------------------------------------------------------------------
# Bundle .manifest assertions (INV-012 bundle-roots carve-out)
# ---------------------------------------------------------------------------


def test_bundle_manifest_exists():
    """policies/rego/.manifest must exist for OPA bundle roots carve-out."""
    assert _MANIFEST.exists(), (
        f".manifest not found at {_MANIFEST}. "
        "This file is required to carve the 'mcp' root so the bundle does not "
        "own 'mcp_grants' (where grants are pushed at runtime)."
    )


def test_bundle_manifest_roots_is_mcp():
    """
    .manifest must declare roots: ["mcp"].

    This ensures the signed bundle owns only the "mcp" subtree (policies +
    injection_phrases + tool metadata). The "mcp_grants" path is NOT owned by
    the bundle, so the proxy can push grants via the OPA data API without
    conflict (INV-012 preserved).
    """
    assert _MANIFEST.exists()
    manifest = json.loads(_MANIFEST.read_text())

    assert "roots" in manifest, ".manifest must have a 'roots' key"
    roots = manifest["roots"]
    assert isinstance(roots, list), ".manifest roots must be a list"
    assert "mcp" in roots, (
        f"Bundle manifest must include 'mcp' in roots. Got: {roots}"
    )
    assert "mcp_grants" not in roots, (
        "Bundle manifest must NOT include 'mcp_grants' in roots — "
        "that path must be unowned so the proxy can write grants via data API."
    )


def test_bundle_manifest_does_not_own_all():
    """
    .manifest roots must not be an empty list [] (which means OPA owns everything).

    An empty roots list would make the bundle own all data paths, blocking
    any data-API writes to mcp_grants.
    """
    assert _MANIFEST.exists()
    manifest = json.loads(_MANIFEST.read_text())
    roots = manifest.get("roots", [])
    assert len(roots) > 0, (
        "Bundle manifest roots must not be empty — empty roots means the bundle "
        "owns ALL paths, blocking data-API writes to mcp_grants."
    )


# ---------------------------------------------------------------------------
# data.json assertions (grants removed)
# ---------------------------------------------------------------------------


def test_data_json_has_no_grants():
    """
    Task 4.4b: mcp.grants must NOT exist in data.json.

    Grants have been moved to the client_grants DB table. If data.json still
    contains mcp.grants, the bundle would carry stale static grants, leading
    to divergence between the bundle and DB-driven grants at runtime.
    """
    assert _DATA_JSON.exists(), f"data.json not found at {_DATA_JSON}"
    data = json.loads(_DATA_JSON.read_text())

    assert "mcp" in data, "data.json must still have 'mcp' key (injection_phrases + tools)"
    mcp = data["mcp"]
    assert "grants" not in mcp, (
        "data.json must NOT contain 'mcp.grants' after Task 4.4b. "
        "Grants are now in the client_grants DB table."
    )


def test_data_json_still_has_injection_phrases():
    """
    data.json must still contain mcp.injection_phrases.

    Injection phrases are used by authz.rego and tool_risk.rego via
    data.mcp.injection_phrases — they must remain in the bundle, not be
    moved to the DB.
    """
    assert _DATA_JSON.exists()
    data = json.loads(_DATA_JSON.read_text())
    mcp = data.get("mcp", {})
    assert "injection_phrases" in mcp, (
        "data.json must retain 'mcp.injection_phrases' — these stay in the bundle."
    )
    assert len(mcp["injection_phrases"]) > 0, "injection_phrases list must be non-empty"


def test_data_json_still_has_tools():
    """
    data.json must still contain mcp.tools (tool tag metadata).

    Tool tag metadata (used for tag-based grant matching in authz.rego) stays in
    the bundle. Only per-client grants moved to the DB.
    """
    assert _DATA_JSON.exists()
    data = json.loads(_DATA_JSON.read_text())
    mcp = data.get("mcp", {})
    assert "tools" in mcp, (
        "data.json must retain 'mcp.tools' — tool tag metadata stays in the bundle."
    )


# ---------------------------------------------------------------------------
# authz.rego data path assertions
# ---------------------------------------------------------------------------


def test_authz_rego_reads_mcp_grants_not_mcp_dot_grants():
    """
    authz.rego must reference data.mcp_grants (new path) and NOT data.mcp.grants (old path).

    After Task 4.4b, grants are pushed to OPA at /mcp_grants. Rego reads them as
    data.mcp_grants[client_id]. If authz.rego still references data.mcp.grants,
    policy evaluations will silently fail (empty grants → deny-all for non-admin).
    """
    assert _AUTHZ_REGO.exists()
    content = _AUTHZ_REGO.read_text()

    assert "data.mcp_grants" in content, (
        "authz.rego must reference 'data.mcp_grants' (Task 4.4b new path)"
    )
    # Count occurrences of old vs new pattern (excluding comments)
    lines = content.splitlines()
    code_lines = [l for l in lines if not l.strip().startswith("#")]
    code = "\n".join(code_lines)

    old_pattern_count = code.count("data.mcp.grants")
    assert old_pattern_count == 0, (
        f"authz.rego still references 'data.mcp.grants' on {old_pattern_count} code line(s). "
        "All grant references must use 'data.mcp_grants' after Task 4.4b."
    )


# ---------------------------------------------------------------------------
# OPADataSync: path and payload correctness
# ---------------------------------------------------------------------------


@pytest.fixture
def mock_db_pool() -> AsyncMock:
    return AsyncMock()


@pytest.fixture
def sample_client_grant_rows() -> list[dict[str, Any]]:
    return [
        {
            "client_id": "alice@corp",
            "allowed_tools": ["ping", "whoami"],
            "allowed_tags": ["lab"],
            "max_risk_level": "medium",
        },
        {
            "client_id": "test-agent-client",
            "allowed_tools": ["active-low-risk-tool"],
            "allowed_tags": [],
            "max_risk_level": "low",
        },
    ]


@pytest.mark.asyncio
async def test_sync_grants_to_opa_path(mock_db_pool, sample_client_grant_rows):
    """
    After push_grants(), PUT /v1/data/mcp_grants is called — not /v1/data/mcp/grants.

    This is the critical bundle-roots carve-out assertion for INV-012.
    """
    mock_db_pool.fetch.return_value = sample_client_grant_rows

    sync = OPADataSync(db_pool=mock_db_pool)

    with patch("app.services.opa_data_sync.OPAClient.put_data", new_callable=AsyncMock) as mock_put:
        await sync.push_grants()

        mock_put.assert_called_once()
        kwargs = mock_put.call_args[1]
        path = kwargs.get("path") or mock_put.call_args[0][0]

        assert path == "/mcp_grants", (
            f"OPA data push must use path /mcp_grants (bundle-unowned), got {path!r}. "
            "Path /mcp/grants would be rejected by the signed bundle (INV-012)."
        )


@pytest.mark.asyncio
async def test_sync_grants_to_opa_payload_structure(mock_db_pool, sample_client_grant_rows):
    """
    Pushed payload must be a flat dict keyed by client_id — readable in Rego as
    data.mcp_grants["alice@corp"].allowed_tools.
    """
    mock_db_pool.fetch.return_value = sample_client_grant_rows

    sync = OPADataSync(db_pool=mock_db_pool)

    with patch("app.services.opa_data_sync.OPAClient.put_data", new_callable=AsyncMock) as mock_put:
        await sync.push_grants()

        kwargs = mock_put.call_args[1]
        data = kwargs.get("data") or mock_put.call_args[0][1]

        # Must be a flat dict — not wrapped in {"mcp": {"grants": ...}}
        assert isinstance(data, dict)
        assert "mcp" not in data, "Payload must NOT be nested under 'mcp'"
        assert "alice@corp" in data
        assert "test-agent-client" in data

        alice = data["alice@corp"]
        assert "allowed_tools" in alice
        assert "allowed_tags" in alice
        assert "max_risk_level" in alice
        assert alice["max_risk_level"] == "medium"


@pytest.mark.asyncio
async def test_sync_grants_db_query_targets_client_grants(mock_db_pool, sample_client_grant_rows):
    """
    push_grants() must SELECT from client_grants table (V034), not role_assignments.

    role_assignments stores RBAC roles (admin, agent, auditor, readonly).
    client_grants stores per-client tool allowlists. They are different tables.
    """
    mock_db_pool.fetch.return_value = sample_client_grant_rows

    sync = OPADataSync(db_pool=mock_db_pool)

    with patch("app.services.opa_data_sync.OPAClient.put_data", new_callable=AsyncMock):
        await sync.push_grants()

    query = str(mock_db_pool.fetch.call_args[0][0])
    assert "client_grants" in query, (
        f"push_grants() must query 'client_grants' table. Query: {query}"
    )
    assert "role_assignments" not in query, (
        "push_grants() must NOT query 'role_assignments' — that table stores RBAC roles."
    )
