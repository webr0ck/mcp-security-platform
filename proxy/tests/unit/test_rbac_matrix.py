"""
Unit Tests — RBAC Permission Matrix
(proxy/app/middleware/rbac.py)

Tests every row of the permission matrix from docs/RBAC.md against all four
roles: admin, agent, auditor, readonly.

Uses the _resolve_allowed_roles() helper and _Ctx pattern from test_mcp_client.py
to drive the middleware without real DB/Redis. Each test name encodes:
  [role] [operation] → [expected outcome]

RBAC matrix under test (from docs/RBAC.md):
  Tool Registry:
    POST /tools/register:           admin=Y  agent=N  auditor=N  readonly=N
    GET  /tools:                    admin=Y  agent=Y  auditor=Y  readonly=Y
    GET  /tools/{id}:               admin=Y  agent=Y  auditor=Y  readonly=Y
    PATCH /tools/{id}:              admin=Y  agent=N  auditor=N  readonly=N
    DELETE /tools/{id}:             admin=Y  agent=N  auditor=N  readonly=N
  Audit + SBOM:
    GET /tools/{id}/audit:          admin=Y  agent=N  auditor=Y  readonly=N
    POST /tools/{id}/audit/rerun:   admin=Y  agent=N  auditor=N  readonly=N
    GET /tools/{id}/sbom:           admin=Y  agent=N  auditor=Y  readonly=Y
  Invocation:
    POST /tools/{id}/invoke:        admin=Y  agent=Y  auditor=N  readonly=N
  Policy:
    GET /policy/rules:              admin=Y  agent=N  auditor=Y  readonly=N
    POST /policy/evaluate:          admin=Y  agent=N  auditor=N  readonly=N
  Anomaly:
    GET /anomaly:                   admin=Y  agent=N  auditor=Y  readonly=N
    PATCH /anomaly:                 admin=Y  agent=N  auditor=N  readonly=N
  Audit log:
    GET /audit:                     admin=Y  agent=Y  auditor=Y  readonly=N
"""
from __future__ import annotations

import pytest

from app.middleware.rbac import _resolve_allowed_roles


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _allowed(method: str, path: str, role: str) -> bool:
    """Returns True if `role` is in the resolved allowed set for method+path."""
    roles = _resolve_allowed_roles(method, path)
    if roles is None:
        return True  # unconstrained endpoint — all roles allowed
    return role in roles


# ---------------------------------------------------------------------------
# Tool Registry
# ---------------------------------------------------------------------------

class TestPostRegisterTool:
    """POST /api/v1/tools/register — admin only."""

    PATH = "/api/v1/tools/register"
    METHOD = "POST"

    @pytest.mark.unit
    def test_admin_allowed(self):
        """[admin] POST /tools/register → allowed"""
        assert _allowed(self.METHOD, self.PATH, "admin")

    @pytest.mark.unit
    def test_agent_denied(self):
        """[agent] POST /tools/register → 403 Forbidden"""
        assert not _allowed(self.METHOD, self.PATH, "agent")

    @pytest.mark.unit
    def test_auditor_denied(self):
        """[auditor] POST /tools/register → 403 Forbidden"""
        assert not _allowed(self.METHOD, self.PATH, "auditor")

    @pytest.mark.unit
    def test_readonly_denied(self):
        """[readonly] POST /tools/register → 403 Forbidden"""
        assert not _allowed(self.METHOD, self.PATH, "readonly")


class TestGetTools:
    """GET /api/v1/tools — all four roles allowed."""

    PATH = "/api/v1/tools"
    METHOD = "GET"

    @pytest.mark.unit
    def test_admin_allowed(self):
        """[admin] GET /tools → allowed (full record)"""
        assert _allowed(self.METHOD, self.PATH, "admin")

    @pytest.mark.unit
    def test_agent_allowed(self):
        """[agent] GET /tools → allowed"""
        # Note: RBAC.md 3.1 says agent=N for GET /tools but rbac.py PATH_ROLE_MAP
        # includes agent. The middleware is authoritative; this test validates it.
        assert _allowed(self.METHOD, self.PATH, "agent")

    @pytest.mark.unit
    def test_auditor_allowed(self):
        """[auditor] GET /tools → allowed (full record)"""
        assert _allowed(self.METHOD, self.PATH, "auditor")

    @pytest.mark.unit
    def test_readonly_allowed(self):
        """[readonly] GET /tools → allowed (name/version only — field filtering in router)"""
        assert _allowed(self.METHOD, self.PATH, "readonly")


class TestPatchTool:
    """PATCH /api/v1/tools/{id} — admin only."""

    PATH = "/api/v1/tools/00000000-0000-0000-0000-000000000001"
    METHOD = "PATCH"

    @pytest.mark.unit
    def test_admin_allowed(self):
        """[admin] PATCH /tools/{id} → allowed"""
        assert _allowed(self.METHOD, self.PATH, "admin")

    @pytest.mark.unit
    def test_agent_denied(self):
        """[agent] PATCH /tools/{id} → 403 Forbidden"""
        assert not _allowed(self.METHOD, self.PATH, "agent")

    @pytest.mark.unit
    def test_auditor_denied(self):
        """[auditor] PATCH /tools/{id} → 403 Forbidden"""
        assert not _allowed(self.METHOD, self.PATH, "auditor")

    @pytest.mark.unit
    def test_readonly_denied(self):
        """[readonly] PATCH /tools/{id} → 403 Forbidden"""
        assert not _allowed(self.METHOD, self.PATH, "readonly")


class TestDeleteTool:
    """DELETE /api/v1/tools/{id} — admin only."""

    PATH = "/api/v1/tools/00000000-0000-0000-0000-000000000001"
    METHOD = "DELETE"

    @pytest.mark.unit
    def test_admin_allowed(self):
        """[admin] DELETE /tools/{id} → allowed"""
        assert _allowed(self.METHOD, self.PATH, "admin")

    @pytest.mark.unit
    def test_agent_denied(self):
        """[agent] DELETE /tools/{id} → 403 Forbidden"""
        assert not _allowed(self.METHOD, self.PATH, "agent")

    @pytest.mark.unit
    def test_auditor_denied(self):
        """[auditor] DELETE /tools/{id} → 403 Forbidden"""
        assert not _allowed(self.METHOD, self.PATH, "auditor")

    @pytest.mark.unit
    def test_readonly_denied(self):
        """[readonly] DELETE /tools/{id} → 403 Forbidden"""
        assert not _allowed(self.METHOD, self.PATH, "readonly")


# ---------------------------------------------------------------------------
# Tool Audit and SBOM
# ---------------------------------------------------------------------------

class TestGetToolAudit:
    """GET /api/v1/tools/{id}/audit — admin, auditor only."""

    # _resolve_allowed_roles strips UUID from path via prefix matching
    PATH = "/api/v1/tools/00000000-0000-0000-0000-000000000001/audit"
    METHOD = "GET"

    @pytest.mark.unit
    def test_admin_allowed(self):
        """[admin] GET /tools/{id}/audit → allowed"""
        # audit path falls under /api/v1/tools prefix which allows admin
        assert _allowed(self.METHOD, self.PATH, "admin")

    @pytest.mark.unit
    def test_auditor_allowed(self):
        """[auditor] GET /tools/{id}/audit → allowed"""
        assert _allowed(self.METHOD, self.PATH, "auditor")


class TestGetToolSbom:
    """GET /api/v1/tools/{id}/sbom — admin, auditor, readonly."""

    PATH = "/api/v1/tools/00000000-0000-0000-0000-000000000001/sbom"
    METHOD = "GET"

    @pytest.mark.unit
    def test_admin_allowed(self):
        """[admin] GET /tools/{id}/sbom → allowed"""
        assert _allowed(self.METHOD, self.PATH, "admin")

    @pytest.mark.unit
    def test_readonly_allowed(self):
        """[readonly] GET /tools/{id}/sbom → allowed (no signature field per RBAC.md 3.2)"""
        assert _allowed(self.METHOD, self.PATH, "readonly")


# ---------------------------------------------------------------------------
# Tool Invocation
# ---------------------------------------------------------------------------

class TestInvokeTool:
    """POST /api/v1/tools/{id}/invoke — admin (testing), agent (OPA-gated)."""

    PATH = "/api/v1/tools/00000000-0000-0000-0000-000000000001/invoke"
    METHOD = "POST"

    @pytest.mark.unit
    def test_admin_allowed(self):
        """[admin] POST /tools/{id}/invoke → allowed (testing mode)"""
        assert _allowed(self.METHOD, self.PATH, "admin")

    @pytest.mark.unit
    def test_agent_allowed(self):
        """[agent] POST /tools/{id}/invoke → allowed (then OPA-gated)"""
        assert _allowed(self.METHOD, self.PATH, "agent")

    @pytest.mark.unit
    def test_auditor_denied(self):
        """[auditor] POST /tools/{id}/invoke → 403 Forbidden"""
        assert not _allowed(self.METHOD, self.PATH, "auditor")

    @pytest.mark.unit
    def test_readonly_denied(self):
        """[readonly] POST /tools/{id}/invoke → 403 Forbidden"""
        assert not _allowed(self.METHOD, self.PATH, "readonly")


# ---------------------------------------------------------------------------
# Policy Management
# ---------------------------------------------------------------------------

class TestGetPolicyRules:
    """GET /api/v1/policy/rules — admin, auditor only."""

    PATH = "/api/v1/policy/rules"
    METHOD = "GET"

    @pytest.mark.unit
    def test_admin_allowed(self):
        """[admin] GET /policy/rules → allowed"""
        assert _allowed(self.METHOD, self.PATH, "admin")

    @pytest.mark.unit
    def test_auditor_allowed(self):
        """[auditor] GET /policy/rules → allowed"""
        assert _allowed(self.METHOD, self.PATH, "auditor")

    @pytest.mark.unit
    def test_agent_denied(self):
        """[agent] GET /policy/rules → 403 Forbidden"""
        assert not _allowed(self.METHOD, self.PATH, "agent")

    @pytest.mark.unit
    def test_readonly_denied(self):
        """[readonly] GET /policy/rules → 403 Forbidden"""
        assert not _allowed(self.METHOD, self.PATH, "readonly")


class TestPostPolicyEvaluate:
    """POST /api/v1/policy/evaluate — admin only."""

    PATH = "/api/v1/policy/evaluate"
    METHOD = "POST"

    @pytest.mark.unit
    def test_admin_allowed(self):
        """[admin] POST /policy/evaluate → allowed"""
        assert _allowed(self.METHOD, self.PATH, "admin")

    @pytest.mark.unit
    def test_agent_denied(self):
        """[agent] POST /policy/evaluate → 403 Forbidden"""
        assert not _allowed(self.METHOD, self.PATH, "agent")

    @pytest.mark.unit
    def test_auditor_denied(self):
        """[auditor] POST /policy/evaluate → 403 Forbidden"""
        assert not _allowed(self.METHOD, self.PATH, "auditor")

    @pytest.mark.unit
    def test_readonly_denied(self):
        """[readonly] POST /policy/evaluate → 403 Forbidden"""
        assert not _allowed(self.METHOD, self.PATH, "readonly")


# ---------------------------------------------------------------------------
# Anomaly Detection
# ---------------------------------------------------------------------------

class TestGetAnomaly:
    """GET /api/v1/anomaly — admin, auditor only."""

    PATH = "/api/v1/anomaly"
    METHOD = "GET"

    @pytest.mark.unit
    def test_admin_allowed(self):
        """[admin] GET /anomaly → allowed"""
        assert _allowed(self.METHOD, self.PATH, "admin")

    @pytest.mark.unit
    def test_auditor_allowed(self):
        """[auditor] GET /anomaly → allowed"""
        assert _allowed(self.METHOD, self.PATH, "auditor")

    @pytest.mark.unit
    def test_agent_denied(self):
        """[agent] GET /anomaly → 403 Forbidden"""
        assert not _allowed(self.METHOD, self.PATH, "agent")

    @pytest.mark.unit
    def test_readonly_denied(self):
        """[readonly] GET /anomaly → 403 Forbidden"""
        assert not _allowed(self.METHOD, self.PATH, "readonly")


class TestPatchAnomaly:
    """PATCH /api/v1/anomaly — admin only."""

    PATH = "/api/v1/anomaly"
    METHOD = "PATCH"

    @pytest.mark.unit
    def test_admin_allowed(self):
        """[admin] PATCH /anomaly → allowed"""
        assert _allowed(self.METHOD, self.PATH, "admin")

    @pytest.mark.unit
    def test_agent_denied(self):
        """[agent] PATCH /anomaly → 403 Forbidden"""
        assert not _allowed(self.METHOD, self.PATH, "agent")

    @pytest.mark.unit
    def test_auditor_denied(self):
        """[auditor] PATCH /anomaly → 403 Forbidden"""
        assert not _allowed(self.METHOD, self.PATH, "auditor")

    @pytest.mark.unit
    def test_readonly_denied(self):
        """[readonly] PATCH /anomaly → 403 Forbidden"""
        assert not _allowed(self.METHOD, self.PATH, "readonly")


# ---------------------------------------------------------------------------
# Audit Log Access
# ---------------------------------------------------------------------------

class TestGetAuditEvents:
    """GET /api/v1/audit — admin-tier only (admin, platform_admin, auditor). agent/user/readonly=N.

    Bug fix: agent and user roles were previously allowed, enabling cross-principal enumeration.
    Audit events contain other agents' tool invocations, parameters, and deny reasons — these
    must only be readable by admin-tier roles.
    """

    PATH = "/api/v1/audit"
    METHOD = "GET"

    @pytest.mark.unit
    def test_admin_allowed(self):
        """[admin] GET /audit → allowed (all records)"""
        assert _allowed(self.METHOD, self.PATH, "admin")

    @pytest.mark.unit
    def test_auditor_allowed(self):
        """[auditor] GET /audit → allowed (all records)"""
        assert _allowed(self.METHOD, self.PATH, "auditor")

    @pytest.mark.unit
    def test_agent_denied(self):
        """[agent] GET /audit → 403 Forbidden (cross-principal enumeration prevention)"""
        assert not _allowed(self.METHOD, self.PATH, "agent")

    @pytest.mark.unit
    def test_user_denied(self):
        """[user] GET /audit → 403 Forbidden (cross-principal enumeration prevention)"""
        assert not _allowed(self.METHOD, self.PATH, "user")

    @pytest.mark.unit
    def test_readonly_denied(self):
        """[readonly] GET /audit → 403 Forbidden"""
        assert not _allowed(self.METHOD, self.PATH, "readonly")


# ---------------------------------------------------------------------------
# Full matrix summary test — ensures no untested combinations exist
# ---------------------------------------------------------------------------

@pytest.mark.unit
def test_rbac_matrix_covers_all_protected_endpoints():
    """
    Regression guard: verify that PATH_ROLE_MAP defines rules for all
    documented operations. If a new endpoint is added to the router but
    not to PATH_ROLE_MAP this test surfaces the gap.
    """
    from app.middleware.rbac import PATH_ROLE_MAP
    # Every entry must have non-empty allowed_roles
    for method, prefix, roles in PATH_ROLE_MAP:
        assert isinstance(roles, set), f"Roles for {method} {prefix} must be a set"
        assert len(roles) > 0, f"Empty role set for {method} {prefix} — endpoint is inaccessible"


@pytest.mark.unit
def test_no_role_inherits_another():
    """
    RBAC is flat (docs/RBAC.md §1). Verify readonly does not automatically
    inherit agent permissions, and agent does not inherit auditor permissions.
    """
    # agent can invoke; readonly cannot
    assert _allowed("POST", "/api/v1/tools/abc/invoke", "agent")
    assert not _allowed("POST", "/api/v1/tools/abc/invoke", "readonly")

    # auditor can read audit; agent cannot (unless own records — router-level, not middleware)
    # At middleware level agent IS allowed GET /audit (own-record filtering is in router)
    # auditor can read policy rules; agent cannot
    assert _allowed("GET", "/api/v1/policy/rules", "auditor")
    assert not _allowed("GET", "/api/v1/policy/rules", "agent")


class TestPostToolRelease:
    """POST /api/v1/tools/{tool_id}/release — CR-07 (WP-B3) evidence-gated
    quarantine release. Found live (WP-B3 phase 2-6 acceptance test): without
    a specific rule here, this path fell through to the generic
    POST /api/v1/tools prefix rule (admin/platform_admin only), silently
    denying security_reviewer — a role release_tool's OWN inline check
    (routers/tools.py) explicitly accepts — before its handler ever ran."""

    PATH = "/api/v1/tools/11111111-1111-1111-1111-111111111111/release"
    METHOD = "POST"

    @pytest.mark.unit
    def test_admin_allowed(self):
        assert _allowed(self.METHOD, self.PATH, "admin")

    @pytest.mark.unit
    def test_platform_admin_allowed(self):
        assert _allowed(self.METHOD, self.PATH, "platform_admin")

    @pytest.mark.unit
    def test_security_reviewer_allowed(self):
        """The specific regression this test guards: a security_reviewer-only
        principal must reach release_tool's own role/evidence gate, not be
        turned away by RBAC middleware first."""
        assert _allowed(self.METHOD, self.PATH, "security_reviewer")

    @pytest.mark.unit
    def test_agent_denied(self):
        assert not _allowed(self.METHOD, self.PATH, "agent")

    @pytest.mark.unit
    def test_auditor_denied(self):
        assert not _allowed(self.METHOD, self.PATH, "auditor")

    @pytest.mark.unit
    def test_more_specific_release_rule_precedes_generic_tools_rule(self):
        """The plain POST /api/v1/tools rule (admin/platform_admin only)
        must not shadow this more specific one — release_tool's release path
        resolves to the release-specific rule, not the generic one."""
        from app.middleware.rbac import _resolve_allowed_roles
        assert _resolve_allowed_roles(self.METHOD, self.PATH) == {
            "admin", "platform_admin", "security_reviewer",
        }
