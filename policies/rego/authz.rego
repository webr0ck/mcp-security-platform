# MCP Security Platform — Core Authorization Policy
# Package: mcp.authz
#
# This is the primary policy evaluated for every tool invocation.
# INV-003: default allow = false is MANDATORY and must never be changed.
# INV-004: If this policy fails to load, OPA returns 500 which the proxy treats as deny.
#
# Input schema:
#   input.client_id          string   — resolved client identity
#   input.client_roles       [string] — role list for this client
#   input.tool_id            string   — UUID of the tool being invoked
#   input.tool_name          string   — name of the tool
#   input.tool_status        string   — "active" | "quarantined" | "deprecated"
#   input.tool_risk_level    string   — "low" | "medium" | "high" | "critical"
#   input.tool_server_id     string   — UUID of the server owning this tool ("" when unlinked)
#   input.owned_server_ids   [string] — server UUIDs where caller has server_owner/manager role
#                                        (computed by proxy from server_role_grant, never from request body)
#   input.owner_max_risk_level string — risk ceiling set by admin for this server's owner/manager
#                                        (default "medium" until V025 adds the DB column)
#   input.params             object   — tool invocation parameters (for pattern matching)
#   input.anomaly_score      number   — 0.0-1.0, current invocation anomaly score
#   input.is_testing         boolean  — true if called by admin for testing purposes

package mcp.authz

import rego.v1

# INV-003: Deny by default. This line MUST NEVER be removed or changed to true.
default allow := false

# =============================================================================
# ALLOW rules
# All conditions must be satisfied. An explicit deny overrides any allow.
# =============================================================================

allow if {
    count(deny) == 0
    tool_is_active
    client_has_invoke_permission
    risk_level_within_threshold
    not anomaly_threshold_exceeded
}

# Admins performing testing invocations bypass anomaly scoring only.
# All other gates (inventory grant, risk-level cap, deny rules) still apply,
# so an admin cannot reach a tool that is outside their OPA inventory.
allow if {
    input.is_testing == true
    some role in input.client_roles
    role in {"admin", "platform_admin"}
    tool_is_active
    admin_has_test_permission
    risk_level_within_threshold
    count(deny) == 0
}

# Admins are only permitted to test tools explicitly listed in their grant or
# implied by an allowed tag — never tools outside the inventory.
admin_has_test_permission if {
    input.tool_name in data.mcp.grants[input.client_id].allowed_tools
}

admin_has_test_permission if {
    some tag in data.mcp.grants[input.client_id].allowed_tags
    tag in data.mcp.tools[input.tool_name].tags
}

# =============================================================================
# DENY rules (explicit, collected as a set for audit logging)
# =============================================================================

deny contains "tool_quarantined" if {
    input.tool_status == "quarantined"
}

deny contains "tool_deprecated" if {
    input.tool_status == "deprecated"
}

deny contains "client_not_authorized_for_tool" if {
    not client_has_invoke_permission
}

deny contains "risk_level_exceeds_threshold" if {
    not risk_level_within_threshold
}

deny contains "anomaly_threshold_exceeded" if {
    anomaly_threshold_exceeded
    not input.is_testing
}

deny contains "suspicious_parameter_pattern" if {
    some s in all_string_values(input.params)
    matches_prompt_injection(s)
}

# =============================================================================
# HELPER RULES
# =============================================================================

tool_is_active if {
    input.tool_status == "active"
}

# REMOVED 2026-06-04: internal bypass was a universal access control bypass.
# Internal tools now require explicit grant entries and respect risk thresholds.
# If platform tooling needs elevated access, use role 'platform_admin' with explicit grants.

client_has_invoke_permission if {
    some role in input.client_roles
    role in {"agent", "user"}
    tool_allowed_for_client(input.client_id, input.tool_name)
}

client_has_invoke_permission if {
    some role in input.client_roles
    role in {"agent", "user"}
    some tag in data.mcp.grants[input.client_id].allowed_tags
    tag in data.mcp.tools[input.tool_name].tags
}

# Admins (admin/platform_admin) may invoke any active tool
# without requiring explicit per-tool grants.  Critical/quarantined tools
# are still blocked by the risk-gate below.
client_has_invoke_permission if {
    some role in input.client_roles
    role in {"admin", "platform_admin"}
    input.tool_status == "active"
}

# Analysts with explicit grants may invoke tools within their risk threshold.
client_has_invoke_permission if {
    "analyst" in input.client_roles
    tool_allowed_for_client(input.client_id, input.tool_name)
}

# Platform-internal principal: allow access to explicitly granted internal tools only.
# This replaces the removed tool_status=="internal" bypass (OPA-001 fix).
client_has_invoke_permission if {
    input.client_id == "platform_internal"
    tool_allowed_for_client("platform_internal", input.tool_name)
}

# Owners/managers may invoke tools belonging to servers they own/manage.
# input.owned_server_ids is computed by the proxy from server_role_grant —
# it is NEVER taken from the request body.
# Both input.tool_server_id and input.owned_server_ids must be present and
# non-empty; absent or empty either field means the rule cannot fire (fail-closed).
client_has_invoke_permission if {
    some role in input.client_roles
    role in {"server_owner", "manager"}
    input.tool_server_id != ""
    input.tool_server_id in input.owned_server_ids
}

# 6.1: Platform meta-tools are authorized by ROLE, independent of per-client
# tool grants. They have no tool_registry row and no grant object, so the
# grant-based rules above never fire for them. Before this rule the proxy
# evaluated meta-tools under a hardcoded platform_admin identity, making OPA
# decorative for the /mcp built-ins. Now the real caller's roles decide.
client_has_invoke_permission if {
    caller_may_use_meta_tool
}

# REMOVED 2026-06-04: internal bypass was a universal access control bypass.
# Internal tools now require explicit grant entries and respect risk thresholds.
# If platform tooling needs elevated access, use role 'platform_admin' with explicit grants.

risk_level_value := {
    "low":      1,
    "medium":   2,
    "high":     3,
    "critical": 4,
}

risk_level_within_threshold if {
    client_max := data.mcp.grants[input.client_id].max_risk_level
    risk_level_value[input.tool_risk_level] <= risk_level_value[client_max]
}

# 6.1: Platform meta-tools are inherently low-risk platform reads with no
# per-client grant, so the grant-based risk gate does not apply to them.
# Role authorization (caller_may_use_meta_tool) is the control for meta-tools;
# deny rules (quarantine, prompt injection) still apply via count(deny)==0.
risk_level_within_threshold if {
    is_platform_meta_tool
}

# Owner risk ceiling: the ceiling is the value the approving admin explicitly
# set on the server row at approval time (server_registry.owner_max_risk_level,
# default 'medium' until V025 adds the DB column). Absent input → rule can't
# fire → falls back to grant-based ceiling = fail-closed.
# Both tool_server_id and owned_server_ids must be present for this to fire;
# missing either means the principal must satisfy the grant-based risk gate.
risk_level_within_threshold if {
    input.tool_server_id != ""
    input.tool_server_id in input.owned_server_ids
    risk_level_value[input.tool_risk_level] <= risk_level_value[input.owner_max_risk_level]
}

# REMOVED 2026-06-04: internal bypass was a universal access control bypass.
# Internal tools now require explicit grant entries and respect risk thresholds.
# If platform tooling needs elevated access, use role 'platform_admin' with explicit grants.

# REMOVED: fail-open fallback that allowed low-risk tools when max_risk_level was absent.
# Missing max_risk_level now falls through to deny (INV-003, FIND-005 fix).
# Every grant object must declare max_risk_level explicitly.

anomaly_threshold_exceeded if {
    input.anomaly_score > 0.85
}

tool_allowed_for_client(client_id, tool_name) if {
    tool_name in data.mcp.grants[client_id].allowed_tools
}

# =============================================================================
# 6.1 — PLATFORM META-TOOLS (proxy/app/routers/mcp_server.py _TOOLS)
# This map MUST mirror the _roles set declared on each entry in _TOOLS.
# If you change a meta-tool's _roles in the router, change it here too — the
# Python _can_call pre-filter and this OPA gate must agree.
# 'invoke_tool' is intentionally absent: it runs its own full OPA pipeline.
# =============================================================================
platform_meta_tool_roles := {
    "platform_info":          {"admin", "analyst", "viewer"},
    "security_pulse_summary": {"admin", "analyst"},
    "list_registered_tools":  {"admin", "analyst"},
    "enrollment_status":      {"admin", "analyst", "viewer"},
}

# A request is a platform meta-tool ONLY when the inline /mcp meta dispatch
# explicitly marks it (input.is_platform_meta == true) AND the name is one of the
# known meta-tools. The marker is never set on the registry invoke path
# (services/invocation.py), so a registry tool registered with a reserved name
# cannot inherit the meta-tool risk/grant bypass — the policy never trusts
# tool_name alone.
is_platform_meta_tool if {
    input.is_platform_meta == true
    platform_meta_tool_roles[input.tool_name]
}

caller_may_use_meta_tool if {
    some role in input.client_roles
    role in platform_meta_tool_roles[input.tool_name]
}

# Explicit deny reason for the audit trail when a caller reaches a meta-tool
# they are not entitled to (defense in depth behind the Python _can_call filter).
deny contains "meta_tool_role_not_authorized" if {
    is_platform_meta_tool
    not caller_may_use_meta_tool
}

matches_prompt_injection(s) if {
    is_string(s)
    regex.match(`(?i)(ignore previous|ignore all prior|you are now|act as|jailbreak)`, s)
}

# walk(x) yields every leaf of x. We keep the string ones.
all_string_values(x) := result if {
    result := [v |
        walk(x, [_, v])
        is_string(v)
    ]
}

# =============================================================================
# PROFILE-BASED ACCESS CONTROL (mcp_profiles table via input.profile)
# =============================================================================
# The proxy may inject input.profile.enabled and input.profile.allowed_functions
# when an mcp_profiles row exists for (client_id, tool_name).
# If no profile data is present, default = allow (backward-compatible).

deny contains "mcp_disabled_for_profile" if {
    input.profile.enabled == false
}

deny contains "function_not_allowed_for_profile" if {
    is_array(input.profile.allowed_functions)
    count(input.profile.allowed_functions) > 0
    not input.tool_function_name in input.profile.allowed_functions
    input.tool_function_name != ""
    input.tool_function_name != null
}

# Expose deny reasons for audit logging and API response
reasons := deny
