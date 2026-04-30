# MCP Security Platform — Core Authorization Policy
# Package: mcp.authz
#
# This is the primary policy evaluated for every tool invocation.
# INV-003: default allow = false is MANDATORY and must never be changed.
# INV-004: If this policy fails to load, OPA returns 500 which the proxy treats as deny.
#
# Input schema:
#   input.client_id        string   — resolved client identity
#   input.client_roles     [string] — role list for this client
#   input.tool_id          string   — UUID of the tool being invoked
#   input.tool_name        string   — name of the tool
#   input.tool_status      string   — "active" | "quarantined" | "deprecated"
#   input.tool_risk_level  string   — "low" | "medium" | "high" | "critical"
#   input.params           object   — tool invocation parameters (for pattern matching)
#   input.anomaly_score    number   — 0.0-1.0, current invocation anomaly score
#   input.is_testing       boolean  — true if called by admin for testing purposes

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

# Admins performing testing invocations bypass anomaly scoring
allow if {
    input.is_testing == true
    "admin" in input.client_roles
    tool_is_active
    count(deny) == 0
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
    some _k, val in input.params
    suspicious_param_value(val)
}

# =============================================================================
# HELPER RULES
# =============================================================================

tool_is_active if {
    input.tool_status == "active"
}

client_has_invoke_permission if {
    "agent" in input.client_roles
    tool_allowed_for_client(input.client_id, input.tool_name)
}

client_has_invoke_permission if {
    "agent" in input.client_roles
    some tag in data.mcp.grants[input.client_id].allowed_tags
    tag in data.mcp.tools[input.tool_name].tags
}

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

risk_level_within_threshold if {
    not data.mcp.grants[input.client_id].max_risk_level
    input.tool_risk_level == "low"
}

anomaly_threshold_exceeded if {
    input.anomaly_score > 0.85
}

tool_allowed_for_client(client_id, tool_name) if {
    tool_name in data.mcp.grants[client_id].allowed_tools
}

suspicious_param_value(val) if {
    is_string(val)
    regex.match(`(?i)(ignore previous|ignore all prior|you are now|act as|jailbreak)`, val)
}

# Expose deny reasons for audit logging and API response
reasons := deny
