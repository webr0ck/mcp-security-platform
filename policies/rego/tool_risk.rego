# MCP Security Platform — Tool Risk Assessment Policy
# Package: mcp.tool_risk
#
# Provides Rego-based structural risk heuristics for tool schemas.
# These rules are evaluated during tool registration by the Tool Manifest Auditor
# as a fast, deterministic pre-screen before LLM scoring.
#
# The proxy POSTs the tool schema to OPA and receives risk_flags back.
# LLM (Ollama) scoring is done separately and combined with these flags.
#
# Input schema:
#   input.tool_name        string  — tool identifier
#   input.description      string  — tool description text
#   input.schema           object  — JSON Schema defining tool parameters
#   input.source_repo      string  — optional source repository URL
#   input.tags             [string] — tool taxonomy tags

package mcp.tool_risk

import rego.v1

# =============================================================================
# RISK FLAGS
# Each flag adds to the overall risk score in the proxy service.
# _risk_flag is an incremental set — all partial rules contribute to it.
# =============================================================================

_risk_flag contains "filesystem_unrestricted" if {
    some param_name, param_def in input.schema.properties
    contains(param_name, "path")
    not param_def.pattern
    not param_def.enum
}

_risk_flag contains "description_prompt_injection" if {
    injection_phrases := [
        "ignore previous",
        "ignore all prior",
        "you are now",
        "act as",
        "jailbreak",
        "disregard",
        "do not follow",
        "override instructions",
    ]
    some phrase in injection_phrases
    contains(lower(input.description), phrase)
}

_risk_flag contains "excessive_permissions_tag" if {
    "admin" in input.tags
}

_risk_flag contains "excessive_permissions_tag" if {
    "root" in input.tags
}

# Helper: param_name is a network-type parameter
_is_network_param(param_name) if contains(param_name, "url")
_is_network_param(param_name) if contains(param_name, "host")
_is_network_param(param_name) if contains(param_name, "endpoint")

_risk_flag contains "network_unrestricted" if {
    some param_name in object.keys(input.schema.properties)
    _is_network_param(param_name)
    not input.schema.properties[param_name].pattern
}

_risk_flag contains "no_source_repo" if {
    not input.source_repo
}

# Helper: param_name is a shell-execution-type parameter
_is_shell_param(param_name) if contains(param_name, "command")
_is_shell_param(param_name) if contains(param_name, "cmd")
_is_shell_param(param_name) if contains(param_name, "exec")
_is_shell_param(param_name) if contains(param_name, "shell")
_is_shell_param(param_name) if contains(param_name, "script")

_risk_flag contains "shell_execution" if {
    some param_name in object.keys(input.schema.properties)
    _is_shell_param(param_name)
}

# Helper: param_name is a credential-type parameter
_is_cred_param(param_name) if contains(param_name, "password")
_is_cred_param(param_name) if contains(param_name, "secret")
_is_cred_param(param_name) if contains(param_name, "token")
_is_cred_param(param_name) if contains(param_name, "key")
_is_cred_param(param_name) if contains(param_name, "credential")

_risk_flag contains "credential_parameter" if {
    some param_name in object.keys(input.schema.properties)
    _is_cred_param(param_name)
}

# Helper: tag indicates code execution
_is_exec_tag(tag) if tag == "exec"
_is_exec_tag(tag) if tag == "shell"
_is_exec_tag(tag) if tag == "code"
_is_exec_tag(tag) if tag == "eval"

_risk_flag contains "code_execution" if {
    some tag in input.tags
    _is_exec_tag(tag)
}

# Expose the complete set of flags as the top-level result
# _risk_flag is already a complete set; risk_flags is an alias for external query.
risk_flags := _risk_flag

# =============================================================================
# RISK SCORE COMPUTATION
# Converts flag count to a 0-100 score for combination with LLM score.
# =============================================================================

# Points per flag category
_flag_weights := {
    "filesystem_unrestricted":   25,
    "description_prompt_injection": 40,
    "excessive_permissions_tag": 30,
    "network_unrestricted":      20,
    "no_source_repo":            10,
    "shell_execution":           35,
    "credential_parameter":      30,
    "code_execution":            35,
}

static_risk_score := score if {
    points := [w | some flag in risk_flags; w := _flag_weights[flag]]
    raw := sum(points)
    score := min([100, raw])
}

default static_risk_score := 0

static_risk_level := "critical" if static_risk_score >= 90
static_risk_level := "high" if { static_risk_score >= 70; static_risk_score < 90 }
static_risk_level := "medium" if { static_risk_score >= 40; static_risk_score < 70 }
static_risk_level := "low" if static_risk_score < 40
