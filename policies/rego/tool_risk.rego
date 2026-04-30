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
# =============================================================================

# Collect all risk flags as a set
risk_flags := flags if {
    flags := {flag | flag := _risk_flag[_]}
}

# Default: no flags
default risk_flags := set()

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

_risk_flag contains "network_unrestricted" if {
    some param_name in object.keys(input.schema.properties)
    any([
        contains(param_name, "url"),
        contains(param_name, "host"),
        contains(param_name, "endpoint"),
    ])
    not input.schema.properties[param_name].pattern
}

_risk_flag contains "no_source_repo" if {
    not input.source_repo
}

_risk_flag contains "shell_execution" if {
    some param_name in object.keys(input.schema.properties)
    any([
        contains(param_name, "command"),
        contains(param_name, "cmd"),
        contains(param_name, "exec"),
        contains(param_name, "shell"),
        contains(param_name, "script"),
    ])
}

_risk_flag contains "credential_parameter" if {
    some param_name in object.keys(input.schema.properties)
    any([
        contains(param_name, "password"),
        contains(param_name, "secret"),
        contains(param_name, "token"),
        contains(param_name, "key"),
        contains(param_name, "credential"),
    ])
}

_risk_flag contains "code_execution" if {
    some tag in input.tags
    any([
        tag == "exec",
        tag == "shell",
        tag == "code",
        tag == "eval",
    ])
}

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

static_risk_level := level if {
    static_risk_score >= 90
    level := "critical"
}

static_risk_level := level if {
    static_risk_score >= 70
    static_risk_score < 90
    level := "high"
}

static_risk_level := level if {
    static_risk_score >= 40
    static_risk_score < 70
    level := "medium"
}

static_risk_level := level if {
    static_risk_score < 40
    level := "low"
}
