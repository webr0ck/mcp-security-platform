# MCP Security Platform — Anomaly Detection Policy
# Package: mcp.anomaly
#
# Supplementary policy evaluated by the proxy's anomaly service.
# The proxy evaluates the anomaly score independently; this policy provides
# structured Rego-based rules for specific known-bad invocation sequences.
#
# These rules do NOT gate invocations directly — they produce deny reasons
# that are merged into the authz.rego evaluation via input.anomaly_score.
#
# Known exfiltration chains are defined as sequence patterns. The proxy
# anomaly service computes the score; OPA verifies specific structural patterns.

package mcp.anomaly

import rego.v1

# Default: no structural anomaly detected by this policy
default structural_anomaly := false

# structural_deny_reasons is an incremental set — no default needed (empty set by default in Rego v1)

# =============================================================================
# KNOWN EXFILTRATION CHAIN: web_search followed by bulk file_read
# Triggers when recent_calls contains this pattern within a time window.
#
# input.recent_calls: [{tool_name: string, timestamp: number}] — last N calls
# input.window_seconds: number — time window to evaluate
# =============================================================================

structural_anomaly if {
    web_search_then_bulk_read
}

structural_anomaly if {
    bulk_read_spike
}

web_search_then_bulk_read if {
    # Count web_search calls in the window
    web_searches := [c | c := input.recent_calls[_]; c.tool_name == "web_search"]
    count(web_searches) >= 2

    # Count file_read calls immediately after
    file_reads := [c | c := input.recent_calls[_]; contains(c.tool_name, "file_read")]
    count(file_reads) >= 5
}

bulk_read_spike if {
    # More than 10 file-read-type calls in the window
    file_reads := [c | c := input.recent_calls[_]; contains(c.tool_name, "file")]
    count(file_reads) > 10
}

structural_deny_reasons contains "exfiltration_chain_detected" if {
    web_search_then_bulk_read
}

structural_deny_reasons contains "bulk_file_read_spike" if {
    bulk_read_spike
}

# =============================================================================
# KNOWN EXFILTRATION CHAIN: code execution after credential access
# =============================================================================

structural_anomaly if {
    credential_then_exec
}

# Helper: tool_name indicates credential access
_is_cred_tool(name) if contains(name, "secret")
_is_cred_tool(name) if contains(name, "credential")
_is_cred_tool(name) if contains(name, "vault")
_is_cred_tool(name) if contains(name, "env")

# Helper: tool_name indicates code/shell execution
_is_exec_tool(name) if contains(name, "exec")
_is_exec_tool(name) if contains(name, "shell")
_is_exec_tool(name) if contains(name, "run")
_is_exec_tool(name) if contains(name, "command")

credential_then_exec if {
    cred_calls := [c |
        c := input.recent_calls[_]
        _is_cred_tool(c.tool_name)
    ]
    count(cred_calls) >= 1

    exec_calls := [c |
        c := input.recent_calls[_]
        _is_exec_tool(c.tool_name)
    ]
    count(exec_calls) >= 1
}

structural_deny_reasons contains "credential_access_then_exec" if {
    credential_then_exec
}
