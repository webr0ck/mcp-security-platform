# MCP Security Platform — Anomaly Detection Policy
# Package: mcp.anomaly
#
# Supplementary policy evaluated alongside `authz.rego` — see that file's
# "ANOMALY STRUCTURAL DENY RULES" section, which merges
# `data.mcp.anomaly.structural_deny_reasons` into its own `deny` set. Ported
# verbatim (semantics unchanged) from the Python platform's
# `policies/rego/anomaly.rego`; loaded into the SAME `regorus::Engine`
# instance as `authz.rego` by `engine.rs`'s `compile_entrypoints` — this
# file is not evaluated standalone.
#
# input.recent_calls: [{tool_name: string, timestamp: number}] — the
# principal's sliding window, populated from
# `mcphub_store::redis_store::RecentCall` by `bin/mcphubd/src/wiring/
# policy.rs`. A Redis read failure on that side must DENY, never send an
# empty list here — an empty `recent_calls` is indistinguishable from "this
# client has no history" from this policy's point of view, which is why
# that fail-closed behavior has to live on the Rust side, before this input
# is ever built.
# input.window_seconds: number — informational only; the window is already
# pre-filtered by the producer, this policy does not re-filter by time.

package mcp.anomaly

import rego.v1

default structural_anomaly := false

structural_anomaly if {
    web_search_then_bulk_read
}

structural_anomaly if {
    bulk_read_spike
}

web_search_then_bulk_read if {
    web_searches := [c | c := input.recent_calls[_]; c.tool_name == "web_search"]
    count(web_searches) >= 2

    file_reads := [c | c := input.recent_calls[_]; contains(c.tool_name, "file_read")]
    count(file_reads) >= 5
}

bulk_read_spike if {
    file_reads := [c | c := input.recent_calls[_]; contains(c.tool_name, "file")]
    count(file_reads) > 10
}

structural_deny_reasons contains "exfiltration_chain_detected" if {
    web_search_then_bulk_read
}

structural_deny_reasons contains "bulk_file_read_spike" if {
    bulk_read_spike
}

structural_anomaly if {
    credential_then_exec
}

_is_cred_tool(name) if contains(name, "secret")
_is_cred_tool(name) if contains(name, "credential")
_is_cred_tool(name) if contains(name, "vault")
_is_cred_tool(name) if contains(name, "env")

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
