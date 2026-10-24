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
#   input.anomaly_score      number   — 0.0-1.0, current invocation anomaly score.
#                                        Rust-rewrite: NOT READ BY THIS FILE — the
#                                        score is computed inside anomaly.rego from
#                                        input.recent_calls instead of being passed
#                                        in precomputed. See anomaly.rego's
#                                        "SCORE-BASED ANOMALY DETECTION" section.
#   input.is_testing         boolean  — true if called by admin for testing purposes
#
# Rust-rewrite addition (not present in the Python platform's contract —
# this file has diverged from policies/rego/authz.rego here, deliberately):
#   input.client_granted_roles [object] — role provenance, one entry per
#                                          granted role: {"role": <same
#                                          strings as client_roles>,
#                                          "asserted_by": <issuer id string>}.
#                                          Built by bin/mcphubd/src/wiring/
#                                          policy.rs from mcphub-types::
#                                          GrantedRole. See the comment at
#                                          client_has_invoke_permission below
#                                          for what this is (and isn't) for.

package mcp.authz

import rego.v1

# INV-003: Deny by default. This line MUST NEVER be removed or changed to true.
default allow := false

# =============================================================================
# GRANTS DATA PATH NOTE (Task 4.4b — SELF-F6)
# =============================================================================
# Client grants are read from data.mcp_grants (pushed by proxy OPADataSync
# via PUT /v1/data/mcp_grants on startup and every 60s).
#
# This path is intentionally OUTSIDE the "mcp" bundle root (see .manifest)
# so the proxy can push grants via the OPA data API without conflict.
# Previously grants lived at data.mcp.grants (bundle-owned); this was
# impossible to update at runtime without a full bundle re-sign + deploy.
#
# data.mcp_grants structure:
#   {
#     "alice@corp": {
#       "allowed_tools": ["ping", "echo_args", ...],
#       "allowed_tags": ["lab", "testing"],
#       "max_risk_level": "medium"
#     },
#     ...
#   }
#
# Rust-rewrite note, CONFIRMED (moved here from an adapter's header comment
# per the architect — a policy author reading this file, not an adapter's
# Rust doc comment, is who needs to see it):
#
# `data.mcp_grants[client_id]` above is NOT server-scoped — one flat record
# per principal. `mcphub-store`'s `grants` table IS server-scoped (one row
# per (principal, server)), so `bin/mcphubd/src/wiring/policy.rs`'s
# `sync_policy_data` UNIONS a principal's `allowed_tools`/`allowed_tags`
# across every server they have a grant on into this single flat record,
# and takes the max of their `max_risk_level`s. That is coarser than the
# real per-server grant: a principal entitled on server A for tool "x" and
# on server B for a differently-scoped tool "y" ends up with both "x" and
# "y" in one flat `allowed_tools` list here, with no way for THIS rule set
# to tell which server a given tool call is actually against.
#
# This is safe ONLY because of where this policy sits in the enforcement
# order (ARCHITECTURE.md): `... rbac → quarantine → entitlement
# (discovery==invoke) → rate limit / anomaly → policy (this file) → taint
# floor ...` — the entitlement gate, which IS per-server-scoped (`mcphub-
# policy::entitlement::GrantResolver`, keyed by the real per-tool/per-server
# catalog), runs and can already deny BEFORE this policy is ever evaluated.
# So a call this coarsened grant would (wrongly, in isolation) authorize —
# tool "y" reached via server A's context — has already been rejected
# upstream by entitlement before `data.mcp_grants` union-coarsening could
# matter. This rule set being more permissive than the real per-server grant
# can therefore never itself OPEN an access path the entitlement gate would
# have closed; it can only ever be redundant with (never looser than, in
# net effect) what already ran. If that enforcement ORDER ever changes —
# policy moving ahead of entitlement, or entitlement's own per-server
# scoping regressing — this argument breaks silently. Whoever changes that
# order must re-verify this note, not just the code that changed.
# =============================================================================

# =============================================================================
# ALLOW rules
# All conditions must be satisfied. An explicit deny overrides any allow.
# =============================================================================

allow if {
    count(deny) == 0
    tool_is_active
    client_has_invoke_permission
    risk_level_within_threshold
    # `not anomaly_threshold_exceeded` REMOVED here — see the "ANOMALY
    # STRUCTURAL DENY RULES" section below for why the score-cutoff
    # mechanism moved to anomaly.rego entirely (Rust-rewrite divergence).
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
    input.tool_name in data.mcp_grants[input.client_id].allowed_tools
}

admin_has_test_permission if {
    some tag in data.mcp_grants[input.client_id].allowed_tags
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

# Rust-rewrite divergence: the `anomaly_threshold_exceeded` deny rule (and
# the R-4 `is_liveness_probe`/`ping` exemption that went with it) moved to
# `anomaly.rego` — see this file's "ANOMALY STRUCTURAL DENY RULES" section
# below for the full writeup, and `anomaly.rego`'s "SCORE-BASED ANOMALY
# DETECTION" section for the ported logic (including the same `ping`
# liveness exemption, preserved verbatim).

deny contains "suspicious_parameter_pattern" if {
    some s in all_string_values(input.params)
    matches_prompt_injection(s)
}

# Stage 4: argument-aware deny — sensitive filesystem path patterns in any
# string argument value.  Blocks traversal and home-directory exfiltration
# attempts independent of which tool is being called.
deny contains "suspicious_path_argument" if {
    some s in all_string_values(input.params)
    is_string(s)
    _matches_sensitive_path(s)
}

_sensitive_path_patterns := [
    "../../../", "..\\", "~/.ssh", "~/.gnupg", "~/.aws",
    "/etc/passwd", "/etc/shadow", "/etc/sudoers",
    "/proc/", "/sys/", "/dev/",
]

_matches_sensitive_path(s) if {
    some pattern in _sensitive_path_patterns
    contains(lower(s), pattern)
}

# Stage 4: argument-aware deny — dangerous URL schemes in any string argument
# value.  Catches file://, javascript:, data: and other SSRF-enabling schemes
# that a model might be prompted to pass as a tool argument.
deny contains "suspicious_url_scheme" if {
    some s in all_string_values(input.params)
    is_string(s)
    _matches_dangerous_scheme(s)
}

_dangerous_schemes := ["file://", "javascript:", "data:", "vbscript:", "gopher://"]

_matches_dangerous_scheme(s) if {
    some scheme in _dangerous_schemes
    startswith(lower(s), scheme)
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

# Rust-rewrite note: `input.client_granted_roles` (see the input schema
# comment at the top of this file) carries per-role issuer provenance
# (`{"role": ..., "asserted_by": ...}`), not just the flat role name every
# rule below matches on. It exists because the primary defense against a
# less-trusted IDP asserting a high-privilege role (e.g. a contractor
# tenant's admin granting itself "mcphub-super-admin") is a ceiling
# enforced upstream, before role resolution — see `IdpConfig.
# max_assertable_role` in mcphub-identity — so no rule here needs it for
# that. It's here for a narrower, currently-unneeded case: a rule that
# wants to distinguish between two issuers that are BOTH entitled to assert
# the same role (e.g. treat the corporate IDP's `admin` differently from a
# trusted partner IDP's `admin`). No rule below reads it yet. If you're
# adding one that needs to, that's what it's for — do not re-plumb
# provenance through a separate proxy lookup, and do not write a rule
# against flat `client_roles` when what you actually need is
# `client_granted_roles`.
client_has_invoke_permission if {
    some role in input.client_roles
    role in {"agent", "user"}
    tool_allowed_for_client(input.client_id, input.tool_name)
}

client_has_invoke_permission if {
    some role in input.client_roles
    role in {"agent", "user"}
    some tag in data.mcp_grants[input.client_id].allowed_tags
    tag in data.mcp.tools[input.tool_name].tags
}

# Admins (admin/platform_admin) may invoke any active tool
# without requiring explicit per-tool grants.
# Quarantined tools are denied by status (blocked at app layer + deny rule above).
# Critical-risk tools require max_risk_level: critical in the caller's grant entry
# (see risk_level_within_threshold below) — they are NOT unconditionally blocked
# for admins.
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
    client_max := data.mcp_grants[input.client_id].max_risk_level
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

# `anomaly_cutoff`/`anomaly_threshold_exceeded` REMOVED here — moved to
# `anomaly.rego`. This is a CONFIRMED-real gap, not a stylistic move: this
# mechanism reads `input.anomaly_score`/`input.anomaly_cutoff`, both
# per-call-varying values (the score is derived from `input.recent_calls`,
# which changes almost every call) — exactly the class of field that
# broke the decision cache for the structural anomaly rules before those
# moved out of this file's `with input as {...}` indirection (see the
# "ANOMALY STRUCTURAL DENY RULES" section). Had this rule been fixed
# (populated with a real score/cutoff) IN PLACE here, in this cached
# module, every score-varying call would either poison the authz cache
# key or — worse — get served a STALE score-threshold verdict from a
# cache hit computed against a different call's score. It has to live in
# `anomaly.rego`, which is evaluated fresh on every call and never
# cached, for the same reason the structural rules do. See
# `anomaly.rego`'s "SCORE-BASED ANOMALY DETECTION" section for the ported
# scoring logic (from `proxy/app/services/anomaly.py`'s `_score_window`)
# and `engine.rs`'s `anomaly_policy` for how it's wired in.

tool_allowed_for_client(client_id, tool_name) if {
    tool_name in data.mcp_grants[client_id].allowed_tools
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
    # 2026-07-25: these four were MISSING, so is_platform_meta_tool was false for
    # them and they fell through to the generic allow, which requires
    # client_has_invoke_permission — a rule that recognises agent/user/admin/
    # platform_admin/analyst/platform_internal/server_owner/manager and NEVER
    # viewer or editor. Meanwhile _TOOLS grants exactly those roles. Result: a
    # viewer or editor SAW these in tools/list and was denied on tools/call —
    # the same listed-but-denied class as the discovery/invoke drift.
    #
    # This matters most for get_my_profile + enable_mcp_server: they are the
    # RECOVERY PATH out of a profile lockout (see _RECOVERY_MCPS in
    # routers/profiles.py). Recovery that only works for some roles is not
    # recovery. Sets below mirror _TOOLS[i]["_roles"] exactly, as the comment
    # above this map has always required.
    "list_available_mcps":    {"admin", "analyst", "viewer", "editor", "platform_admin", "agent"},
    "get_my_profile":         {"admin", "analyst", "viewer", "editor", "platform_admin", "agent"},
    "enable_mcp_server":      {"admin", "analyst", "editor", "platform_admin", "agent"},
    "disable_mcp_server":     {"admin", "analyst", "editor", "platform_admin", "agent"},
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

# Task 1.4: reads injection phrases from data.mcp.injection_phrases instead of
# an inline regex. This keeps authz.rego, response_filter.py, and tool_risk.rego
# in sync through a single canonical source (injection_patterns.py → data.json).
matches_prompt_injection(s) if {
    is_string(s)
    some phrase in data.mcp.injection_phrases
    contains(lower(s), phrase)
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

# Task 1.9 (SELF-F2): two deny rules for function-level profile restrictions.
#
# Rule A: named function not in the allowed list — the nominal case.
deny contains "function_not_allowed_for_profile" if {
    is_array(input.profile.allowed_functions)
    count(input.profile.allowed_functions) > 0
    not input.tool_function_name in input.profile.allowed_functions
    input.tool_function_name != ""
    input.tool_function_name != null
}

# Rule B: empty tool_function_name with a non-empty allowed_functions list.
# Semantics: if the profile restricts to specific functions, a call with no
# identified function name cannot satisfy the restriction. This closes the
# fail-open on the direct tools/call path where tool_function_name was
# previously always "" (derived from params.arguments instead of params.name).
# After Task 1.9's Python fix, this rule fires only on truly un-named invocations.
deny contains "function_not_allowed_for_profile" if {
    is_array(input.profile.allowed_functions)
    count(input.profile.allowed_functions) > 0
    input.tool_function_name == ""
}

# =============================================================================
# ANOMALY STRUCTURAL DENY RULES (Task 1.7 — DET-F3)
# =============================================================================
# Import structural deny reasons from mcp.anomaly and merge them into authz
# deny set via a single combined OPA query. The proxy populates input.recent_calls
# from the Redis sliding window before calling this policy.
#
# Failure semantics (enforced in invocation.py, not here):
#   - If recent_calls cannot be populated (Redis failure), the proxy raises
#     OPAUnavailableError → 503. Sending an empty recent_calls list would
#     silently bypass structural rules — that is the same class as INV-004.
#   - input.recent_calls absent or empty → anomaly structural rules simply
#     evaluate to false (no deny). This is the correct "no history" case.
#
# The anomaly score threshold rule (anomaly_threshold_exceeded) continues to
# operate on input.anomaly_score for backward compatibility. [Rust-rewrite:
# this rule no longer lives in this file at all — see below.]

# Rust-rewrite divergence, CONFIRMED regorus limitation (not present in
# policies/rego/authz.rego — that OPA-evaluated version merges anomaly
# reasons in-Rego via `with input as {...}`, below):
#
# The Python original's approach was:
#   deny contains reason if {
#       some reason in _anomaly_structural_deny_reasons
#   }
#   _anomaly_structural_deny_reasons := reasons if {
#       reasons := data.mcp.anomaly.structural_deny_reasons with input as {
#           "recent_calls": input.recent_calls,
#           "window_seconds": 300,
#       }
#   } else := set()
#
# Under regorus 0.11's PREPARED evaluation path (`Engine::
# compile_with_entrypoint` + `CompiledPolicy::eval_with_input` — what this
# crate's `engine.rs` uses for the ~4x performance win over the unprepared
# `eval_bool_query` API; see `engine.rs`'s module docs), evaluating ANY
# rule whose value is a composite type (array or set — confirmed with both,
# and confirmed it is NOT specific to incremental `contains` rules; a
# single complete `rule := [1,2,3]` static-literal rule reproduces it too)
# from INSIDE a `with input as {...}` scope fails with `"previous value is
# not an object"`, even on a completely unrelated in-package minimal
# 15-line repro with no cross-package reference at all. It works correctly
# through the UNPREPARED `eval_bool_query`/`eval_query` API on the exact
# same bundle/data/input — see `engine.rs`'s
# `anomaly_structural_rule_evaluates_correctly_via_unprepared_query_api`
# test, which passes. Root cause (not fully traced beyond this): `with`'s
# `apply_with_modifiers` resets `self.data` to a fresh clone of
# `with_document["data"]` on entering ANY `with` scope (even one that only
# overrides `input`, never `data`) — something about the compiled/prepared
# schedule's assumptions about rule-value write order does not survive that
# reset for non-scalar rule values. Filed as a regorus limitation, not
# fixed here (forking regorus was out of scope for this round).
#
# WORKAROUND (what this build actually does): `data.mcp.anomaly.
# structural_deny_reasons` is compiled as its OWN separate prepared
# entrypoint (`engine.rs`'s `anomaly_policy`) and evaluated directly against
# the SAME unmodified `input` — no `with input as {...}` remapping needed at
# all, because `anomaly.rego` already reads `input.recent_calls` /
# `input.window_seconds` off the real top-level input `bin/mcphubd`'s
# adapter builds (see `anomaly.rego`'s header comment). `engine.rs`'s
# `evaluate_raw` then merges that result into the final decision in Rust:
# `allow := authz_allow && anomaly_reasons.is_empty()`, `reasons :=
# authz_reasons ∪ anomaly_reasons`. This policy's OWN `allow`/`reasons`
# below therefore do NOT account for anomaly structural denials by
# themselves — the merge happens one layer up. If you are reading this
# file's `allow` rule in isolation (e.g. via `opa eval` against just this
# bundle) expecting it to reflect anomaly denials, it will not; that is
# `evaluate_raw`'s job, not this rule's.
#
# Expose deny reasons for audit logging and API response
reasons := deny
