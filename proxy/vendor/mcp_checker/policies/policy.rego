package mcp.policy

import future.keywords.if
import future.keywords.in
import future.keywords.contains

# Deny by default - explicit allow required
default allow := false

# Helper: find tool policy by canonical or nested name
get_tool_policy(tp) {
  some svc
  some act
  svc := input.tool.service        # e.g., "file_browser"
  act := input.tool.action         # e.g., "read"
  nested := input.tools[svc][act]
  tp := object.union(nested, {"name": nested.canonical_name})
} else = tp {
  # flat name passthrough
  tp := input.tools[input.tool.name]
}

# Registry pinning - prevent rug pull attacks
deny["missing server_id"] {
  not input.server_id
}

deny["server_id mismatch"] {
  expected := registry[input.tool.name]
  expected.server_id != input.server_id
}

deny["tool description hash mismatch (rug pull)"] {
  expected := registry[input.tool.name]
  expected.desc_sha256 != input.tool.meta.desc_sha256
}

deny["tool schema hash mismatch"] {
  expected := registry[input.tool.name]
  expected.schema_sha256 != input.tool.meta.schema_sha256
}

# Shadowing detection - same name, different hash
shadowing(other) {
  other := input.introspection.tools[_]
  other.name == input.tool.name
  other.meta.desc_sha256 != input.tool.meta.desc_sha256
}

deny[sprintf("shadowing attempt for %s", [input.tool.name])] {
  shadowing(_)
}

# Tool registry lookup
registry := { r.name: r | r := input.registry[_] }

deny[sprintf("tool not in registry: %s", [input.tool.name])] {
  not registry[input.tool.name]
}

# File tools
is_file_tool(tp) { tp.file_roots }

# Absolute path, traversal, symlink, glob denies, size caps
deny["path must be absolute"] { 
  is_file_tool(get_tool_policy(tp)); 
  not startswith(input.tool.args.path, "/") 
}

deny["path traversal '..' detected"] { 
  is_file_tool(get_tool_policy(tp)); 
  contains(input.tool.args.path, ".."); 
  not get_tool_policy(tp).allow_traversal 
}

deny[sprintf("path denied by policy: %s", [input.tool.args.path])] { 
  is_file_tool(get_tool_policy(tp)); 
  some g; 
  g := get_tool_policy(tp).deny_globs[_]; 
  glob.match(g, [], input.tool.args.path) 
}

deny[sprintf("outside roots: %s", [input.tool.args.path])] { 
  is_file_tool(get_tool_policy(tp)); 
  not some r; 
  r := get_tool_policy(tp).file_roots[_]; 
  startswith(input.tool.args.path, r) 
}

deny["requested read exceeds max_read_bytes"] { 
  is_file_tool(get_tool_policy(tp)); 
  input.tool.op == "read"; 
  get_tool_policy(tp).max_read_bytes > 0; 
  input.tool.args.requested_bytes > get_tool_policy(tp).max_read_bytes 
}

deny["requested write exceeds max_write_bytes"] { 
  is_file_tool(get_tool_policy(tp)); 
  input.tool.op == "write"; 
  get_tool_policy(tp).max_write_bytes > 0; 
  input.tool.args.requested_bytes > get_tool_policy(tp).max_write_bytes 
}

deny["symlink access denied"] {
  is_file_tool(get_tool_policy(tp))
  get_tool_policy(tp).follow_symlinks == false
  input.tool.args.is_symlink == true
}

# LLM tools
is_llm(tp) { tp.allowed_models }

deny[sprintf("model not allowed: %s", [input.tool.args.model])] { 
  is_llm(get_tool_policy(tp)); 
  not get_tool_policy(tp).allowed_models[_] == input.tool.args.model 
}

deny[sprintf("max_tokens exceeded: %v", [input.tool.args.max_tokens])] { 
  is_llm(get_tool_policy(tp)); 
  get_tool_policy(tp).max_tokens > 0; 
  input.tool.args.max_tokens > get_tool_policy(tp).max_tokens 
}

# Per-tool rate (gate must supply recent_count for the identity)
deny[sprintf("rate exceeded: %v/min", [get_tool_policy(tp).rate_limit_per_minute])] {
  get_tool_policy(tp).rate_limit_per_minute > 0
  input.identity.id
  input.telemetry.window == "1m"
  input.telemetry.recent_calls >= get_tool_policy(tp).rate_limit_per_minute
}

# Network per-tool controls
is_net_tool(tp) { tp.network_egress }

deny[sprintf("egress not allowed to: %s", [input.tool.args.dest])] {
  is_net_tool(get_tool_policy(tp))
  dst := input.tool.args.dest
  not some host
  host := get_tool_policy(tp).network_egress[_]
  dst == host
}

# Execution class requires confirmation
is_exec {
  re_match("(?i)(exec|shell|subprocess|eval|bash|sh|python_exec|node_exec)", input.tool.name)
}

deny["execution tool requires confirmation"] {
  is_exec
  not input.tool.args.requires_confirmation
}

# Jira specific controls
deny["too many fields in issue"] {
  input.tool.name == "jira.create_issue"
  count(input.tool.args.fields) > get_tool_policy({}).max_fields
}

deny["too many search results requested"] {
  input.tool.name == "jira.search"
  input.tool.args.max_results > get_tool_policy({}).max_results
}

# Global security requirements
deny["authn_required must be true"] {
  not input.requirements.authn_required
}

deny["redact_pii_in_logs must be true"] {
  not input.requirements.redact_pii_in_logs
}

deny["confirmation_for_write must be true"] {
  not input.requirements.confirmation_for_write
}

deny["token_storage must be false"] {
  input.requirements.token_storage == true
}

deny["token_broker must be true"] {
  not input.requirements.token_broker
}

deny["registry_pinning must be true"] {
  not input.requirements.registry_pinning
}

deny["hash_validation must be true"] {
  not input.requirements.hash_validation
}

deny["shadowing_detection must be true"] {
  not input.requirements.shadowing_detection
}

deny["tools_allowed missing"] {
  not input.allow_lists.tools_allowed
}

deny[sprintf("dangerous tool on allowlist: %s", [t])] {
  some t
  t := input.allow_lists.tools_allowed[_]
  re_match("(?i)(exec|shell|run_cmd|eval|subprocess|bash|sh|python_exec|node_exec)", t)
}

# Global allow lists must be empty (enforce tool-scoped)
deny["global file_roots must be empty - use tool-scoped permissions"] {
  count(input.allow_lists.file_roots) > 0
}

deny["global network_egress must be empty - use tool-scoped permissions"] {
  count(input.allow_lists.network_egress) > 0
}

# Container security requirements
deny["container.run_as_non_root must be true"] {
  not input.requirements.container.run_as_non_root
}

deny["container.readonly_filesystem must be true"] {
  not input.requirements.container.readonly_filesystem
}

deny["container.no_new_privileges must be true"] {
  not input.requirements.container.no_new_privileges
}

# Logging requirements
deny["logging.audit_enabled must be true"] {
  not input.requirements.logging.audit_enabled
}

deny["logging.security_events must be true"] {
  not input.requirements.logging.security_events
}

# Helper functions
startswith(s, prefix) := true {
  substring(0, count(prefix), s) == prefix
}

contains_any(arr, allow_set) := true if {
  elem := arr[_]
  allow_set[elem]
}

contains(item, arr) := true {
  some i
  arr[i] == item
}

# Final allow decision - only if no denies
allow {
  count(deny) == 0
}
