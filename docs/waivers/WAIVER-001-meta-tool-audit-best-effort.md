# WAIVER-001 — Meta-Tool Audit Events Are Best-Effort (INV-001 partial exception)

**Status:** ACCEPTED  
**Date:** 2026-06-08  
**Reviewer:** appsec-reviewer agent (Phase 6 sign-off)  
**Waiver owner:** platform team  
**Review trigger:** HIGH-2 finding in Phase 6 AppSec review

---

## What is waived

INV-001 requires that every invocation produces a synchronous audit event before
responding, and that audit failure produces a 500. For **platform meta-tools**
(`platform_info`, `security_pulse_summary`, `list_registered_tools`,
`enrollment_status`), OPA-deny events are emitted via `emit_internal_tool_event()`
(`invocation.py:681–714`), which explicitly swallows emission failures rather than
propagating them as 500s.

This means a meta-tool OPA denial can fail to produce an audit record without
blocking the denial response to the caller.

## Why this is accepted

1. **Meta-tools are read-only platform introspection.** They do not invoke upstream
   servers, do not forward credentials, and do not write data. The information they
   expose (`platform_info`, `enrollment_status`) is non-sensitive operational
   metadata visible to any authenticated role that meets the ACL.

2. **The denial itself is correctly enforced.** The audit emission failure does not
   change the policy outcome: the caller is still denied. There is no fail-open risk.

3. **The alternative (500 on audit failure) creates a worse security posture.**
   Blocking meta-tool reads on audit transients would make the platform appear
   unavailable and could mask operational problems with the underlying stack.

4. **Coverage for the security-significant paths is maintained.** All registry tool
   invocations and entitlement denials go through the `invoke_tool()` chokepoint,
   which enforces INV-001 strictly (audit failure = 500). Meta-tool denials are a
   lower-risk subset.

## Conditions for re-evaluation

This waiver should be revisited if:
- Any meta-tool is extended to return non-public data (e.g. per-principal credential
  status, server-level secrets).
- The audit backend gains a reliable write-through path (e.g. Kafka + dead-letter
  queue) that makes a best-effort emit materially equivalent to a guaranteed one.
- A meta-tool is given write capabilities.

## Affected code

- `proxy/app/routers/mcp_server.py` — `_dispatch()` lines ~685–700: OPA deny path
  for meta-tools calls `emit_internal_tool_event()`.
- `proxy/app/services/invocation.py` — `emit_internal_tool_event()` function:
  exceptions are caught and logged at WARNING.
