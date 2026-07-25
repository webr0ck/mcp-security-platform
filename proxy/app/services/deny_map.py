"""
One deny table, three renderers.

The exception -> client-error mapping was hand-copied at three sites:
  routers/tools.py       (HTTP status + JSON envelope)
  routers/mcp_server.py  (JSON-RPC error, /mcp tools/call dispatch)
  routers/mcp_server.py  (a text block, invoke_tool meta-tool wrapper)

They had already drifted: ToolDisabledError / ToolQuarantinedError /
ToolDeprecatedError were mapped ONLY in tools.py. On the two /mcp paths they fell
through to `_err(-32603, f"Tool invocation failed: {exc}")`, which both loses the
deny semantics and interpolates the exception string into a client-facing message —
three branches below a comment promising no internals are leaked. Latent today only
because those statuses are pre-filtered at lookup (mcp_server.py), which is exactly
the kind of accident that stops being true after an unrelated refactor.

This module owns the decision (which reason, which code, what the caller is told).
The renderers own only the envelope shape. Adding a deny reason means adding one row
here, and every surface gets it.

Messages are deliberately non-specific about internals — no server_id, no upstream
URL, no exception text — while still being actionable via `remediation`.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class DenyInfo:
    reason: str          # stable machine code for audit/tests
    message: str         # client-safe, no internals
    http_status: int     # REST renderer
    jsonrpc_code: int    # /mcp renderer
    data: dict = field(default_factory=dict)


# -32003 is this platform's "denied by policy" JSON-RPC code; -32010/-32011 are the
# credential-enrollment codes handled separately by their own richer branches.
_DENIED = -32003


def classify_deny(exc: BaseException) -> DenyInfo | None:
    """Map a pipeline exception to a client-facing deny, or None if it is not a deny.

    None means "this is a genuine internal error" — the caller renders a 500/-32603
    WITHOUT the exception text.
    """
    from app.services.entitlement import NotEntitledError
    from app.services.invocation import (
        ScanFreshnessError,
        ServerInMaintenanceError,
        TaintFloorDenyError,
        ToolDeprecatedError,
        ToolDisabledError,
        ToolQuarantinedError,
    )
    from app.services.policy import OPADenyError, OPAUnavailableError

    if isinstance(exc, NotEntitledError):
        return DenyInfo(
            "not_entitled",
            "Access denied: not entitled to this tool's server. Being able to see a "
            "tool never implies permission to call it — request access from the "
            "server's owner.",
            403, _DENIED,
        )

    if isinstance(exc, ScanFreshnessError):
        return DenyInfo(
            "scan_stale",
            "Access denied: this server's supply-chain scan is stale. It must be "
            "re-scanned before its tools can be called again.",
            403, _DENIED,
        )

    if isinstance(exc, ServerInMaintenanceError):
        return DenyInfo(
            "server_in_maintenance",
            "This MCP server is in maintenance. Only its owner and maintainers can "
            "call it right now — there is deliberately no admin override.",
            403, _DENIED,
        )

    if isinstance(exc, TaintFloorDenyError):
        return DenyInfo(
            "taint_floor",
            "Access denied: this session is restricted by trust policy. A result "
            "derived from an untrusted or not-yet-reviewed source cannot flow into "
            "this tool.",
            403, _DENIED,
        )

    # These three existed ONLY in the REST renderer before 2026-07-25.
    if isinstance(exc, ToolQuarantinedError):
        return DenyInfo(
            "tool_quarantined",
            "This tool is quarantined pending review and cannot be called.",
            403, _DENIED,
        )
    if isinstance(exc, ToolDisabledError):
        return DenyInfo(
            "tool_disabled",
            "This tool is disabled and cannot be called.",
            403, _DENIED,
        )
    if isinstance(exc, ToolDeprecatedError):
        return DenyInfo(
            "tool_deprecated",
            "This tool is deprecated and no longer callable. Check the catalog for a "
            "replacement.",
            410, _DENIED,
        )

    if isinstance(exc, OPADenyError):
        from app.services.policy import deny_remediation
        reasons = list(getattr(exc, "reasons", []) or [])
        help_text = deny_remediation(reasons)
        msg = "Access denied by policy" + (f". {help_text}" if help_text else "")
        data: dict = {"reasons": reasons}
        if help_text:
            data["remediation"] = help_text
        return DenyInfo("opa_deny", msg, 403, _DENIED, data)

    if isinstance(exc, OPAUnavailableError):
        # INV-004: OPA unreachable denies. 503 because it is retryable, unlike the
        # 403s above which are decisions.
        return DenyInfo(
            "opa_unavailable",
            "Authorization is temporarily unavailable, so the call was denied. "
            "This is fail-closed behaviour — retry shortly.",
            503, _DENIED,
        )

    return None
