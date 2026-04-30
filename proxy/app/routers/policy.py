"""
MCP Security Platform — Policy Management Router

Implements docs/API.md Section 2.5.

Endpoints:
  GET  /api/v1/policy/rules     — List loaded OPA rule metadata (admin, auditor)
  POST /api/v1/policy/evaluate  — Manual policy evaluation for debugging (admin only)
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

import httpx
from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import JSONResponse

from app.core.config import settings
from app.services.policy import OPAUnavailableError, manual_evaluate

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/policy")

# ---------------------------------------------------------------------------
# Known MCP platform rules — used as fallback metadata when OPA /v1/policies
# is unavailable or doesn't return structured descriptions.
# These are the authoritative rule IDs; update when authz.rego is updated.
# ---------------------------------------------------------------------------
_KNOWN_RULES: list[dict[str, Any]] = [
    {
        "rule_id": "allow",
        "package": "mcp.authz",
        "description": (
            "Top-level allow decision. True only when all deny conditions are absent, "
            "the tool is active, the client has invoke permission, the tool risk level "
            "is within the client's threshold, and anomaly threshold is not exceeded."
        ),
        "enabled": True,
    },
    {
        "rule_id": "deny_quarantined_tool",
        "package": "mcp.authz",
        "description": "Deny invocation when the tool status is 'quarantined'. Applied before OPA (INV-005).",
        "enabled": True,
    },
    {
        "rule_id": "deny_missing_invoke_permission",
        "package": "mcp.authz",
        "description": "Deny when the client_roles set does not include 'agent' or 'admin'.",
        "enabled": True,
    },
    {
        "rule_id": "deny_risk_level_too_high",
        "package": "mcp.authz",
        "description": (
            "Deny when tool risk_level exceeds the client's maximum allowed threshold "
            "(resolved from client metadata or role defaults)."
        ),
        "enabled": True,
    },
    {
        "rule_id": "deny_anomaly_threshold_exceeded",
        "package": "mcp.authz",
        "description": "Deny when the anomaly score for this client >= 0.85 within the 300-second window.",
        "enabled": True,
    },
    {
        "rule_id": "admin_testing_bypass",
        "package": "mcp.authz",
        "description": (
            "Allow admin clients with is_testing=true to bypass risk-level and anomaly checks "
            "for integration testing. Tool must still be active and have no hard deny reasons."
        ),
        "enabled": True,
    },
    {
        "rule_id": "static_risk_score",
        "package": "mcp.tool_risk",
        "description": (
            "Assigns a static risk score (0–100) to tools based on detected capability flags: "
            "filesystem_unrestricted, prompt_injection, network_unrestricted, credential_parameters, "
            "shell execution, and others."
        ),
        "enabled": True,
    },
    {
        "rule_id": "structural_deny_web_search_then_bulk_read",
        "package": "mcp.anomaly",
        "description": "Flag sequences where web_search is followed immediately by bulk file reads (exfil pattern).",
        "enabled": True,
    },
    {
        "rule_id": "structural_deny_credential_then_exec",
        "package": "mcp.anomaly",
        "description": "Flag sequences where credential-fetch tools are followed by execution tools.",
        "enabled": True,
    },
]


async def _fetch_opa_policy_metadata() -> list[dict[str, Any]] | None:
    """
    Attempt to fetch policy metadata from OPA's /v1/policies endpoint.

    Returns a list of rule metadata dicts on success, or None if OPA is
    unreachable or returns unexpected data. Callers fall back to static metadata.
    """
    url = f"{settings.opa_url}/v1/policies"
    try:
        async with httpx.AsyncClient(timeout=float(settings.OPA_TIMEOUT_SECONDS)) as client:
            response = await client.get(url)
    except (httpx.ConnectError, httpx.TimeoutException, httpx.NetworkError) as exc:
        logger.warning("OPA /v1/policies unreachable — using static metadata", extra={"error": str(exc)})
        return None

    if response.status_code != 200:
        logger.warning(
            "OPA /v1/policies returned non-200 — using static metadata",
            extra={"status_code": response.status_code},
        )
        return None

    try:
        body = response.json()
    except Exception:
        return None

    # OPA response: {"result": [{"id": "...", "ast": {...}}, ...]}
    opa_policies: list[dict[str, Any]] = body.get("result", [])
    if not isinstance(opa_policies, list):
        return None

    # Build a minimal rule metadata list from OPA policy packages.
    # OPA doesn't expose per-rule descriptions — we annotate from _KNOWN_RULES.
    known_by_id = {r["rule_id"]: r for r in _KNOWN_RULES}
    live_rules: list[dict[str, Any]] = []

    for policy in opa_policies:
        policy_id: str = policy.get("id", "")
        # OPA policy IDs typically match package path: "mcp/authz" or "mcp/tool_risk"
        package_name = policy_id.replace("/", ".")

        # Try to match annotations if present in OPA AST metadata
        ast: dict[str, Any] = policy.get("ast", {})
        annotations: list[dict[str, Any]] = []
        _collect_annotations(ast, annotations)

        if annotations:
            for ann in annotations:
                rule_title: str = ann.get("title", "")
                rule_desc: str = ann.get("description", "")
                rule_id_from_ann = (
                    rule_title.lower().replace(" ", "_") or f"{package_name}_{len(live_rules)}"
                )
                # Check if this rule is in our known set for richer metadata
                known = known_by_id.get(rule_id_from_ann, {})
                live_rules.append({
                    "rule_id": known.get("rule_id", rule_id_from_ann),
                    "package": known.get("package", package_name),
                    "description": rule_desc or known.get("description", rule_title),
                    "enabled": known.get("enabled", True),
                    "last_loaded_at": datetime.now(timezone.utc).isoformat(),
                })
        else:
            # No annotations — emit a package-level entry for each known rule in this package
            package_rules = [r for r in _KNOWN_RULES if r["package"] == package_name]
            for r in package_rules:
                live_rules.append({
                    **r,
                    "last_loaded_at": datetime.now(timezone.utc).isoformat(),
                })

    return live_rules if live_rules else None


def _collect_annotations(node: Any, out: list[dict[str, Any]]) -> None:
    """Recursively collect OPA annotation blocks from an AST node."""
    if not isinstance(node, dict):
        return
    if "annotations" in node:
        ann = node["annotations"]
        if isinstance(ann, dict):
            out.append(ann)
    for value in node.values():
        if isinstance(value, dict):
            _collect_annotations(value, out)
        elif isinstance(value, list):
            for item in value:
                _collect_annotations(item, out)


@router.get("/rules")
async def list_policy_rules(
    request: Request,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
) -> JSONResponse:
    """
    List currently loaded OPA policy rules (metadata only, not Rego source).

    Attempts to fetch live rule metadata from OPA's /v1/policies endpoint.
    Falls back to static known-rule metadata if OPA is unreachable.

    Required role: admin, auditor.

    Args:
        page: 1-based page number.
        page_size: Results per page (1–200).

    Returns:
        Paginated list of rule metadata records.
    """
    roles: list[str] = getattr(request.state, "client_roles", [])
    if not any(r in {"admin", "auditor"} for r in roles):
        raise HTTPException(
            status_code=403,
            detail={"code": "FORBIDDEN", "message": "Requires admin or auditor role."},
        )

    # Try live OPA metadata; fall back to static list.
    live_rules = await _fetch_opa_policy_metadata()
    all_rules: list[dict[str, Any]] = live_rules if live_rules is not None else [
        {**r, "last_loaded_at": datetime.now(timezone.utc).isoformat()}
        for r in _KNOWN_RULES
    ]

    total_items = len(all_rules)
    offset = (page - 1) * page_size
    page_rules = all_rules[offset : offset + page_size]
    total_pages = max(1, -(-total_items // page_size))

    return JSONResponse(
        status_code=200,
        content={
            "data": page_rules,
            "pagination": {
                "page": page,
                "page_size": page_size,
                "total_items": total_items,
                "total_pages": total_pages,
            },
        },
    )


@router.post("/evaluate")
async def evaluate_policy(
    request: Request,
) -> JSONResponse:
    """
    Manually evaluate a policy decision. Used for testing and debugging.

    Sends the provided input dict to OPA and returns the allow/deny decision
    with reasons. Conforms to INV-003: OPA default deny always applies.

    Required role: admin.

    Request body must include an 'input' key with the OPA input context.

    Returns:
        OPA decision: {allow, reasons, evaluated_at, opa_decision_id}

    Raises:
        HTTP 400 if 'input' key is missing.
        HTTP 503 if OPA is unreachable (INV-004).
    """
    roles: list[str] = getattr(request.state, "client_roles", [])
    if "admin" not in roles:
        raise HTTPException(
            status_code=403,
            detail={"code": "FORBIDDEN", "message": "Requires admin role."},
        )

    body = await request.json()
    input_data = body.get("input", {})

    if not input_data:
        raise HTTPException(
            status_code=400,
            detail={"code": "VALIDATION_ERROR", "message": "Request body must include 'input' key."},
        )

    try:
        result = await manual_evaluate(input_data)
    except OPAUnavailableError as exc:
        raise HTTPException(
            status_code=503,
            detail={"code": "OPA_UNAVAILABLE", "message": str(exc)},
        ) from exc

    logger.info(
        "Manual policy evaluation completed",
        extra={
            "allow": result.get("allow"),
            "client_id": input_data.get("client_id"),
            "tool_name": input_data.get("tool_name"),
            "request_id": getattr(request.state, "request_id", "unknown"),
        },
    )

    return JSONResponse(status_code=200, content=result)
