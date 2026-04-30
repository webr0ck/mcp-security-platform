"""
MCP Security Platform — OPA Policy Client

Sends tool invocation context to the OPA sidecar for policy evaluation.

INV-003: OPA is deny-by-default. allow=false unless explicitly allowed.
INV-004: If OPA is unreachable, return 503 OPA_UNAVAILABLE immediately.
         Never allow on OPA failure.

POST to http://opa:8181/v1/data/mcp/authz/allow with the full input context.
"""
from __future__ import annotations

import logging
from typing import Any

import httpx

from app.core.config import settings

logger = logging.getLogger(__name__)


class OPADenyError(Exception):
    """OPA evaluated and denied the request."""

    def __init__(self, reasons: list[str]) -> None:
        self.reasons = reasons
        super().__init__(f"OPA denied: {reasons}")


class OPAUnavailableError(Exception):
    """OPA sidecar is unreachable. Per INV-004, deny all."""


async def evaluate_policy(input_data: dict[str, Any]) -> dict[str, Any]:
    """
    POST input_data to OPA and return {allow: bool, reasons: list[str]}.

    Per INV-004: any connection error or non-200 from OPA raises OPAUnavailableError.
    Callers must catch OPAUnavailableError and return HTTP 503.

    Args:
        input_data: Dict matching the OPA input schema in authz.rego.

    Returns:
        {"allow": bool, "reasons": list[str]}

    Raises:
        OPAUnavailableError: if OPA is unreachable or returns an error.
    """
    url = settings.opa_authz_url
    payload = {"input": input_data}

    try:
        async with httpx.AsyncClient(timeout=float(settings.OPA_TIMEOUT_SECONDS)) as client:
            response = await client.post(url, json=payload)
    except (httpx.ConnectError, httpx.TimeoutException, httpx.NetworkError) as exc:
        logger.error(
            "OPA unreachable — failing closed per INV-004",
            extra={"opa_url": url, "error": str(exc)},
        )
        raise OPAUnavailableError(f"OPA unreachable: {exc}") from exc
    except Exception as exc:
        logger.error("Unexpected error contacting OPA", extra={"error": str(exc)})
        raise OPAUnavailableError(f"OPA contact failed: {exc}") from exc

    if response.status_code != 200:
        logger.error(
            "OPA returned non-200 — failing closed per INV-004",
            extra={"status_code": response.status_code, "body": response.text[:500]},
        )
        raise OPAUnavailableError(f"OPA HTTP {response.status_code}")

    try:
        body = response.json()
    except Exception as exc:
        raise OPAUnavailableError(f"OPA returned invalid JSON: {exc}") from exc

    # OPA result structure: {"result": {"allow": bool, "reasons": set}}
    result = body.get("result", {})
    allow: bool = bool(result.get("allow", False))  # Default false per INV-003
    reasons: list[str] = list(result.get("reasons", []))

    logger.info(
        "OPA decision",
        extra={
            "allow": allow,
            "reasons": reasons,
            "input_client": input_data.get("client_id"),
            "input_tool": input_data.get("tool_name"),
        },
    )

    return {"allow": allow, "reasons": reasons}


async def manual_evaluate(input_data: dict[str, Any]) -> dict[str, Any]:
    """
    Manually evaluate a policy decision for debugging (POST /policy/evaluate).

    Returns the OPA decision with an evaluated_at timestamp.
    Raises OPAUnavailableError if OPA cannot be reached.
    """
    from datetime import datetime, timezone
    from uuid import uuid4

    result = await evaluate_policy(input_data)
    return {
        "allow": result["allow"],
        "reasons": result["reasons"],
        "evaluated_at": datetime.now(timezone.utc).isoformat(),
        "opa_decision_id": f"dec_{uuid4().hex[:16]}",
    }
