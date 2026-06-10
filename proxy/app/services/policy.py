"""
MCP Security Platform — OPA Policy Client

Sends tool invocation context to the OPA sidecar for policy evaluation,
and manages the OPA data API for syncing grants and policy data.

INV-003: OPA is deny-by-default. allow=false unless explicitly allowed.
INV-004: If OPA is unreachable, return 503 OPA_UNAVAILABLE immediately.
         Never allow on OPA failure.

Interfaces:
  - evaluate_policy(): POST /v1/data/mcp/authz/allow for tool invocation decisions
  - OPAClient.put_data(): PUT /v1/data/* for syncing grants, deny lists, etc.
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


class PolicyEngineError(Exception):
    """Generic policy engine error (OPA push failure, etc.)."""

    pass


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

    opa_headers: dict[str, str] = {}
    if settings.OPA_AUTH_TOKEN:
        opa_headers["Authorization"] = f"Bearer {settings.OPA_AUTH_TOKEN}"

    try:
        async with httpx.AsyncClient(timeout=float(settings.OPA_TIMEOUT_SECONDS)) as client:
            response = await client.post(url, json=payload, headers=opa_headers)
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
    # During the OPA startup race window (bundle not yet loaded), OPA may return
    # {"result": null} or {"result": {}} (allow key absent). Both must be treated
    # as deny per INV-003 (default allow = false) and INV-004 (fail closed).
    # body.get("result", {}) returns None when the key is present with null value,
    # so we normalise None → {} explicitly before extracting allow.
    raw_result = body.get("result")
    result: dict = raw_result if isinstance(raw_result, dict) else {}
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


class OPAClient:
    """
    OPA client for data API operations (push grants, deny lists, etc.).

    Methods:
      - put_data(path, data): PUT /v1/data{path} to sync runtime data to OPA
    """

    @staticmethod
    async def put_data(path: str, data: dict[str, Any]) -> None:
        """
        Push data to OPA's data API.

        Sends a PUT request to http://opa:8181/v1/data{path} with the provided data.
        Used to sync grants, deny lists, and other runtime data to OPA.

        Args:
            path: OPA data path, e.g. "/mcp/grants"
            data: JSON structure to push, e.g. {"mcp": {"grants": {...}}}

        Raises:
            PolicyEngineError: on any failure (connection, timeout, HTTP error)

        Design:
          - Pairwise network only (opa-net between proxy and OPA)
          - Never exposed to the internet
          - Idempotent: pushing the same data multiple times is safe
        """
        url = f"{settings.opa_url}/v1/data{path}"
        payload = data

        opa_headers: dict[str, str] = {}
        if settings.OPA_AUTH_TOKEN:
            opa_headers["Authorization"] = f"Bearer {settings.OPA_AUTH_TOKEN}"

        try:
            async with httpx.AsyncClient(
                timeout=float(settings.OPA_TIMEOUT_SECONDS)
            ) as client:
                response = await client.put(url, json=payload, headers=opa_headers)
        except (httpx.ConnectError, httpx.TimeoutException, httpx.NetworkError) as exc:
            logger.error(
                "OPA data push failed — OPA unreachable",
                extra={"path": path, "opa_url": url, "error": str(exc)},
            )
            raise PolicyEngineError(f"OPA unreachable: {exc}") from exc
        except Exception as exc:
            logger.error(
                "OPA data push failed — unexpected error",
                extra={"path": path, "error": str(exc)},
            )
            raise PolicyEngineError(f"OPA push failed: {exc}") from exc

        if response.status_code not in (200, 204):
            logger.error(
                "OPA data push failed — non-success HTTP status",
                extra={
                    "path": path,
                    "status_code": response.status_code,
                    "body": response.text[:500],
                },
            )
            raise PolicyEngineError(
                f"OPA returned HTTP {response.status_code}: {response.text[:200]}"
            )

        logger.info(
            "OPA data pushed successfully",
            extra={"path": path, "status_code": response.status_code},
        )
