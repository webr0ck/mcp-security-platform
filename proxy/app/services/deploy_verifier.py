"""
Deploy verifier (CR-01 / WP-B3 phase 4) — the final gate between a running
container and an invocable-but-quarantined server.

`run_verification_probes` is the SINGLE verification code path shared by
both the platform-managed pipeline (`verify_server`, this module) and the
self-hosted `provide-url` flow (`app.routers.submission.provide_running_url`,
extended in Task 6 to call the same helper) — per the plan's explicit
requirement, there is exactly one place that runs the healthcheck +
discovery + invocation-probe sequence, not two independently-maintained
copies.

`verify_server` promotes `runtime_url` -> `upstream_url` and
`server_registry.status` -> 'approved' BEFORE running the probes (not
after) — `run_verification_probes`' discovery step reuses the existing
`_run_tool_discovery`, which both requires `status='approved'` as a
precondition AND reads `upstream_url` directly from `server_registry`
itself, so both columns must already reflect the target being verified or
discovery cannot run at all. This exactly mirrors `provide-url`'s existing
ordering (self-hosted also sets `upstream_url`+`status='approved'` before
its own verification call) — "approval already committed, verification is
diagnostic from here" in both paths; a probe failure still never advances
`deployment_status` past `'failed'`, and a quarantine-then-review path is
the only way from there to invocable (INV-005 unchanged — this module
never releases anything, it only discovers tools quarantined, same as
`_run_tool_discovery` always does).
"""
from __future__ import annotations

import json
import logging

import httpx
from sqlalchemy import text

from app.core.database import AsyncSessionLocal

logger = logging.getLogger(__name__)

_PROBE_TIMEOUT_SECONDS = 10


class VerificationFailedError(Exception):
    """Raised by run_verification_probes on any probe failure — the caller
    (verify_server / provide_running_url) is responsible for fail-closed
    handling; this exception itself carries the partial report so the
    caller can still persist what was learned."""

    def __init__(self, message: str, report: dict):
        super().__init__(message)
        self.report = report


async def _probe_initialize(url: str) -> bool:
    payload = {
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                  "clientInfo": {"name": "mcp-security-platform-verify-probe", "version": "1.0.0"}},
    }
    headers = {"Accept": "application/json, text/event-stream"}
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.post(url, json=payload, headers=headers, timeout=_PROBE_TIMEOUT_SECONDS)
            resp.raise_for_status()
            return True
    except httpx.HTTPError as exc:
        logger.warning("verify healthcheck probe failed url=%s: %s", url, exc)
        return False


async def run_verification_probes(server_id: str, url: str, actor_client_id: str) -> dict:
    """
    Healthcheck -> strict-audit quarantined tool discovery -> invocation
    probe. Raises VerificationFailedError (carrying the partial report) on
    any failure — never returns a report claiming success for a step that
    didn't run.

    Reuses app.routers.tools._run_tool_discovery — the existing strict-audit,
    quarantine-by-default path — rather than reimplementing discovery here.
    """
    healthcheck = await _probe_initialize(url)
    if not healthcheck:
        raise VerificationFailedError(
            "healthcheck probe failed",
            {"healthcheck": False, "tools_discovered": 0, "tools_skipped": [],
             "invocation_probe_ok": False, "contract_check": None},
        )

    from app.routers.tools import _run_tool_discovery

    tools_discovered = 0
    tools_skipped: list[dict] = []
    try:
        async with AsyncSessionLocal() as disc_session:
            disc_response = await _run_tool_discovery(
                server_id, disc_session, actor_client_id=actor_client_id,
            )
        if disc_response.status_code != 200:
            raise RuntimeError(f"discovery returned status {disc_response.status_code}")
        body = json.loads(disc_response.body)
        tools_discovered = body.get("discovered", 0)
        tools_skipped = body.get("skipped", [])
    except Exception as exc:
        logger.error("verify discovery failed server_id=%s: %s", server_id, exc)
        raise VerificationFailedError(
            f"tool discovery failed: {exc}",
            {"healthcheck": True, "tools_discovered": 0, "tools_skipped": [],
             "invocation_probe_ok": False, "contract_check": None},
        ) from exc

    # Final invocation probe (PRD-8 sec 4) — same handshake as the
    # healthcheck, run once more post-discovery so a server that answered
    # once but degraded mid-discovery is still caught.
    invocation_probe_ok = await _probe_initialize(url)
    if not invocation_probe_ok:
        raise VerificationFailedError(
            "post-discovery invocation probe failed",
            {"healthcheck": True, "tools_discovered": tools_discovered,
             "tools_skipped": tools_skipped, "invocation_probe_ok": False, "contract_check": None},
        )

    # CR-06 (WP-B3 phase 6): machine-testable contract subset — validates
    # initialize/tools-list response SHAPE against
    # docs/reference/mcp-server-contract.schema.json. A contract violation
    # is recorded in the report but does NOT by itself fail verification —
    # it is diagnostic (CR-06 scope), distinct from the hard healthcheck/
    # discovery/invocation-probe gates above which DO fail closed.
    from app.services.contract_check import run_contract_check
    contract_check = await run_contract_check(url)

    return {
        "healthcheck": True,
        "tools_discovered": tools_discovered,
        "tools_skipped": tools_skipped,
        "invocation_probe_ok": True,
        "contract_check": contract_check,
    }


async def _fetch_server(session, server_id: str):
    return (await session.execute(text(
        """
        SELECT server_id, deployment_status, runtime_url
        FROM server_registry
        WHERE server_id = :sid AND deleted_at IS NULL
        """
    ), {"sid": str(server_id)})).mappings().first()


async def _mark_failed(server_id: str, report: dict | None) -> None:
    async with AsyncSessionLocal() as session:
        await session.execute(text(
            """
            UPDATE server_registry
            SET deployment_status = 'failed',
                verification_report = CAST(:report AS jsonb),
                updated_at = now()
            WHERE server_id = :sid
            """
        ), {"report": json.dumps(report or {}), "sid": str(server_id)})
        await session.commit()


async def verify_server(server_id: str) -> dict:
    """
    Platform-managed verify phase: reads server_registry.runtime_url (set by
    deploy_launcher.deploy_server), promotes runtime_url -> upstream_url and
    status='approved' BEFORE running the shared verification probes (see
    module docstring — discovery requires both already set), then runs
    them. Only on full probe success does deployment_status become
    'verified'; any probe failure fails deployment_status closed to
    'failed' and still records whatever partial report was gathered.
    """
    async with AsyncSessionLocal() as session:
        row = await _fetch_server(session, server_id)
        if row is None:
            report = {"healthcheck": False, "tools_discovered": 0, "tools_skipped": [],
                       "invocation_probe_ok": False, "contract_check": None}
            return report

        if row["deployment_status"] != "deployed" or not row["runtime_url"]:
            error = (f"refusing to verify: deployment_status={row['deployment_status']!r} "
                     f"runtime_url={row['runtime_url']!r} — deploy must succeed first")
            logger.warning("verify_server refused server_id=%s: %s", server_id, error)
            report = {"healthcheck": False, "tools_discovered": 0, "tools_skipped": [],
                       "invocation_probe_ok": False, "contract_check": None}
            await _mark_failed(server_id, report)
            return report

        runtime_url = row["runtime_url"]
        # status='approved' AND upstream_url must both be set BEFORE the
        # probes run, not after — found live: run_verification_probes'
        # discovery step reuses the existing _run_tool_discovery, which (a)
        # requires status='approved' as a precondition and (b) reads
        # upstream_url directly from server_registry itself (not from a
        # parameter), so discovery would target the WRONG url (or 400 on a
        # null one) unless upstream_url already reflects runtime_url before
        # discovery runs. This exactly mirrors provide_running_url's
        # existing ordering for the self-hosted path (it sets upstream_url +
        # status='approved' before its own verification call, with the same
        # accepted risk noted there: "the approval above already committed —
        # a discovery failure here must not roll that back"). Final
        # promotion below re-asserts both columns for a clean audit trail,
        # not because they weren't already set.
        await session.execute(text(
            "UPDATE server_registry SET deployment_status = 'verifying', status = 'approved', "
            "upstream_url = :upstream_url, updated_at = now() WHERE server_id = :sid"
        ), {"upstream_url": runtime_url, "sid": str(server_id)})
        await session.commit()

    try:
        report = await run_verification_probes(server_id, runtime_url, actor_client_id="platform-deploy-verifier")
    except VerificationFailedError as exc:
        await _mark_failed(server_id, exc.report)
        return exc.report

    async with AsyncSessionLocal() as session:
        await session.execute(text(
            """
            UPDATE server_registry
            SET deployment_status = 'verified',
                upstream_url = :upstream_url,
                status = 'approved',
                verification_report = CAST(:report AS jsonb),
                contract_version = 'v0.1',
                updated_at = now()
            WHERE server_id = :sid
            """
        ), {"upstream_url": runtime_url, "report": json.dumps(report), "sid": str(server_id)})
        await session.commit()

    logger.info("verify_server succeeded server_id=%s", server_id)
    return report
