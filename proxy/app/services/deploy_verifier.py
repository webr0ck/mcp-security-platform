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


async def _run_same_idp_verify(server_id: str, url: str) -> tuple[bool, dict | None, str | None]:
    """
    WP-A6 Finding 4: for a same-platform-IdP (kc_token_exchange) server, prove
    the upstream itself rejects missing/wrong-audience/expired tokens —
    same_idp_verify.run_same_idp_verify_probe() previously existed only as a
    standalone, acceptance-test-able probe, never called from the actual
    verify phase. Returns (ok, probe_report_or_None, reason) — ok=True/report=
    None for servers this doesn't apply to (skip, not a failure); ok=False
    fails verification closed when any of the three negative probes is
    accepted by the upstream.
    """
    async with AsyncSessionLocal() as session:
        row = (await session.execute(text(
            "SELECT injection_mode, approved_token_audience FROM server_registry "
            "WHERE server_id = :sid AND deleted_at IS NULL"
        ), {"sid": server_id})).mappings().first()
    if row is None or row.get("injection_mode") not in ("kc_token_exchange", "oauth_user_token"):
        return True, None, None

    approved_audience = row.get("approved_token_audience")
    if not approved_audience:
        # Same fail-closed posture as oauth_policy.py: a same-IdP server with
        # no reviewer-approved audience recorded cannot be probed meaningfully
        # (the "wrong audience" probe needs a real approved value to differ
        # from) — and dispatch itself already refuses to invoke without one.
        return False, None, "same-IdP server has no approved_token_audience recorded; cannot run the negative-token probe"

    from app.services.same_idp_verify import run_same_idp_verify_probe

    result = await run_same_idp_verify_probe(server_url=url, approved_audience=approved_audience)
    report = {
        "server_url": result.server_url,
        "all_rejected": result.all_rejected,
        "probes": [
            {"name": p.name, "rejected": p.rejected, "status_code": p.status_code, "detail": p.detail}
            for p in result.probes
        ],
    }
    if not result.all_rejected:
        return False, report, "same-IdP verify probe: upstream accepted at least one invalid token"
    return True, report, None


async def _run_service_adapter_verify(server_id: str) -> tuple[str, str | None]:
    """
    WP-A6 Finding 3: best-effort ServiceAdapter.verify_access() check.
    Returns (result, reason) where result is one of:
      - "not_applicable": nothing to verify — no service_context yet, the
        mode isn't one where a verify-time token can be obtained without a
        specific end user, or no service credential has been provisioned
        yet. Never fails verification.
      - "passed": a token was obtained and verify_access() accepted it.
      - "failed": a token was obtained and verify_access() rejected it —
        this fails verification closed.

    H-02 fix (2026-07-11 audit): previously collapsed all three cases to a
    bool, so a caller of the report couldn't tell "verified" apart from
    "skipped" or "couldn't obtain a token to test with" — all read as
    service_adapter_verified: true.

    ponytail: only external_oauth_client_credentials (app-only) is checked
    here — per-user modes (external_oauth_user_token) have no single
    verify-time token to test without a specific enrolled user, and
    same_platform_idp's own negative-token probe is Finding 4's
    run_same_idp_verify_probe, not this. Add per-user coverage if a real
    need for it shows up.
    """
    async with AsyncSessionLocal() as session:
        row = (await session.execute(text(
            "SELECT sr.service_context, sr.injection_mode, p.service_adapter "
            "FROM server_registry sr LEFT JOIN oauth_provider_profile p "
            "ON p.id = sr.oauth_provider_profile_id "
            "WHERE sr.server_id = :sid AND sr.deleted_at IS NULL"
        ), {"sid": server_id})).mappings().first()
        if row is None or not row.get("service_context") or row.get("injection_mode") != "external_oauth_client_credentials":
            return "not_applicable", None

        tool_row = (await session.execute(text(
            "SELECT tool_id, server_id, credential_id, service_name "
            "FROM tool_registry WHERE server_id = :sid AND credential_id IS NOT NULL "
            "AND deleted_at IS NULL ORDER BY created_at ASC LIMIT 1"
        ), {"sid": server_id})).mappings().first()
        if tool_row is None:
            return "not_applicable", None  # no service credential provisioned yet — nothing to verify

    from app.credential_broker.dispatcher import (
        _inject_external_oauth_client_credentials,
        CredentialInjectionError,
    )
    try:
        headers = await _inject_external_oauth_client_credentials(
            tool_record=dict(tool_row), inject_header="Authorization", inject_prefix="Bearer",
        )
    except CredentialInjectionError as exc:
        logger.warning(
            "service adapter verify: could not obtain client_credentials token for "
            "server_id=%s: %s", server_id, exc,
        )
        return "not_applicable", None  # couldn't get a token to test with — not this gate's failure

    access_token = headers.get("Authorization", "").split(" ", 1)[-1].strip()
    if not access_token:
        return "not_applicable", None

    from app.credential_broker.adapters.service_adapter_registry import get_service_adapter
    from app.credential_broker.adapters.service_adapter import RuntimeContext

    ctx = row.get("service_context") or {}
    runtime_context = RuntimeContext(
        adapter=ctx.get("adapter", "generic"),
        api_base_url=ctx.get("api_base_url"),
        resource_id=ctx.get("resource_id"),
        resource_name=ctx.get("resource_name"),
        resource_url=ctx.get("resource_url"),
    )
    svc_adapter = get_service_adapter(row.get("service_adapter"))
    ok = await svc_adapter.verify_access(access_token, runtime_context)
    if ok:
        return "passed", None
    return "failed", "ServiceAdapter.verify_access rejected the token/resource"


async def run_verification_probes(
    server_id: str, url: str, actor_client_id: str, *, require_approved: bool = True,
) -> dict:
    """
    Healthcheck -> strict-audit quarantined tool discovery -> invocation
    probe. Raises VerificationFailedError (carrying the partial report) on
    any failure — never returns a report claiming success for a step that
    didn't run.

    Reuses app.routers.tools._run_tool_discovery — the existing strict-audit,
    quarantine-by-default path — rather than reimplementing discovery here.

    require_approved (H-01, 2026-07-11 audit): pass False when the caller
    intentionally has NOT yet promoted server_registry.status to 'approved'
    (status is the real entitlement/credential-issuance gate and must only
    flip after these probes succeed — see verify_server/provide_running_url).
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
                require_approved=require_approved,
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

    # WP-A6 Finding 4: same-platform-IdP servers must prove the upstream
    # itself rejects missing/wrong-audience/expired tokens. Fail closed.
    same_idp_ok, same_idp_report, same_idp_reason = await _run_same_idp_verify(server_id, url)
    if not same_idp_ok:
        raise VerificationFailedError(
            same_idp_reason or "same-IdP verify probe failed",
            {"healthcheck": True, "tools_discovered": tools_discovered,
             "tools_skipped": tools_skipped, "invocation_probe_ok": True,
             "same_idp_verify": same_idp_report, "contract_check": None},
        )

    # WP-A6 Finding 3: ServiceAdapter.verify_access() — fail closed only when
    # a verify-time token was actually obtainable and the adapter rejected it.
    service_adapter_result, service_adapter_reason = await _run_service_adapter_verify(server_id)
    if service_adapter_result == "failed":
        raise VerificationFailedError(
            service_adapter_reason or "service adapter verify_access failed",
            {"healthcheck": True, "tools_discovered": tools_discovered,
             "tools_skipped": tools_skipped, "invocation_probe_ok": True,
             "same_idp_verify": same_idp_report, "service_adapter_verified": "failed", "contract_check": None},
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
        "same_idp_verify": same_idp_report,
        "service_adapter_verified": service_adapter_result,
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
        # upstream_url must be set BEFORE the probes run, not after — found
        # live: run_verification_probes' discovery step reuses the existing
        # _run_tool_discovery, which reads upstream_url directly from
        # server_registry itself (not from a parameter), so discovery would
        # target the WRONG url (or 400 on a null one) unless upstream_url
        # already reflects runtime_url before discovery runs.
        #
        # H-01 fix (2026-07-11 audit): status is NOT promoted to 'approved'
        # here anymore — status is the actual entitlement/credential-
        # issuance gate (checked by Registry.refresh(), credential_broker,
        # entitlement checks), and a server whose verification later fails
        # must never have briefly been invocable/entitled. _run_tool_discovery
        # is called with require_approved=False below so discovery can still
        # run against a not-yet-approved row; only the final success block
        # promotes status='approved', atomically with deployment_status=
        # 'verified'.
        await session.execute(text(
            "UPDATE server_registry SET deployment_status = 'verifying', "
            "upstream_url = :upstream_url, updated_at = now() WHERE server_id = :sid"
        ), {"upstream_url": runtime_url, "sid": str(server_id)})
        await session.commit()

    try:
        report = await run_verification_probes(
            server_id, runtime_url, actor_client_id="platform-deploy-verifier",
            require_approved=False,
        )
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
