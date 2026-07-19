"""
PRD-0012 (url-first onboarding, re-approval on change, debug-mode-first) —
shared self-hosted server lifecycle helpers.

The load-bearing correction this whole PRD is built on: runtime enforcement
gates on server_registry.status='approved' (entitlement.py, credential_broker/
registry.py) and tool_registry.status + server_registry.debug_mode
(invocation.py Step 1/1.1) — never submission_status. Every function here
moves those REAL columns, not just the review-queue label.

Two entry points are shared by both C2 (POST /admin/submissions/{id}/approve)
and C3's IP-only auto-approve (POST /api/v1/servers/{id}/request-change):

  - approve_self_hosted_server(): SSRF-validate -> persist upstream_url ->
    run_verification_probes (H-01: status='approved' only after probes pass)
    -> debug_mode=TRUE (real identity, never 'system') -> release quarantined
    tools. One approval code path, one place that can get H-01 wrong.
  - fetch_live_tool_schema(): a READ-ONLY MCP tools/list probe (no DB writes)
    used purely for the IP-only classifier's byte-identical comparison —
    deliberately NOT the same code path as tool discovery, because
    discovery's (server_id, name) dedup is skip-idempotent (does not compare
    schema content) and would silently rubber-stamp a same-named tool whose
    schema actually changed.
"""
from __future__ import annotations

import json
import logging
import uuid
from typing import Any
from urllib.parse import urlparse

import httpx
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import AsyncSessionLocal
from app.services.deploy_verifier import VerificationFailedError, run_verification_probes
from app.services.pinned_transport import PinnedIPTransport
from app.services.server_onboarding import (
    InvalidOnboardingConfig,
    UpstreamRevalidationError,
    revalidate_upstream_ip_at_invoke,
    validate_upstream_url_ssrf,
)
from app.services.ssrf import SSRFError, validate_server_url

logger = logging.getLogger(__name__)

_PROBE_TIMEOUT_SECONDS = 10


class ChangeApprovalError(Exception):
    """Raised by approve_self_hosted_server on any hard-stop (SSRF, probe
    failure). Carries whatever partial verification_report is available so
    the caller can persist it even on failure."""

    def __init__(self, message: str, report: dict | None = None):
        super().__init__(message)
        self.report = report


async def validate_upstream_url_full(upstream_url: str) -> str | None:
    """
    Full SSRF validation (C1/C2 — never the cheap structural guard). Returns
    the matched allowlist entry (possibly "" for public upstreams) for the
    caller to persist as provenance. Raises ChangeApprovalError (fail-closed)
    on rejection.
    """
    from app.core.config import get_settings

    settings = get_settings()
    allowlist = settings.upstream_private_cidr_allowlist_parsed
    try:
        matched_entry = await validate_upstream_url_ssrf(
            upstream_url,
            private_cidr_allowlist=allowlist,
            allow_http_dev=(settings.ENVIRONMENT == "development"),
        )
    except (InvalidOnboardingConfig, SSRFError, ValueError) as exc:
        raise ChangeApprovalError(f"SSRF validation failed: {exc}") from exc
    return matched_entry if matched_entry else None


async def release_all_quarantined_tools_for_server(
    session: AsyncSession, server_id: str, actor: str, notes: str,
) -> int:
    """
    Bulk-release every currently-quarantined tool_registry row for this
    server — the evidence-legitimate release C2/C4 auto-approve perform once
    scan+approval+verification probes have all passed (INV-006/CR-07). Also
    syncs each tool's stored upstream_url to the server's current one, so a
    tool re-released after an IP-only change dispatches to the NEW address
    rather than the stale one captured at original discovery time (discovery's
    (server_id, name) dedup never updates upstream_url on an existing row).

    Returns the number of rows released.
    """
    result = await session.execute(
        text(
            """
            UPDATE tool_registry
            SET status = 'active',
                upstream_url = (
                    SELECT upstream_url FROM server_registry
                    WHERE server_id = :sid
                ),
                released_by = :actor,
                released_at = now(),
                release_notes = :notes,
                updated_at = now()
            WHERE server_id = :sid
              AND deleted_at IS NULL
              AND status = 'quarantined'
            """
        ),
        {"sid": server_id, "actor": actor, "notes": notes},
    )
    return result.rowcount or 0


async def snapshot_tool_schema(session: AsyncSession, server_id: str) -> list[dict]:
    """Read the current active tool set for a server as a sorted
    [{"name","schema"}] list — the same shape persisted into
    last_good_tool_schema and compared against fetch_live_tool_schema()."""
    rows = (
        await session.execute(
            text(
                """
                SELECT name, schema FROM tool_registry
                WHERE server_id = :sid AND deleted_at IS NULL AND status = 'active'
                ORDER BY name
                """
            ),
            {"sid": server_id},
        )
    ).mappings().all()
    return [{"name": r["name"], "schema": r["schema"]} for r in rows]


async def fetch_live_tool_schema(
    upstream_url: str, allowlist_entry: str | None,
) -> list[dict] | None:
    """
    Read-only MCP initialize + tools/list probe against upstream_url — NEVER
    writes to tool_registry. Used only by the C3 IP-only classifier to
    determine whether the live tool set is byte-identical to
    last_good_tool_schema. Returns None (never raises) on any SSRF/network/
    protocol failure — the caller must treat None as "uncertain" and
    fail-safe toward the full re-review path, never toward auto-approval.
    """
    try:
        validate_server_url(
            upstream_url,
            allow_http_localhost=False,
            allowed_cidr=allowlist_entry,
        )
        pinned_ips = await revalidate_upstream_ip_at_invoke(
            upstream_url=upstream_url, registered_allowlist_entry=allowlist_entry,
        )
        hostname = urlparse(upstream_url).hostname or ""
        transport = (
            PinnedIPTransport(pinned_ips[0], hostname) if (pinned_ips and hostname) else None
        )
        headers = {
            "Accept": "application/json, text/event-stream",
            "X-User-Sub": "system:change-classifier",
            "X-User-Role": "admin",
        }
        async with httpx.AsyncClient(transport=transport) as client:
            init_resp = await client.post(
                upstream_url,
                json={
                    "jsonrpc": "2.0", "id": 1, "method": "initialize",
                    "params": {
                        "protocolVersion": "2024-11-05", "capabilities": {},
                        "clientInfo": {
                            "name": "mcp-security-platform-change-classifier", "version": "1.0.0",
                        },
                    },
                },
                headers=headers, timeout=_PROBE_TIMEOUT_SECONDS,
            )
            init_resp.raise_for_status()
            session_id = init_resp.headers.get("Mcp-Session-Id")
            list_headers = dict(headers)
            if session_id:
                list_headers["Mcp-Session-Id"] = session_id
            list_resp = await client.post(
                upstream_url,
                json={"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
                headers=list_headers, timeout=_PROBE_TIMEOUT_SECONDS,
            )
            list_resp.raise_for_status()
            tools = list_resp.json().get("result", {}).get("tools", [])
    except (SSRFError, UpstreamRevalidationError, httpx.HTTPError, ValueError) as exc:
        logger.warning("fetch_live_tool_schema failed url=%s: %s", upstream_url, exc)
        return None

    out = [
        {
            "name": t.get("name"),
            "schema": t.get("inputSchema", {"type": "object", "properties": {}}),
        }
        for t in tools if t.get("name")
    ]
    out.sort(key=lambda d: d["name"])
    return out


def tool_schemas_identical(live: list[dict] | None, last_good: Any) -> bool:
    """Byte-identical comparison (json-normalized) between a live fetch and
    the persisted last_good_tool_schema snapshot. None/missing on either side
    is never treated as a match — fail-safe toward the full re-review path.
    Both sides are independently re-sorted by name here (never assumes the
    caller already sorted either one) so this is safe to call directly."""
    if live is None or not last_good:
        return False
    try:
        last_good_list = last_good if isinstance(last_good, list) else json.loads(last_good)
    except (TypeError, ValueError):
        return False
    normalized_last_good = sorted(
        ({"name": e.get("name"), "schema": e.get("schema")} for e in last_good_list),
        key=lambda d: d["name"] or "",
    )
    normalized_live = sorted(
        ({"name": e.get("name"), "schema": e.get("schema")} for e in live),
        key=lambda d: d["name"] or "",
    )
    return (
        json.dumps(normalized_live, sort_keys=True)
        == json.dumps(normalized_last_good, sort_keys=True)
    )


async def approve_self_hosted_server(
    server_id: str,
    target_upstream_url: str,
    actor: str,
    *,
    new_submission_status: str = "active",
    release_notes: str = "approved: scan passed, server approved, verification probes passed",
) -> dict:
    """
    THE approval code path (C2) — shared verbatim by the manual reviewer
    approve endpoint and C3's IP-only auto-approve. Never inline this logic
    at a second call site; H-01 ordering (status='approved' only after
    probes pass) and TRAP-4 (debug_enabled_by/at set atomically with
    debug_mode=TRUE, real identity, never 'system') both depend on there
    being exactly one place this happens.

    Steps:
      1. Full SSRF-validate target_upstream_url, persist upstream_allowlist_entry.
      2. Persist upstream_url = target_upstream_url (BEFORE verification —
         run_verification_probes' discovery step reads upstream_url straight
         from server_registry, mirroring deploy_verifier.verify_server).
      3. run_verification_probes(require_approved=False) — healthcheck,
         quarantined discovery, invocation probe, same-IdP/service-adapter/
         contract checks. H-01: status stays NOT 'approved' until this
         returns successfully.
      4. On success: status='approved', submission_status=new_submission_status,
         debug_mode=TRUE + debug_enabled_by=actor + debug_enabled_at=now()
         (one statement — satisfies server_registry_debug_consistency CHECK),
         persist verification_report + last_good_* snapshot (this IS the new
         last-known-good the instant it goes live), then release every
         quarantined tool for this server (evidence-legitimate — INV-006/CR-07).
      5. On failure: persist verification_report, leave status/submission_status
         untouched, raise ChangeApprovalError carrying the partial report.

    Returns {"status": "approved", "submission_status": ..., "verification_report": ...,
             "tools_released": N} on success.
    """
    allowlist_entry = await validate_upstream_url_full(target_upstream_url)

    async with AsyncSessionLocal() as session:
        await session.execute(
            text(
                """
                UPDATE server_registry
                SET upstream_url = :url,
                    requested_upstream_url = :url,
                    upstream_allowlist_entry = :allowlist_entry,
                    updated_at = now()
                WHERE server_id = :sid
                """
            ),
            {"url": target_upstream_url, "allowlist_entry": allowlist_entry, "sid": server_id},
        )
        await session.commit()

    try:
        report = await run_verification_probes(
            server_id, target_upstream_url, actor_client_id=actor, require_approved=False,
        )
    except VerificationFailedError as exc:
        async with AsyncSessionLocal() as session:
            await session.execute(
                text(
                    """
                    UPDATE server_registry
                    SET verification_report = CAST(:report AS jsonb), updated_at = now()
                    WHERE server_id = :sid
                    """
                ),
                {"report": json.dumps(exc.report), "sid": server_id},
            )
            await session.commit()
        raise ChangeApprovalError(str(exc), exc.report) from exc

    async with AsyncSessionLocal() as session:
        await session.execute(
            text(
                """
                UPDATE server_registry
                SET status = 'approved',
                    submission_status = :new_status,
                    debug_mode = TRUE,
                    debug_enabled_by = :actor,
                    debug_enabled_at = now(),
                    verification_report = CAST(:report AS jsonb),
                    contract_version = 'v0.1',
                    last_good_upstream_url = :url,
                    last_good_scan_commit = scan_commit,
                    last_good_recorded_at = now(),
                    updated_at = now()
                WHERE server_id = :sid
                """
            ),
            {
                "new_status": new_submission_status, "actor": actor,
                "report": json.dumps(report), "url": target_upstream_url, "sid": server_id,
            },
        )
        tools_released = await release_all_quarantined_tools_for_server(
            session, server_id, actor, release_notes,
        )
        # last_good_tool_schema must reflect the just-released set, not the
        # pre-release snapshot — take it after release commits status='active'
        # on those rows above (same transaction, so the SELECT below sees them).
        tool_schema = await snapshot_tool_schema(session, server_id)
        await session.execute(
            text(
                "UPDATE server_registry SET last_good_tool_schema = CAST(:schema AS jsonb) "
                "WHERE server_id = :sid"
            ),
            {"schema": json.dumps(tool_schema), "sid": server_id},
        )
        await session.commit()

    logger.info(
        "approve_self_hosted_server succeeded server_id=%s actor=%s tools_released=%s",
        server_id, actor, tools_released,
    )
    return {
        "status": "approved",
        "submission_status": new_submission_status,
        "verification_report": report,
        "tools_released": tools_released,
    }


class ServerNotFoundError(Exception):
    """server_id does not exist / is soft-deleted."""


class RequestChangeNotEligibleError(Exception):
    """Server is not in a state request-change can act on (not self-hosted,
    or not currently live) — carries the HTTP status the router should use."""

    def __init__(self, message: str, status_code: int = 409):
        super().__init__(message)
        self.status_code = status_code


async def _fetch_server_for_change(session: AsyncSession, server_id: str) -> dict | None:
    row = (
        await session.execute(
            text(
                """
                SELECT server_id, status, submission_status, is_self_hosted, github_repo_url,
                       requested_upstream_url, upstream_url, scan_commit, upstream_allowlist_entry,
                       owner_sub, maintainers, deleted_at
                FROM server_registry WHERE server_id = :sid
                """
            ),
            {"sid": server_id},
        )
    ).mappings().first()
    return dict(row) if row else None


async def _enqueue_change_rereview(server_id: str, github_repo_url: str | None) -> str | None:
    """TRAP-6: enqueue via the dedicated 'change_rereview_scan' job_type, NOT
    'submission_scan' — scan_evaluator dispatches these to the CAS-guarded
    _evaluate_change_rereview_scan, never the unguarded _evaluate_submission_scan.
    force=True: a request-change re-review must always get a fresh job, never
    dedupe against a stale in-flight job_type='submission_scan' row for the
    same (server_id, github_url) pair."""
    if not github_repo_url:
        return None
    from app.services import scan_queue

    return await scan_queue.enqueue_scan(
        server_id, github_repo_url, job_type="change_rereview_scan", force=True,
    )


async def request_change_for_server(
    server_id: str,
    actor: str,
    *,
    new_upstream_url: str | None = None,
    new_github_repo_url: str | None = None,
    asserted_ip_only: bool = False,
    reason: str = "",
    require_self_hosted: bool = True,
) -> dict:
    """
    PRD-0012 C3 — POST /api/v1/servers/{id}/request-change.

    One transaction:
      1. Snapshot the CURRENT active tool set + upstream_url/scan_commit into
         last_good_* (TRAP-4/product-HIGH-3: this is what reject-rollback
         restores to, and what the IP-only classifier below diffs against —
         taken BEFORE any mutation, never after quarantining).
      2. CAS-demote server_registry: status approved->quarantined,
         submission_status ->'awaiting_review', guarded on
         WHERE status='approved' AND submission_status IN ('approved','active')
         (TRAP-5 — legal source states only; a concurrent
         reject/delete/mid-scan row is rejected, never silently overwritten).
      3. Quarantine EVERY tool_registry row for server_id regardless of
         current status (TRAP-2 — closes the skip-idempotent-discovery hole:
         re-discovery after the change would otherwise skip already-named
         tools and leave them 'active' against a changed/unverified backend).

    Then, outside that transaction, classify:
      - explicit new_github_repo_url change, or asserted_ip_only=False
        (the conservative default) -> full code-change path: enqueue a
        guarded re-review scan (TRAP-6), reviewer must re-approve via the
        normal approve endpoint (C2) once it passes.
      - asserted_ip_only=True: fetch the LIVE tool schema from the new target
        (never the DB-recorded one — discovery's skip-idempotent dedup would
        hide a same-named-but-different-schema drift) and compare against
        the last_good_tool_schema snapshot from step 1. Byte-identical ->
        auto-approve (server_lifecycle.approve_self_hosted_server, landing
        in debug mode, no reviewer step). Any mismatch or fetch failure
        (unreachable, SSRF-rejected, etc.) escalates to the full code-change
        path — fail-safe toward MORE review, never less.
    """
    async with AsyncSessionLocal() as session:
        row = await _fetch_server_for_change(session, server_id)
    if row is None or row.get("deleted_at") is not None:
        raise ServerNotFoundError(f"server {server_id!r} not found")
    # The is_self_hosted gate guards the *URL-change* path (a platform-deployed
    # server's upstream_url is platform-managed, not owner-settable). A code
    # re-review — e.g. triggered by the ops-agent "update from git & rebuild"
    # after it has already rebuilt a platform-hosted container — is valid for any
    # server, so that caller passes require_self_hosted=False. This keeps ONE
    # canonical demote+quarantine+re-scan sequence (never duplicated elsewhere).
    if require_self_hosted and not row.get("is_self_hosted", True):
        raise RequestChangeNotEligibleError(
            "request-change (URL change) only applies to self-hosted servers; "
            "platform-deployed servers change their backend via the build pipeline",
            status_code=400,
        )

    # C1-style: validate a newly-requested URL BEFORE mutating anything — a
    # bad URL must never trigger the quarantine/demote side effects below.
    if new_upstream_url:
        await validate_upstream_url_full(new_upstream_url)

    async with AsyncSessionLocal() as session:
        tool_schema_snapshot = await snapshot_tool_schema(session, server_id)

        set_clauses = [
            "status = 'quarantined'",
            "submission_status = 'awaiting_review'",
            "last_good_upstream_url = upstream_url",
            "last_good_scan_commit = scan_commit",
            "last_good_tool_schema = CAST(:tool_schema AS jsonb)",
            "last_good_recorded_at = now()",
            "updated_at = now()",
        ]
        params: dict[str, Any] = {"sid": server_id, "tool_schema": json.dumps(tool_schema_snapshot)}
        if new_upstream_url:
            set_clauses.append("requested_upstream_url = :new_url")
            params["new_url"] = new_upstream_url
        if new_github_repo_url and new_github_repo_url != row.get("github_repo_url"):
            set_clauses.append("github_repo_url = :new_repo")
            params["new_repo"] = new_github_repo_url

        # set_clauses is built entirely from a fixed, hardcoded set of column
        # assignments above (never from user-supplied column/table names) —
        # all VALUES flow through bound params. Same pattern/rationale as
        # routers/server_registry.py update_server's set_clause construction.
        _update_sql = (
            "UPDATE server_registry SET " + ", ".join(set_clauses) +  # noqa: S608
            " WHERE server_id = :sid AND deleted_at IS NULL AND status = 'approved' "
            "AND submission_status IN ('approved', 'active') RETURNING server_id"
        )
        result = await session.execute(text(_update_sql), params)
        if result.rowcount == 0:
            await session.rollback()
            raise RequestChangeNotEligibleError(
                "server is not in a live state (status='approved', submission_status "
                "in ('approved','active')) — request-change only applies to a "
                "currently-live server", status_code=409,
            )

        quarantine_result = await session.execute(
            text(
                """
                UPDATE tool_registry
                SET status = 'quarantined', updated_at = now()
                WHERE server_id = :sid AND deleted_at IS NULL AND status != 'quarantined'
                """
            ),
            {"sid": server_id},
        )
        tools_quarantined = quarantine_result.rowcount or 0

        event_id = str(uuid.uuid4())
        await session.execute(
            text(
                """
                INSERT INTO audit_events
                (event_id, event_type, client_id, tool_name, outcome, request_id,
                 sha256_hash, latency_ms)
                VALUES (:eid, 'SERVER_CHANGE_REQUESTED', :actor, :server_id, 'allow', :rid, '', 0)
                """
            ),
            {"eid": event_id, "actor": actor, "server_id": server_id, "rid": event_id},
        )
        await session.commit()

    logger.info(
        "request_change_for_server demoted server_id=%s actor=%s tools_quarantined=%s",
        server_id, actor, tools_quarantined,
    )

    code_change_forced = bool(
        new_github_repo_url and new_github_repo_url != row.get("github_repo_url")
    )
    target_url = (
        new_upstream_url or row.get("requested_upstream_url") or row.get("upstream_url")
    )

    if code_change_forced or not asserted_ip_only:
        job_id = await _enqueue_change_rereview(server_id, row.get("github_repo_url"))
        return {
            "server_id": server_id,
            "classification": "code_change",
            "submission_status": "awaiting_review",
            "tools_quarantined": tools_quarantined,
            "job_id": job_id,
        }

    # asserted_ip_only=True: verify it. Any uncertainty escalates to the full
    # path — never assume identical on a fetch failure.
    try:
        allowlist_entry = await validate_upstream_url_full(target_url)
    except ChangeApprovalError:
        allowlist_entry = None
    live_schema = await fetch_live_tool_schema(target_url, allowlist_entry)

    if tool_schemas_identical(live_schema, tool_schema_snapshot):
        try:
            approval = await approve_self_hosted_server(
                server_id, target_url, actor, new_submission_status="active",
                release_notes=f"auto-approved by {actor}: IP-only change, tool schema unchanged",
            )
        except ChangeApprovalError as exc:
            # Schema matched but the live server failed verification (e.g. the
            # new address answers tools/list identically but fails a probe) —
            # fall back to the full re-review path rather than leaving the
            # server stuck quarantined with no forward path.
            job_id = await _enqueue_change_rereview(server_id, row.get("github_repo_url"))
            return {
                "server_id": server_id,
                "classification": "code_change",
                "submission_status": "awaiting_review",
                "tools_quarantined": tools_quarantined,
                "job_id": job_id,
                "auto_approve_attempted": True,
                "auto_approve_error": str(exc),
            }
        return {
            "server_id": server_id,
            "classification": "ip_only",
            "submission_status": approval["submission_status"],
            "debug_mode": True,
            "tools_released": approval["tools_released"],
            "tools_quarantined": tools_quarantined,
        }

    job_id = await _enqueue_change_rereview(server_id, row.get("github_repo_url"))
    return {
        "server_id": server_id,
        "classification": "code_change",
        "submission_status": "awaiting_review",
        "tools_quarantined": tools_quarantined,
        "job_id": job_id,
        "reason": (
            "live tool schema differs from last-approved (or could not be fetched) — "
            "escalated to full re-review"
        ),
    }
