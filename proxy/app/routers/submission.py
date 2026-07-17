"""
MCP Server Submission Router — guided self-service onboarding.

Self-service (any authenticated user):
  POST   /api/v1/submissions              — create draft (wizard step 1)
  PATCH  /api/v1/submissions/{id}         — update wizard data (steps 2-3)
  POST   /api/v1/submissions/{id}/submit  — submit for scan + review
  GET    /api/v1/submissions              — list caller's own submissions
  GET    /api/v1/submissions/{id}         — get submission status + scan report
  GET    /api/v1/submissions/{id}/scaffold — download scaffold zip (no-code path)

Admin review (admin / platform_admin role):
  GET    /api/v1/admin/submissions         — review queue
  POST   /api/v1/admin/submissions/{id}/approve          — approve (pending URL)
  POST   /api/v1/admin/submissions/{id}/reject           — reject
  POST   /api/v1/admin/submissions/{id}/request-changes  — request changes
"""
from __future__ import annotations

import asyncio
import io
import json
import logging
import os
import re
import shutil
import tempfile
import uuid
import zipfile
from typing import Any, Optional

from fastapi import APIRouter, BackgroundTasks, HTTPException, Request
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, HttpUrl, field_validator
from sqlalchemy import text

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import AsyncSessionLocal
from app.services import submission_scanner
from app.services.admin_audit import emit_admin_config_event
from app.services.scaffold_generator import generate_prompts, generate_scaffold
from app.services import prompt_store
from app.services.server_onboarding import (
    InvalidOnboardingConfig,
    validate_mode_and_idp,
    validate_upstream_idp_config,
    validate_upstream_url_ssrf,
)
from app.services.submission_scanner import GITHUB_CLONE_ACCOUNT
from app.services import scan_queue
from app.services.auth_modes import self_service_mode_values

# R-2: cheap structural guard at submit time — well-formed https URL, no
# embedded credentials, no whitespace/control chars. The authoritative
# per-provider host allowlist + SSRF validation runs in the async scanner
# (git_providers). Host is NOT pinned to github here so Bitbucket URLs pass the
# API boundary and are gated by the provider config at scan time.
_SAFE_REPO_URL_RE = re.compile(
    r'^https://[A-Za-z0-9.-]+(:\d+)?/[A-Za-z0-9][A-Za-z0-9_./~-]*(\.git)?/?$'
)

logger = logging.getLogger(__name__)
router = APIRouter(tags=["Submissions"])

# WP-A5 (CR-02 completion): sourced from the canonical AuthMode status
# matrix (services/auth_modes.py) instead of a hand-maintained set — this
# self-service submission wizard only ever offers "supported"-tier modes
# (excludes admin_only passthrough and the deprecated oauth_user_token alias;
# a self-service submitter choosing same-IdP token exchange must now name it
# kc_token_exchange). Was a hardcoded set that had silently drifted behind
# the canonical model: it included oauth_user_token/passthrough (neither
# self-service-selectable) and omitted basic_auth (which is) — exactly the
# drift-prone duplication CR-02 calls out.
_VALID_MODES = self_service_mode_values()
_VALID_CATEGORIES = {
    "pii", "financial", "health", "internal_docs", "source_code",
    "email_calendar", "infrastructure", "public",
}


# ── helpers ──────────────────────────────────────────────────────────────────

def _json_safe(d: dict) -> dict:
    """Convert UUID/datetime values in a mapping to JSON-serializable types."""
    import datetime
    out = {}
    for k, v in d.items():
        if isinstance(v, uuid.UUID):
            out[k] = str(v)
        elif isinstance(v, (datetime.datetime, datetime.date)):
            out[k] = v.isoformat()
        else:
            out[k] = v
    return out


def _client_id(request: Request) -> str:
    cid = getattr(request.state, "client_id", None)
    if not cid:
        raise HTTPException(status_code=401, detail="unauthenticated")
    return cid


# T2 trust-bridge fix: lab-mcp-self-service authenticates to this API with its
# OWN service credential (client_id="lab-self-service", an api_key auth_method
# — see seed.py::seed_self_service_api_key) — it does NOT, and per
# docs/spec/02-credential-broker.md §3.2 MUST NOT, receive a forwarded copy of
# the real caller's session token (passthrough only forwards a client-supplied
# X-Downstream-Authorization header nobody sends; it is not a session-token
# relay). Previously the router had no way to learn the real submitting user,
# so every self-service submission was attributed to the service account.
#
# Fix: the submissions endpoints accept an explicit X-On-Behalf-Of: <sub>
# header, but ONLY from a caller that (a) authenticated itself first via the
# platform's normal HMAC-hashed API-key/OIDC/mTLS resolution in
# middleware/auth.py, AND (b) holds the dedicated `submission_service` role —
# a small, DB-backed allowlist granted only to lab-self-service (seed.py),
# mirroring the identical cross-principal delegation already used by
# routers/profiles.py (_assert_may_write / profile_service role) for the same
# "proxy is the trust anchor, self-service server is not" problem. This is
# NOT a blanket passthrough: a caller without the role that sends the header
# is rejected outright (fails closed) rather than silently falling back to
# its own identity, so a spoofed header can never be mistaken for a no-op.
_ON_BEHALF_OF_ROLES = frozenset({"submission_service"})


def _effective_owner(request: Request) -> str:
    """Resolve the owner_sub for a self-service submission action.

    Normally the owner is the authenticated caller. A trusted service
    principal (see module docstring above) may act on behalf of a real user
    by presenting X-On-Behalf-Of: <sub>. Any other caller sending that header
    is rejected (fail closed) rather than ignored, so spoofing attempts are
    observable and testable.
    """
    caller = _client_id(request)
    on_behalf_of = request.headers.get("x-on-behalf-of", "").strip()
    if not on_behalf_of:
        return caller
    roles = list(getattr(request.state, "client_roles", []) or [])
    if not any(r in _ON_BEHALF_OF_ROLES for r in roles):
        raise HTTPException(
            status_code=403,
            detail="X-On-Behalf-Of requires the submission_service role",
        )
    return on_behalf_of


def _require_admin(request: Request) -> None:
    roles = list(getattr(request.state, "client_roles", []) or [])
    if not any(r in {"admin", "platform_admin"} for r in roles):
        raise HTTPException(status_code=403, detail="admin role required")


def _require_submission_reviewer(request: Request) -> None:
    """Approve/reject/request-changes: admin, platform_admin, or the dedicated
    security_reviewer role (read-only auditors do not get mutate rights)."""
    roles = list(getattr(request.state, "client_roles", []) or [])
    if not any(r in {"admin", "platform_admin", "security_reviewer"} for r in roles):
        raise HTTPException(status_code=403, detail="reviewer role required")


def _require_not_self_review(sub: dict[str, Any], reviewer: str, roles: list[str] | None = None) -> None:
    """Segregation of duties: a submitter may not approve/reject/request-changes
    on their own submission — UNLESS they hold admin/platform_admin. Plain
    security_reviewer still cannot self-review. Explicit operator decision:
    a hard four-eyes rule with no carve-out makes the review queue unusable
    in small/lab deployments where admin is the only identity submitting and
    reviewing (previously required a second reviewer account to exist at all)."""
    if roles and any(r in {"admin", "platform_admin"} for r in roles):
        return
    if sub.get("owner_sub") == reviewer:
        raise HTTPException(
            status_code=403,
            detail="cannot review your own submission — ask another reviewer to approve/reject/request changes",
        )


def _require_reviewer(request: Request) -> None:
    """M2 fix: read-only review queue accessible to security_auditor + auditor, not just admin.
    Also includes security_reviewer: anyone entitled to approve/reject a submission
    (via _require_submission_reviewer) must be able to read it first."""
    roles = list(getattr(request.state, "client_roles", []) or [])
    if not any(
        r in {"admin", "platform_admin", "security_auditor", "auditor", "security_reviewer"}
        for r in roles
    ):
        raise HTTPException(status_code=403, detail="reviewer role required")


# Key-file filter for the reviewer source view: skip directories that are
# never worth showing a human reviewer, and any single file over 100KB
# (binaries, lockfiles with thousands of pinned versions, etc.).
_REVIEW_SKIP_DIRS = {".git", "node_modules", ".venv", "__pycache__", "dist", "build"}
_REVIEW_MAX_FILE_BYTES = 100_000
_REVIEW_MAX_TOTAL_BYTES = 500_000


async def _clone_and_read_repo(
    github_url: str,
) -> tuple[bool, str, list[str], dict[str, str], bool]:
    """
    Shallow-clone github_url (reusing submission_scanner's clone helper) and
    return (success, error, file_tree, file_contents, truncated).

    file_contents only includes text files under _REVIEW_MAX_FILE_BYTES,
    skipping _REVIEW_SKIP_DIRS. Stops adding file contents (but still lists
    the full tree) once _REVIEW_MAX_TOTAL_BYTES is reached, and reports that
    via `truncated=True` — the reviewer sees only some contents, not silently
    all-or-nothing.
    """
    tmpdir = tempfile.mkdtemp(prefix="mcp_review_")
    try:
        repo_path = os.path.join(tmpdir, "repo")
        cloned, err = await submission_scanner._clone_repo(github_url, repo_path)
        if not cloned:
            return False, err, [], {}, False

        tree: list[str] = []
        files: dict[str, str] = {}
        total_bytes = 0
        truncated = False
        for root, dirs, filenames in os.walk(repo_path):
            dirs[:] = [d for d in dirs if d not in _REVIEW_SKIP_DIRS]
            for fname in filenames:
                fpath = os.path.join(root, fname)
                rel = os.path.relpath(fpath, repo_path)
                tree.append(rel)
                # os.walk lists symlinked files (unlike symlinked dirs, which it
                # doesn't descend into) — a malicious repo can commit a symlink
                # to an arbitrary host path (e.g. /etc/passwd) and have it
                # checked out as-is by git. List it in the tree so the reviewer
                # sees it exists, but never follow it to read the target's
                # content: no legitimate MCP server repo needs to symlink to a
                # real file it wants scanned.
                if os.path.islink(fpath):
                    continue
                try:
                    size = os.path.getsize(fpath)
                except OSError:
                    continue
                if size > _REVIEW_MAX_FILE_BYTES:
                    continue
                if total_bytes + size > _REVIEW_MAX_TOTAL_BYTES:
                    truncated = True
                    continue
                try:
                    with open(fpath, "r", encoding="utf-8") as f:
                        content = f.read()
                except (UnicodeDecodeError, OSError):
                    continue  # binary or unreadable — listed in tree, no contents
                files[rel] = content
                total_bytes += size
        return True, "", sorted(tree), files, truncated
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


async def _get_submission(server_id: str, owner_sub: str | None = None) -> dict[str, Any]:
    async with AsyncSessionLocal() as session:
        q = "SELECT * FROM server_registry WHERE server_id = :sid AND deleted_at IS NULL"
        params: dict = {"sid": server_id}
        if owner_sub:
            q += " AND owner_sub = :owner"
            params["owner"] = owner_sub
        row = (await session.execute(text(q), params)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="submission not found")
    return dict(row._mapping)


# ── Pydantic models ───────────────────────────────────────────────────────────

def _validate_github_url(v: Optional[str]) -> Optional[str]:
    """Cheap structural guard at submit time (R-2): require a well-formed https
    URL with a bare host path and no embedded credentials. The authoritative
    provider-host allowlist + SSRF check runs asynchronously in the submission
    scanner (git_providers.match_provider / validate_host), which is where an
    unknown/disabled host or a private-IP target is actually rejected. This
    validator only rejects obviously-malformed input (non-https, credentials,
    whitespace, control chars) without hardcoding a single provider host."""
    if v is None or v == "":
        return None
    if not _SAFE_REPO_URL_RE.match(v):
        raise ValueError(
            "repository URL must be https://<host>/<path> with no embedded credentials"
        )
    return v


class DraftCreate(BaseModel):
    name: str
    description: str = ""
    github_repo_url: Optional[str] = None  # None = no-code path

    @field_validator("name")
    @classmethod
    def name_slug(cls, v: str) -> str:
        if not re.match(r'^[a-z0-9][a-z0-9\-]{1,62}$', v.lower()):
            raise ValueError("name must be 2-63 chars, lowercase alphanumeric and hyphens")
        return v.lower()

    @field_validator("github_repo_url")
    @classmethod
    def validate_github_url(cls, v: Optional[str]) -> Optional[str]:
        return _validate_github_url(v)


class DraftUpdate(BaseModel):
    description: Optional[str] = None
    github_repo_url: Optional[str] = None
    injection_mode: Optional[str] = None
    requested_upstream_url: Optional[str] = None

    @field_validator("github_repo_url")
    @classmethod
    def validate_github_url(cls, v: Optional[str]) -> Optional[str]:
        return _validate_github_url(v)
    upstream_idp_type: Optional[str] = None
    upstream_idp_config: Optional[dict] = None
    mode_override_reason: Optional[str] = None
    data_categories: Optional[list[str]] = None
    has_write_ops: Optional[bool] = None

    @field_validator("injection_mode")
    @classmethod
    def valid_mode(cls, v: str | None) -> str | None:
        if v and v not in _VALID_MODES:
            raise ValueError(f"unknown injection_mode '{v}'")
        return v

    @field_validator("data_categories")
    @classmethod
    def valid_cats(cls, v: list[str] | None) -> list[str] | None:
        if v:
            bad = set(v) - _VALID_CATEGORIES
            if bad:
                raise ValueError(f"unknown categories: {bad}")
        return v


class ReviewAction(BaseModel):
    notes: str = ""
    # WP-A2 (CR-13 + CR-03 fold-in): explicit reviewer acknowledgement that
    # high-risk scopes (write/admin/mail/files/offline_access) were reviewed
    # and are intentionally approved. Approval-time validation rejects any
    # submission requesting a high-risk scope unless this is true — a
    # policy-subset pass alone is not sufficient for those scopes.
    high_risk_scopes_approved: bool = False
    # Optional reviewer override of the approved kc_token_exchange audience /
    # scopes; when omitted, the requested upstream_idp_config values are used
    # as-is (still subject to oauth_policy validation below).
    approved_token_audience: Optional[str] = None
    approved_token_scopes: Optional[list[str]] = None


# ── Self-service endpoints ────────────────────────────────────────────────────

@router.post("/api/v1/submissions", status_code=201)
async def create_draft(body: DraftCreate, request: Request) -> JSONResponse:
    """Create a draft submission (wizard step 1)."""
    owner = _effective_owner(request)
    sid = str(uuid.uuid4())
    async with AsyncSessionLocal() as session:
        # Check for name collision by this owner
        existing = (await session.execute(text(
            "SELECT 1 FROM server_registry WHERE name = :name AND owner_sub = :owner AND deleted_at IS NULL"
        ), {"name": body.name, "owner": owner})).fetchone()
        if existing:
            raise HTTPException(status_code=409, detail="you already have a server named '{}'".format(body.name))

        await session.execute(text("""
            INSERT INTO server_registry
                (server_id, name, upstream_url, status, owner_sub, injection_mode,
                 github_repo_url, description, submission_status, scan_status)
            VALUES
                (:sid, :name, '', 'pending', :owner, 'none',
                 :repo_url, :description, 'draft', 'pending')
        """), {
            "sid": sid,
            "name": body.name,
            "owner": owner,
            "repo_url": body.github_repo_url,
            "description": body.description,
        })
        await session.commit()
    return JSONResponse({"server_id": sid, "submission_status": "draft"}, status_code=201)


@router.patch("/api/v1/submissions/{server_id}")
async def update_draft(server_id: str, body: DraftUpdate, request: Request) -> JSONResponse:
    """Update wizard data (steps 2-3). Only allowed in draft or changes_requested state."""
    owner = _effective_owner(request)
    sub = await _get_submission(server_id, owner_sub=owner)
    if sub["submission_status"] not in ("draft", "changes_requested"):
        raise HTTPException(status_code=409, detail="submission is not in an editable state")

    # WP-A5 (CR-02 completion): approval-time-style validator moved to
    # draft/update time — this is the wizard's PATCH step, and previously
    # nothing checked mode<->upstream_idp_type/config compatibility here at
    # all (only the much-later oauth_policy approval gate did, and only for
    # oauth-ish modes). A submitter could PATCH a genuinely contradictory
    # combination (e.g. injection_mode='entra_user_token' with
    # upstream_idp_type='gateway_idp') and only discover it was invalid at
    # first invocation.
    #
    # Deliberately permissive on "not yet specified": the current wizard UI
    # (portal.py's self-service flow) never sends upstream_idp_type at all —
    # only injection_mode + upstream_idp_config. Only run the mode<->idp_type
    # compatibility check when an upstream_idp_type IS actually present
    # (either in this request or already stored) — this catches real
    # contradictions (via direct API use, or a future wizard revision that
    # does send it) without rejecting today's in-progress, idp_type-less
    # drafts. Because this is a PARTIAL update across multiple wizard steps,
    # the check uses the EFFECTIVE merged state (existing row + this patch),
    # not just the fields present in this one request.
    if body.injection_mode is not None or body.upstream_idp_type is not None or body.upstream_idp_config is not None:
        effective_mode = body.injection_mode if body.injection_mode is not None else (sub.get("injection_mode") or "none")
        effective_idp_type = body.upstream_idp_type if body.upstream_idp_type is not None else sub.get("upstream_idp_type")
        effective_idp_config = body.upstream_idp_config if body.upstream_idp_config is not None else sub.get("upstream_idp_config")
        if effective_idp_type:
            try:
                validate_mode_and_idp(effective_mode, effective_idp_type, effective_idp_config)
                validate_upstream_idp_config(effective_idp_type, effective_idp_config)
            except InvalidOnboardingConfig as exc:
                raise HTTPException(status_code=400, detail={"code": "VALIDATION_ERROR", "message": str(exc)}) from exc

    updates: dict[str, Any] = {"updated_at": "now()"}
    fields: list[str] = []

    def _set(col: str, val: Any) -> None:
        if val is not None:
            fields.append(f"{col} = :{col}")
            updates[col] = val

    _set("github_repo_url", body.github_repo_url)
    _set("description", body.description)
    _set("requested_upstream_url", body.requested_upstream_url)
    _set("injection_mode", body.injection_mode)
    _set("upstream_idp_type", body.upstream_idp_type)
    _set("mode_override_reason", body.mode_override_reason)
    _set("has_write_ops", body.has_write_ops)

    if body.upstream_idp_config is not None:
        fields.append("upstream_idp_config = CAST(:idp_config AS jsonb)")
        updates["idp_config"] = json.dumps(body.upstream_idp_config)

    if body.data_categories is not None:
        fields.append("data_categories = :cats")
        updates["cats"] = body.data_categories

    # CRITICAL-1 fix: the submitter must NOT control service_name — it is the
    # credential lookup key, and letting a self-service submitter set it (here it
    # even wrongly stored body.description into it) enabled the cross-user token
    # bleed. Description is not a credential key; drop this mapping entirely.
    # service_name is set only via the admin/approval path (server_registry PATCH,
    # constrained to the registered-adapter allowlist).
    # (body.description is intentionally not persisted to service_name.)

    if not fields:
        return JSONResponse({"server_id": server_id, "updated": False})

    set_clause = ", ".join(fields) + ", updated_at = now()"
    async with AsyncSessionLocal() as session:
        await session.execute(
            text(f"UPDATE server_registry SET {set_clause} WHERE server_id = :sid"),
            {**updates, "sid": server_id},
        )
        await session.commit()
    return JSONResponse({"server_id": server_id, "updated": True})


@router.post("/api/v1/submissions/{server_id}/submit")
async def submit_for_review(
    server_id: str, request: Request, background_tasks: BackgroundTasks
) -> JSONResponse:
    """Submit the draft for automated scan + security review."""
    owner = _effective_owner(request)

    # A reviewer cannot approve a server they don't understand. Require the
    # submitter to actually answer "what does this do" and "where will it
    # run" before the submission can even enter the queue — description was
    # previously collected by the wizard and silently dropped, so submissions
    # with no description at all reached awaiting_review. requested_upstream_url
    # used to be required only for repo-backed submissions (the no-code path
    # has no server yet) — but that carve-out let a no-code submission reach
    # the SAME awaiting_review queue as a real one with nothing but a free-text
    # description, indistinguishable to a reviewer from an incomplete config.
    # Both fields — and injection_mode, the auth *type* (never the secret
    # itself) — are now required unconditionally: get_server_scaffold remains
    # available with no submission at all for "I don't have code/a server yet",
    # so this doesn't block that path, it just keeps it out of the review queue.
    sub = await _get_submission(server_id, owner_sub=owner)
    missing: list[str] = []
    if not (sub.get("description") or "").strip():
        missing.append("description")
    if not (sub.get("requested_upstream_url") or "").strip():
        missing.append("requested_upstream_url")
    if not (sub.get("injection_mode") or "").strip():
        missing.append("injection_mode")
    if missing:
        raise HTTPException(
            status_code=422,
            detail={
                "code": "INCOMPLETE_SUBMISSION",
                "message": f"Missing required field(s) before submitting for review: {', '.join(missing)}",
                "missing_fields": missing,
            },
        )

    # M1 fix: atomic conditional update — no separate read-then-write.
    # If two concurrent requests race, only one wins the CAS; the other gets rowcount=0 → 409.
    async with AsyncSessionLocal() as session:
        row = (await session.execute(text("""
            UPDATE server_registry
            SET submission_status = CASE
                    WHEN github_repo_url IS NOT NULL AND github_repo_url != ''
                    THEN 'scan_pending'
                    ELSE 'awaiting_review'
                END,
                scan_status  = CASE
                    WHEN github_repo_url IS NOT NULL AND github_repo_url != ''
                    THEN 'pending'
                    ELSE 'not_applicable'
                END,
                scan_report  = CASE
                    WHEN github_repo_url IS NOT NULL AND github_repo_url != ''
                    THEN '[]'::jsonb
                    ELSE scan_report
                END,
                updated_at = now()
            WHERE server_id = :sid
              AND owner_sub  = :owner
              AND submission_status IN ('draft', 'changes_requested', 'scan_blocked')
            RETURNING server_id, github_repo_url, submission_status
        """), {"sid": server_id, "owner": owner})).fetchone()
        await session.commit()

    if not row:
        # No row updated → either not found, not owned, or wrong state
        try:
            sub = await _get_submission(server_id, owner_sub=owner)
            raise HTTPException(status_code=409, detail="submission cannot be submitted from its current state")
        except HTTPException:
            raise

    github_url = row.github_repo_url
    new_status = row.submission_status

    if github_url:
        # CR-14: clone + scanner execution moved to the isolated scanner-worker
        # service. The proxy only enqueues; scan_evaluator (proxy-side, never
        # touches attacker-controlled repo content) applies policy once the
        # worker writes a raw result.
        background_tasks.add_task(scan_queue.enqueue_scan, server_id, github_url, "submission_scan")

    return JSONResponse({"server_id": server_id, "submission_status": new_status})


@router.get("/api/v1/submissions")
async def list_submissions(request: Request) -> JSONResponse:
    """List the caller's own submissions."""
    owner = _effective_owner(request)
    async with AsyncSessionLocal() as session:
        rows = (await session.execute(text("""
            SELECT server_id, name, submission_status, scan_status,
                   injection_mode, data_categories, github_repo_url, updated_at,
                   description, requested_upstream_url, upstream_url, service_name
            FROM server_registry
            WHERE owner_sub = :owner AND deleted_at IS NULL
            ORDER BY updated_at DESC
        """), {"owner": owner})).fetchall()
    return JSONResponse({"submissions": [_json_safe(dict(r._mapping)) for r in rows]})


@router.get("/api/v1/submissions/{server_id}")
async def get_submission(server_id: str, request: Request) -> JSONResponse:
    """Get submission status and scan report."""
    owner = _effective_owner(request)
    sub = await _get_submission(server_id, owner_sub=owner)
    safe = _json_safe(dict(sub))
    return JSONResponse({
        "server_id": safe["server_id"],
        "name": safe["name"],
        "submission_status": safe["submission_status"],
        "scan_status": safe["scan_status"],
        "scan_report": safe.get("scan_report") or [],
        "injection_mode": safe.get("injection_mode"),
        "data_categories": list(safe.get("data_categories") or []),
        "github_repo_url": safe.get("github_repo_url"),
        "description": safe.get("description"),
        "requested_upstream_url": safe.get("requested_upstream_url"),
        "upstream_url": safe.get("upstream_url") or None,
        "service_name": safe.get("service_name"),
        "review_notes": safe.get("review_notes"),
        "github_clone_account": GITHUB_CLONE_ACCOUNT,
        # WP-A2 (CR-13 + CR-03 fold-in): requested-vs-approved OAuth/IdP config
        # surfacing. upstream_idp_config/upstream_idp_type are the
        # submitter-REQUESTED values; the approved_* fields are reviewer-set
        # (null until /approve runs the oauth_policy gate).
        "upstream_idp_type": safe.get("upstream_idp_type"),
        "upstream_idp_config": safe.get("upstream_idp_config"),
        "approved_upstream_idp_config": safe.get("approved_upstream_idp_config"),
        "approved_token_audience": safe.get("approved_token_audience"),
        "approved_oauth_scopes": list(safe.get("approved_oauth_scopes") or []),
        "oauth_policy_id": safe.get("oauth_policy_id"),
        "high_risk_scopes_approved_by": safe.get("high_risk_scopes_approved_by"),
        "high_risk_scopes_approved_at": safe.get("high_risk_scopes_approved_at"),
    })


@router.get("/api/v1/admin/submissions/{server_id}/sbom")
async def download_sbom(server_id: str, request: Request) -> JSONResponse:
    """R-5: download the CycloneDX SBOM captured at scan time (reviewer/admin)."""
    _require_submission_reviewer(request)
    from sqlalchemy import text as _text
    from app.core.database import AsyncSessionLocal as _S
    async with _S() as session:
        row = (await session.execute(_text(
            "SELECT sbom_cyclonedx FROM server_registry WHERE server_id = :sid AND deleted_at IS NULL"
        ), {"sid": server_id})).mappings().first()
    if row is None or row["sbom_cyclonedx"] is None:
        raise HTTPException(status_code=404, detail="No CycloneDX SBOM for this submission")
    doc = row["sbom_cyclonedx"]
    if isinstance(doc, str):
        doc = json.loads(doc)
    return JSONResponse(doc, headers={
        "Content-Disposition": f'attachment; filename="sbom-{server_id}.cdx.json"'
    })


@router.get("/api/v1/submissions/{server_id}/prompts")
async def get_design_prompts(server_id: str, request: Request) -> JSONResponse:
    """Return design prompts for the no-code path — questions to answer before writing the server."""
    owner = _effective_owner(request)
    sub = await _get_submission(server_id, owner_sub=owner)
    mode = sub.get("injection_mode") or "none"
    prompts = await prompt_store.prompts_for_mode(mode)
    return JSONResponse({"server_id": server_id, "injection_mode": mode, "prompts": prompts})


@router.get("/api/v1/submissions/{server_id}/scaffold")
async def download_scaffold(server_id: str, request: Request) -> StreamingResponse:
    """
    Download a scaffold zip for the no-code path.

    Owner or reviewer (admin/platform_admin) — a reviewer needs to see exactly
    what a no-code submitter will receive as part of reviewing the submission
    (the admin review UI links here); owner-only access made that 404.
    """
    caller = _effective_owner(request)
    caller_roles = list(getattr(request.state, "client_roles", []) or [])
    is_reviewer = any(r in {"admin", "platform_admin"} for r in caller_roles)
    sub = await _get_submission(server_id, owner_sub=None if is_reviewer else caller)
    mode = sub.get("injection_mode") or "none"
    name = sub["name"]
    from app.core.config import get_settings as _get_scaffold_settings
    _issuer = _get_scaffold_settings().OIDC_ISSUER_URL
    files = generate_scaffold(
        name, mode, issuer=_issuer,
        jwks_uri=f"{_issuer.rstrip('/')}/protocol/openid-connect/certs" if _issuer else "",
    )

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for fname, content in files.items():
            zf.writestr(f"{name}/{fname}", content)
    buf.seek(0)

    return StreamingResponse(
        buf,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{name}-scaffold.zip"'},
    )


# ── Admin review endpoints ────────────────────────────────────────────────────

@router.get("/api/v1/admin/submissions")
async def list_review_queue(request: Request) -> JSONResponse:
    """Security team review queue — all non-draft submissions."""
    _require_reviewer(request)  # M2 fix: auditors can read; only admins can mutate
    async with AsyncSessionLocal() as session:
        rows = (await session.execute(text("""
            SELECT server_id, name, owner_sub, submission_status, scan_status,
                   injection_mode, data_categories, has_write_ops,
                   github_repo_url, scan_report, review_notes,
                   reviewed_by, reviewed_at, created_at, updated_at,
                   upstream_url, service_name, upstream_idp_type, upstream_idp_config,
                   description, requested_upstream_url
            FROM server_registry
            WHERE submission_status NOT IN ('draft')
              AND deleted_at IS NULL
            ORDER BY
              CASE submission_status
                WHEN 'awaiting_review' THEN 1
                WHEN 'scan_blocked'    THEN 2
                ELSE 3
              END,
              updated_at DESC
        """))).fetchall()
    return JSONResponse({"submissions": [_json_safe(dict(r._mapping)) for r in rows]})


_OAUTH_EXCHANGE_MODES = ("kc_token_exchange", "oauth_user_token")
# WP-A3 (CR-04 remainder): external_oauth_* joins the same scope-set policy
# gate as entra_* — issuer/tenant → allowed_scopes, same oauth_provider_policy
# table, same high-risk-scope reviewer-ack requirement. No special-casing
# needed here; validate_requested_config only looks at issuer/tenant/scopes/
# redirect_uri/client_auth_method, all present in external_oauth's config shape.
_OAUTH_ISSUER_MODES = (
    "entra_client_credentials", "entra_user_token",
    "external_oauth_client_credentials", "external_oauth_user_token",
)


def _parse_idp_config(raw: Any) -> dict | None:
    if not raw:
        return None
    if isinstance(raw, dict):
        return raw
    try:
        parsed = json.loads(raw)
    except (TypeError, ValueError):
        return None
    return parsed if isinstance(parsed, dict) else None


async def _validate_oauth_policy_at_approval(
    session: AsyncSession,
    sub: dict[str, Any],
    body: "ReviewAction",
) -> dict[str, Any]:
    """
    WP-A2 (CR-13 + CR-03 fold-in): approval-time OAuth/IdP policy gate.

    Returns a dict of columns to persist alongside submission_status:
      approved_upstream_idp_config, approved_token_audience,
      approved_token_scopes (persisted to the approved_oauth_scopes TEXT[]
      column), oauth_policy_id, high_risk_scopes_approved_by,
      high_risk_scopes_approved_at.

    All values are None/empty when the submission has no OAuth/IdP config to
    approve (service/user/service_account/basic_auth/none modes) — nothing to
    validate, nothing changes for those submissions.

    Raises HTTPException(422) — fail-closed — on any policy violation:
    unknown issuer, overbroad/blocked scope, high-risk scope without explicit
    ack, disallowed redirect/client-auth-method, or an unapproved
    kc_token_exchange audience.
    """
    from app.services import oauth_policy

    result: dict[str, Any] = {
        "approved_upstream_idp_config": None,
        "approved_token_audience": None,
        "approved_token_scopes": [],
        "oauth_policy_id": None,
        # NOTE: this is a bool marker, not the reviewer identity — the caller
        # (approve_submission) substitutes the actual reviewer sub only when
        # this is truthy, so the reviewer identity is always read from the
        # authenticated request, never from anything derived here.
        "high_risk_scopes_approved_by": False,
    }

    effective_mode = sub.get("injection_mode") or sub.get("default_injection_mode") or "none"
    requested_config = _parse_idp_config(sub.get("upstream_idp_config"))

    if effective_mode in _OAUTH_EXCHANGE_MODES:
        # Audience-STRING dimension (RFC 8693) — a completely different shape
        # than the scope-set dimension below; see oauth_policy module docstring.
        requested_audience = (requested_config or {}).get("audience") or body.approved_token_audience
        if not requested_audience:
            raise HTTPException(
                status_code=422,
                detail={"code": "OAUTH_POLICY_VIOLATION", "message": "kc_token_exchange mode requires an audience to approve"},
            )
        from app.core.config import get_settings as _get_kc_settings
        env_allowed = _get_kc_settings().kc_token_exchange_allowed_audiences_parsed
        if requested_audience not in env_allowed:
            raise HTTPException(
                status_code=422,
                detail={
                    "code": "OAUTH_POLICY_VIOLATION",
                    "message": f"audience {requested_audience!r} not in platform KC_TOKEN_EXCHANGE_ALLOWED_AUDIENCES ceiling {sorted(env_allowed)}",
                },
            )
        result["approved_upstream_idp_config"] = requested_config
        result["approved_token_audience"] = body.approved_token_audience or requested_audience
        return result

    if effective_mode in _OAUTH_ISSUER_MODES:
        # Scope-SET dimension — issuer/tenant-scoped oauth_provider_policy row.
        if not requested_config:
            raise HTTPException(
                status_code=422,
                detail={"code": "OAUTH_POLICY_VIOLATION", "message": f"{effective_mode} mode requires upstream_idp_config to approve"},
            )
        try:
            validated = await oauth_policy.validate_requested_config(
                session,
                upstream_idp_config=requested_config,
                high_risk_scopes_approved=body.high_risk_scopes_approved,
            )
        except oauth_policy.OAuthPolicyError as exc:
            raise HTTPException(status_code=422, detail={"code": "OAUTH_POLICY_VIOLATION", "message": str(exc)}) from exc

        result["approved_upstream_idp_config"] = requested_config
        result["approved_token_scopes"] = (
            body.approved_token_scopes if body.approved_token_scopes is not None else validated.approved_scopes
        )
        result["oauth_policy_id"] = validated.policy.id
        result["high_risk_scopes_approved_by"] = bool(validated.high_risk_scopes)
        return result

    # Not an OAuth/IdP-governed mode: nothing to validate/approve.
    return result


@router.get("/api/v1/admin/submissions/{server_id}/review")
async def review_submission_detail(server_id: str, request: Request) -> JSONResponse:
    """Full review detail for one submission: config, scan/SBOM report, and
    (if a repo was provided) its file tree + key file contents, fetched via
    a fresh shallow clone — never the DB, and never a stored copy."""
    _require_reviewer(request)
    sub = await _get_submission(server_id)

    repo: dict[str, Any] | None = None
    github_url = sub.get("github_repo_url")
    if github_url:
        cloned, err, tree, files, truncated = await _clone_and_read_repo(github_url)
        if cloned:
            repo = {"url": github_url, "tree": tree, "files": files, "truncated": truncated}
        else:
            repo = {"url": github_url, "error": err}

    return JSONResponse({
        "server_id": sub["server_id"] if isinstance(sub["server_id"], str) else str(sub["server_id"]),
        "name": sub["name"],
        "owner_sub": sub["owner_sub"],
        "submission_status": sub["submission_status"],
        "config": {
            "injection_mode": sub.get("injection_mode"),
            "data_categories": sub.get("data_categories") or [],
            "has_write_ops": sub.get("has_write_ops", False),
        },
        "scan_report": sub.get("scan_report") or [],
        "sbom_components": sub.get("sbom_components") or [],
        "review_notes": sub.get("review_notes"),
        "repo": repo,
    })


@router.post("/api/v1/admin/submissions/{server_id}/approve")
async def approve_submission(server_id: str, body: ReviewAction, request: Request) -> JSONResponse:
    """Approve submission — repo path moves to approved_pending_url (submitter still
    supplies the running URL); no-code path (F-15) has no URL to ever supply, so it
    goes straight to the terminal 'scaffold_ready' state instead — never
    approved_pending_url, never "active"/"running" language.

    WP-A2 (CR-13 + CR-03 fold-in): this is also the single reviewer gate where
    requested OAuth/IdP config (server_registry.upstream_idp_config,
    submitter-controlled) is validated against oauth_provider_policy and, if
    it passes, copied into the approved_* columns that dispatch-time code
    actually reads. A policy violation blocks approval entirely (422) — the
    submission stays 'awaiting_review' until re-submitted with a compliant
    config or a policy row is added by an admin.
    """
    _require_submission_reviewer(request)
    reviewer = _client_id(request)
    sub = await _get_submission(server_id)
    _require_not_self_review(sub, reviewer, list(getattr(request.state, "client_roles", []) or []))
    if sub["submission_status"] != "awaiting_review":
        raise HTTPException(status_code=409, detail="submission is not awaiting review")
    # A-06 fix: scan must have completed (or been genuinely not-applicable — no
    # repo to scan) before human approval. Blocks 'blocked', 'pending', 'scan_running'.
    # 'review_required' (CR-12/WP-B2: unknown-severity CVE, no npm lockfile, or a
    # govulncheck module-load failure) is reviewable — a human may approve past it
    # (optionally after adding a waiver) but it is never auto-approved like 'passed'.
    if sub.get("scan_status") not in ("passed", "not_applicable", "review_required"):
        raise HTTPException(status_code=409, detail="cannot approve a scan-blocked submission")

    # R-10/F-15: no-code submissions (no repo) can never reach provide_running_url —
    # there is no server anywhere to supply a URL for.
    new_status = "approved_pending_url" if sub.get("github_repo_url") else "scaffold_ready"

    async with AsyncSessionLocal() as session:
        oauth_approval = await _validate_oauth_policy_at_approval(session, sub, body)
        high_risk_by = reviewer if oauth_approval.get("high_risk_scopes_approved_by") else None
        await session.execute(text("""
            UPDATE server_registry
            SET submission_status = :new_status,
                review_notes = :notes,
                reviewed_by = :reviewer,
                reviewed_at = now(),
                updated_at = now(),
                approved_upstream_idp_config = CAST(:approved_idp_config AS jsonb),
                approved_token_audience = :approved_token_audience,
                approved_oauth_scopes = :approved_oauth_scopes,
                oauth_policy_id = CAST(:oauth_policy_id AS uuid),
                high_risk_scopes_approved_by = :high_risk_by,
                high_risk_scopes_approved_at = CASE WHEN CAST(:high_risk_by AS TEXT) IS NOT NULL THEN now() ELSE high_risk_scopes_approved_at END
            WHERE server_id = :sid
        """), {
            "notes": body.notes, "reviewer": reviewer, "sid": server_id, "new_status": new_status,
            "approved_idp_config": json.dumps(oauth_approval["approved_upstream_idp_config"]) if oauth_approval["approved_upstream_idp_config"] is not None else None,
            "approved_token_audience": oauth_approval["approved_token_audience"],
            # approved_oauth_scopes is TEXT[] (pre-existing V014 column, now wired
            # up) — a plain Python list binds directly, same pattern as
            # data_categories elsewhere in this file.
            "approved_oauth_scopes": oauth_approval["approved_token_scopes"] or [],
            "oauth_policy_id": oauth_approval["oauth_policy_id"],
            "high_risk_by": high_risk_by,
        })
        await session.commit()
    await emit_admin_config_event(
        reviewer, "submission_approve", server_id,
        {
            "notes": body.notes,
            "submission_status": new_status,
            "oauth_policy_id": oauth_approval.get("oauth_policy_id"),
            "high_risk_scopes_approved_by": high_risk_by,
        },
    )
    return JSONResponse({"server_id": server_id, "submission_status": new_status})


@router.post("/api/v1/admin/submissions/{server_id}/reject")
async def reject_submission(server_id: str, body: ReviewAction, request: Request) -> JSONResponse:
    """Reject a submission permanently."""
    _require_submission_reviewer(request)
    reviewer = _client_id(request)
    _require_not_self_review(await _get_submission(server_id), reviewer, list(getattr(request.state, "client_roles", []) or []))
    async with AsyncSessionLocal() as session:
        # M3 fix: state guard prevents corrupting active servers via reject API.
        result = await session.execute(text("""
            UPDATE server_registry
            SET submission_status = 'rejected',
                review_notes = :notes,
                reviewed_by = :reviewer,
                reviewed_at = now(),
                updated_at = now()
            WHERE server_id = :sid
              AND deleted_at IS NULL
              AND submission_status IN ('awaiting_review', 'scan_blocked', 'scan_pending', 'changes_requested')
        """), {"notes": body.notes, "reviewer": reviewer, "sid": server_id})
        await session.commit()
    if result.rowcount == 0:
        raise HTTPException(status_code=409, detail="submission is not in a rejectable state")
    await emit_admin_config_event(
        reviewer, "submission_reject", server_id, {"notes": body.notes},
    )
    return JSONResponse({"server_id": server_id, "submission_status": "rejected"})


@router.post("/api/v1/admin/submissions/{server_id}/request-changes")
async def request_changes(server_id: str, body: ReviewAction, request: Request) -> JSONResponse:
    """Return a submission to the submitter with change notes."""
    _require_submission_reviewer(request)
    reviewer = _client_id(request)
    _require_not_self_review(await _get_submission(server_id), reviewer, list(getattr(request.state, "client_roles", []) or []))
    async with AsyncSessionLocal() as session:
        # M3 fix: state guard prevents request-changes on already-approved servers.
        result = await session.execute(text("""
            UPDATE server_registry
            SET submission_status = 'changes_requested',
                review_notes = :notes,
                reviewed_by = :reviewer,
                reviewed_at = now(),
                updated_at = now()
            WHERE server_id = :sid
              AND deleted_at IS NULL
              AND submission_status IN ('awaiting_review', 'scan_blocked', 'changes_requested')
        """), {"notes": body.notes, "reviewer": reviewer, "sid": server_id})
        await session.commit()
    if result.rowcount == 0:
        raise HTTPException(status_code=409, detail="submission is not in a state that allows requesting changes")
    await emit_admin_config_event(
        reviewer, "submission_request_changes", server_id, {"notes": body.notes},
    )
    return JSONResponse({"server_id": server_id, "submission_status": "changes_requested"})


@router.post("/api/v1/submissions/{server_id}/provide-url")
async def provide_running_url(server_id: str, request: Request) -> JSONResponse:
    """Submitter provides the running server URL after approval."""
    owner = _effective_owner(request)
    body = await request.json()
    upstream_url = body.get("upstream_url", "").strip()
    if not upstream_url:
        raise HTTPException(status_code=422, detail="upstream_url required")

    # H2 fix: check ownership + state BEFORE the SSRF DNS probe so the
    # endpoint cannot be used as a DNS oracle by non-owners.
    sub = await _get_submission(server_id, owner_sub=owner)
    if sub["submission_status"] != "approved_pending_url":
        raise HTTPException(status_code=409, detail="submission is not in approved_pending_url state")

    # SSRF guard runs after ownership is confirmed (H2 fix).
    #
    # R-10 provenance fix: this endpoint is the self-service equivalent of the
    # admin registration route (server_registry.py create_server), so it must
    # use the SAME SSRF mechanism — validate_upstream_url_ssrf with the
    # UPSTREAM_PRIVATE_CIDR_ALLOWLIST — and persist the matched CIDR into
    # server_registry.upstream_allowlist_entry. That column is the provenance
    # record revalidate_upstream_ip_at_invoke checks on EVERY discovery and
    # invocation (DNS-rebind/TOCTOU guard); without it, any private upstream
    # registered here is permanently denied at discovery time. Dev-mode lab
    # backends (lab-mcp-*) serve plain HTTP internally, so allow_http_dev is
    # gated on ENVIRONMENT == "development" — but even then the target must
    # resolve entirely inside an explicit allowlist CIDR (stricter than the
    # old validate_server_url dev branch: a public or un-allowlisted-private
    # HTTP target is rejected, and every accepted private target leaves a
    # persisted allowlist-entry record).
    from app.core.config import settings as _settings
    try:
        _matched_entry = await validate_upstream_url_ssrf(
            upstream_url,
            private_cidr_allowlist=_settings.upstream_private_cidr_allowlist_parsed,
            allow_http_dev=(_settings.ENVIRONMENT == "development"),
        )
    except InvalidOnboardingConfig as exc:
        raise HTTPException(status_code=422, detail=f"upstream_url rejected: {exc}") from exc
    upstream_allowlist_entry: str | None = _matched_entry if _matched_entry else None

    # B-03 fix: 'status' (not 'submission_status') is what the rest of the
    # platform actually gates on — Registry.refresh(), credential_broker,
    # entitlement checks, and discover-tools all filter on status='approved'.
    # The §A human review (admin approve, reviewed_by=sub["reviewed_by"]) is
    # this lifecycle's equivalent of that gate, so provide-url is where the
    # submission flow must eventually set status='approved' — otherwise a
    # submission that completes the whole documented §A/§B REST flow is
    # still invisible to every downstream system and can never become
    # tool-discoverable.
    #
    # H-01 fix (2026-07-11 audit): status='approved' is no longer set in
    # THIS write — it is the actual entitlement/credential-issuance gate, so
    # a server whose verification probes below fail must never have briefly
    # been invocable. It stays at its current pre-approval value here and is
    # only promoted in the success branch after run_verification_probes
    # returns without raising.
    async with AsyncSessionLocal() as session:
        await session.execute(text("""
            UPDATE server_registry
            SET upstream_url = :url,
                upstream_allowlist_entry = :allowlist_entry,
                submission_status = 'active',
                approved_at = now(),
                approved_by = :approved_by,
                updated_at = now()
            WHERE server_id = :sid
        """), {"url": upstream_url, "sid": server_id, "allowlist_entry": upstream_allowlist_entry,
               "approved_by": sub.get("reviewed_by") or owner})
        await session.commit()

    # R-10: provisioning is synchronous (the submitter is waiting on this response) —
    # run the SAME verify-phase probes (healthcheck -> quarantined discovery ->
    # invocation probe) the platform-managed /apply pipeline uses (CR-01 /
    # WP-B3 phase 5 "provide-url parity" — exactly one verification code
    # path, not two independently-maintained copies). Self-hosted has no
    # build/deploy step of its own, so this call straight into the shared
    # verify half after upstream_url is already set above.
    # FM: if the upstream is unreachable at this exact moment, the approval above
    # already committed — a probe failure here must not roll that back or
    # fail this request; tools_provisioned=0 is reported and the existing manual
    # discover-tools admin route remains the retry path.
    from app.services.deploy_verifier import VerificationFailedError, run_verification_probes

    tools_provisioned = 0
    tools_skipped: list[dict] = []
    verification_report: dict | None = None
    try:
        verification_report = await run_verification_probes(
            server_id, upstream_url, actor_client_id=sub.get("reviewed_by") or owner,
            require_approved=False,
        )
        tools_provisioned = verification_report.get("tools_discovered", 0)
        tools_skipped = verification_report.get("tools_skipped", [])
        # H-01 fix: only now — probes actually passed — promote status to
        # the real entitlement/credential-issuance gate value.
        async with AsyncSessionLocal() as approve_session:
            await approve_session.execute(text(
                "UPDATE server_registry SET status = 'approved', updated_at = now() WHERE server_id = :sid"
            ), {"sid": server_id})
            await approve_session.commit()
    except VerificationFailedError as exc:
        verification_report = exc.report
        logger.warning(
            "provide-url verification probes failed for server_id=%s (approval already committed): %s",
            server_id, exc,
        )
    except Exception as exc:
        logger.warning(
            "provide-url verification probes crashed for server_id=%s (approval already committed): %s",
            server_id, exc,
        )
        verification_report = {"healthcheck": False, "tools_discovered": 0, "tools_skipped": [],
                               "invocation_probe_ok": False, "contract_check": None, "error": str(exc)}

    if verification_report is not None:
        async with AsyncSessionLocal() as vr_session:
            await vr_session.execute(text(
                """
                UPDATE server_registry
                SET verification_report = CAST(:report AS jsonb),
                    contract_version = 'v0.1',
                    updated_at = now()
                WHERE server_id = :sid
                """
            ), {"report": json.dumps(verification_report), "sid": server_id})
            await vr_session.commit()

    next_msg = (
        f"{tools_provisioned} tool(s) discovered and registered quarantined; "
        "an admin must review and release the quarantine before they're invocable."
        if tools_provisioned
        else "No tools discovered yet — check the upstream server and retry via the admin discover-tools action."
    )
    if tools_skipped:
        next_msg += f" {len(tools_skipped)} tool(s) were skipped — see 'tools_skipped' for why."

    return JSONResponse({
        "server_id": server_id,
        "submission_status": "active",
        "tools_provisioned": tools_provisioned,
        "tools_skipped": tools_skipped,
        "quarantined": True,
        "next": next_msg,
    })


# ---------------------------------------------------------------------------
# POST /apply, GET /verification-report — CR-01 (WP-B3 phase 5): the
# platform-managed build->deploy->verify entry point, for submitters who do
# NOT want to self-host (the provide-url path above remains unchanged and is
# the only route for self-hosted submitters — they never call /apply).
# ---------------------------------------------------------------------------
_APPLY_ELIGIBLE_STATUSES = ("scaffold_ready", "approved_pending_url")


@router.post("/api/v1/submissions/{server_id}/apply")
async def apply_submission(server_id: str, request: Request) -> JSONResponse:
    """
    Kick off the platform-managed build->deploy->verify pipeline for a
    submission that has NOT been self-hosted. Only valid from
    'scaffold_ready' or 'approved_pending_url' — the two states a
    self-hosted submitter would otherwise call provide-url from instead.
    Enqueues a build_requested job (claimed by build_worker, WP-B3 phase 2)
    reusing the existing scan_jobs queue (no new job table), pinning
    scan_jobs.expected_digest to this server's already-scanned+approved
    commit (server_registry.scan_commit) — the TOCTOU guard build_engine.py
    refuses to build past (PRD-8 sec 2).
    """
    owner = _effective_owner(request)
    sub = await _get_submission(server_id, owner_sub=owner)

    if sub["submission_status"] not in _APPLY_ELIGIBLE_STATUSES:
        raise HTTPException(status_code=409, detail=(
            f"submission_status is {sub['submission_status']!r}; /apply is only valid from "
            f"{_APPLY_ELIGIBLE_STATUSES!r} — a self-hosted submission should call provide-url instead"
        ))

    github_url = sub.get("github_repo_url")
    if not github_url:
        raise HTTPException(status_code=422, detail=(
            "submission has no github_repo_url — the platform-managed build pipeline "
            "requires a repository to build; a no-code submission cannot use /apply"
        ))

    expected_digest = sub.get("scan_commit")
    if not expected_digest:
        raise HTTPException(status_code=422, detail=(
            "submission has no recorded scan_commit yet — a scan must complete before "
            "/apply can pin a build to a specific approved commit"
        ))

    job_id = await scan_queue.enqueue_scan(server_id, github_url, job_type="build_requested")

    async with AsyncSessionLocal() as session:
        await session.execute(text(
            """
            UPDATE scan_jobs SET expected_digest = :digest WHERE job_id = :job_id
            """
        ), {"digest": expected_digest, "job_id": job_id})
        await session.execute(text(
            """
            UPDATE server_registry
            SET deployment_status = 'build_requested', updated_at = now()
            WHERE server_id = :sid
            """
        ), {"sid": server_id})
        await session.commit()

    logger.info("apply_submission enqueued build_requested job_id=%s server_id=%s", job_id, server_id)
    return JSONResponse({
        "server_id": server_id,
        "job_id": job_id,
        "deployment_status": "build_requested",
        "next": "Poll GET /api/v1/submissions/{server_id}/verification-report for pipeline progress.",
    })


@router.get("/api/v1/submissions/{server_id}/verification-report")
async def get_verification_report(server_id: str, request: Request) -> JSONResponse:
    """Plain read of server_registry.verification_report — 404 if the verify
    phase has never run for this server (still building/deploying, or a
    self-hosted submission that hasn't called provide-url yet)."""
    owner = _effective_owner(request)
    sub = await _get_submission(server_id, owner_sub=owner)
    report = sub.get("verification_report")
    if report is None:
        raise HTTPException(status_code=404, detail=(
            "no verification_report recorded yet for this server "
            f"(deployment_status={sub.get('deployment_status')!r})"
        ))
    return JSONResponse({
        "server_id": server_id,
        "deployment_status": sub.get("deployment_status"),
        "verification_report": report,
    })


# ── Agent-native self-service endpoints ───────────────────────────────────────
#
# These are designed to be called by an AI agent (Claude, GPT-4, etc.) that
# wants to help a user implement and submit an MCP server conversationally,
# without touching the portal UI.
#
# Typical agentic flow:
#   1. GET /api/v1/design-assist?mode=<mode>  → get questions to ask the user
#   2. Agent asks user the questions, collects answers
#   3. Agent creates a draft: POST /api/v1/submissions
#   4. Agent patches with the collected data: PATCH /api/v1/submissions/{id}
#   5. Agent submits: POST /api/v1/submissions/{id}/submit
#   6. GET /api/v1/submissions/{id} → poll for scan + review status


@router.get("/api/v1/design-assist/scaffold")
async def design_assist_scaffold(request: Request, mode: str = "none") -> JSONResponse:
    """Return scaffold file contents as JSON (for MCP tool consumption)."""
    _client_id(request)
    from app.services.scaffold_generator import generate_scaffold
    # L1 fix: coerce unknown mode values before reflection in the response.
    safe_mode = mode if mode in _VALID_MODES else "none"
    from app.core.config import get_settings as _get_scaffold_settings
    _issuer = _get_scaffold_settings().OIDC_ISSUER_URL
    files = generate_scaffold(
        "my-mcp-server", safe_mode, issuer=_issuer,
        jwks_uri=f"{_issuer.rstrip('/')}/protocol/openid-connect/certs" if _issuer else "",
    )
    return JSONResponse({"injection_mode": safe_mode, "files": files})


@router.get("/api/v1/design-assist")
async def design_assist(request: Request, mode: Optional[str] = None) -> JSONResponse:
    """
    Returns a structured set of questions an AI agent should ask a user before
    implementing an MCP server.  mode=<injection_mode> to get mode-specific
    questions; omit to get the auth-mode decision tree first.
    """
    _client_id(request)  # must be authenticated

    if mode is None:
        # Return the auth-mode decision tree so the agent can guide the user
        return JSONResponse({
            "stage": "auth_mode_selection",
            "instruction": (
                "Ask the user these questions in order to determine the right "
                "authentication mode for their MCP server. Stop at the first "
                "answer that points to a specific mode."
            ),
            "decision_tree": [
                {
                    "question": "Does your server call any upstream system that requires authentication?",
                    "options": {
                        "yes": {"next_question": "upstream_idp"},
                        "no":  {"recommended_mode": "none",
                                "reason": "No credential injection needed."},
                    },
                },
                {
                    "id": "upstream_idp",
                    "question": "Is the upstream system protected by the same Keycloak instance this platform uses?",
                    "options": {
                        "yes": {"recommended_mode": "kc_token_exchange",
                                "reason": "Token exchange — no secret stored. Full per-user attribution."},
                        "no":  {"next_question": "credential_type"},
                    },
                },
                {
                    "id": "credential_type",
                    "question": "What type of credential does the upstream system accept?",
                    "options": {
                        "microsoft_entra": {"next_question": "entra_delegation"},
                        "api_key_or_static_bearer": {"next_question": "shared_or_per_user"},
                        "oauth_different_idp": {"next_question": "oauth_scope"},
                    },
                },
                {
                    "id": "entra_delegation",
                    "question": "Is this machine-to-machine (app identity) or per-user (delegated)?",
                    "options": {
                        "machine": {"recommended_mode": "entra_client_credentials",
                                    "reason": "Entra app identity. Attribution at gateway only."},
                        "per_user": {"recommended_mode": "entra_user_token",
                                     "reason": "Entra delegated token. Full per-user attribution."},
                    },
                },
                {
                    "id": "shared_or_per_user",
                    "question": "Is one credential shared across all callers, or does each user have their own?",
                    "options": {
                        "shared":   {"recommended_mode": "service",
                                     "reason": "Shared service account. Attribution at gateway only."},
                        "per_user": {"recommended_mode": "user",
                                     "reason": "Per-user stored token. Full per-user attribution."},
                    },
                },
                {
                    "id": "oauth_scope",
                    "question": "Is one token shared across all callers, or per-user?",
                    "options": {
                        "shared":   {"recommended_mode": "service_account"},
                        # WP-A5: recommend the canonical name, not the deprecated alias.
                        "per_user": {"recommended_mode": "kc_token_exchange"},
                    },
                },
            ],
            "all_modes": list(_VALID_MODES),
        })

    # Mode-specific design questions (admin-overridable via prompt_store)
    prompts = await prompt_store.prompts_for_mode(mode)
    return JSONResponse({
        "stage": "design_questions",
        "injection_mode": mode,
        "instruction": (
            f"The user has chosen '{mode}' auth mode. Ask them the following questions "
            "to help design their MCP server. You may ask them all at once or one by one. "
            "Collect the answers — they will be needed to implement the server correctly."
        ),
        "questions": prompts,
        "next_steps": [
            "Once you have the answers, create a draft: POST /api/v1/submissions",
            "Then patch it with the design data: PATCH /api/v1/submissions/{id}",
            "Then trigger scan+review: POST /api/v1/submissions/{id}/submit",
            "Poll for status: GET /api/v1/submissions/{id}",
        ],
        "scaffold_available": True,
        "scaffold_note": (
            "A starter server.py, requirements.txt, Dockerfile, and README are available "
            "at GET /api/v1/submissions/{id}/scaffold after creating a draft."
        ),
    })
