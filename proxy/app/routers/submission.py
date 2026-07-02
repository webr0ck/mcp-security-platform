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
import re
import uuid
import zipfile
from typing import Any, Optional

from fastapi import APIRouter, BackgroundTasks, HTTPException, Request
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, HttpUrl, field_validator
from sqlalchemy import text

from app.core.database import AsyncSessionLocal
from app.services.scaffold_generator import generate_prompts, generate_scaffold
from app.services.ssrf import SSRFError, validate_server_url
from app.services.submission_scanner import GITHUB_CLONE_ACCOUNT, scan_submission

# Same regex as submission_scanner — enforced at API boundary before any storage
_GITHUB_URL_RE = re.compile(
    r'^https://github\.com/[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*(\.git)?/?$'
)

logger = logging.getLogger(__name__)
router = APIRouter(tags=["Submissions"])

_VALID_MODES = {
    "none", "service", "user", "service_account", "oauth_user_token",
    "entra_client_credentials", "entra_user_token", "kc_token_exchange", "passthrough",
}
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


def _require_admin(request: Request) -> None:
    roles = list(getattr(request.state, "client_roles", []) or [])
    if not any(r in {"admin", "platform_admin"} for r in roles):
        raise HTTPException(status_code=403, detail="admin role required")


def _require_reviewer(request: Request) -> None:
    """M2 fix: read-only review queue accessible to security_auditor + auditor, not just admin."""
    roles = list(getattr(request.state, "client_roles", []) or [])
    if not any(r in {"admin", "platform_admin", "security_auditor", "auditor"} for r in roles):
        raise HTTPException(status_code=403, detail="reviewer role required")


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
    if v is None or v == "":
        return None
    if not _GITHUB_URL_RE.match(v):
        raise ValueError("github_repo_url must be https://github.com/<owner>/<repo>")
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


# ── Self-service endpoints ────────────────────────────────────────────────────

@router.post("/api/v1/submissions", status_code=201)
async def create_draft(body: DraftCreate, request: Request) -> JSONResponse:
    """Create a draft submission (wizard step 1)."""
    owner = _client_id(request)
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
                 github_repo_url, submission_status, scan_status)
            VALUES
                (:sid, :name, '', 'pending', :owner, 'none',
                 :repo_url, 'draft', 'pending')
        """), {
            "sid": sid,
            "name": body.name,
            "owner": owner,
            "repo_url": body.github_repo_url,
        })
        await session.commit()
    return JSONResponse({"server_id": sid, "submission_status": "draft"}, status_code=201)


@router.patch("/api/v1/submissions/{server_id}")
async def update_draft(server_id: str, body: DraftUpdate, request: Request) -> JSONResponse:
    """Update wizard data (steps 2-3). Only allowed in draft or changes_requested state."""
    owner = _client_id(request)
    sub = await _get_submission(server_id, owner_sub=owner)
    if sub["submission_status"] not in ("draft", "changes_requested"):
        raise HTTPException(status_code=409, detail="submission is not in an editable state")

    updates: dict[str, Any] = {"updated_at": "now()"}
    fields: list[str] = []

    def _set(col: str, val: Any) -> None:
        if val is not None:
            fields.append(f"{col} = :{col}")
            updates[col] = val

    _set("github_repo_url", body.github_repo_url)
    _set("injection_mode", body.injection_mode)
    _set("upstream_idp_type", body.upstream_idp_type)
    _set("mode_override_reason", body.mode_override_reason)
    _set("has_write_ops", body.has_write_ops)

    if body.upstream_idp_config is not None:
        fields.append("upstream_idp_config = :idp_config::jsonb")
        updates["idp_config"] = json.dumps(body.upstream_idp_config)

    if body.data_categories is not None:
        fields.append("data_categories = :cats")
        updates["cats"] = body.data_categories

    if body.description is not None:
        fields.append("service_name = :svc_name")
        updates["svc_name"] = body.description

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
    owner = _client_id(request)

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
                    ELSE scan_status
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
        background_tasks.add_task(scan_submission, server_id, github_url)

    return JSONResponse({"server_id": server_id, "submission_status": new_status})


@router.get("/api/v1/submissions")
async def list_submissions(request: Request) -> JSONResponse:
    """List the caller's own submissions."""
    owner = _client_id(request)
    async with AsyncSessionLocal() as session:
        rows = (await session.execute(text("""
            SELECT server_id, name, submission_status, scan_status,
                   injection_mode, data_categories, github_repo_url, updated_at
            FROM server_registry
            WHERE owner_sub = :owner AND deleted_at IS NULL
            ORDER BY updated_at DESC
        """), {"owner": owner})).fetchall()
    return JSONResponse({"submissions": [_json_safe(dict(r._mapping)) for r in rows]})


@router.get("/api/v1/submissions/{server_id}")
async def get_submission(server_id: str, request: Request) -> JSONResponse:
    """Get submission status and scan report."""
    owner = _client_id(request)
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
        "review_notes": safe.get("review_notes"),
        "github_clone_account": GITHUB_CLONE_ACCOUNT,
    })


@router.get("/api/v1/submissions/{server_id}/prompts")
async def get_design_prompts(server_id: str, request: Request) -> JSONResponse:
    """Return design prompts for the no-code path — questions to answer before writing the server."""
    owner = _client_id(request)
    sub = await _get_submission(server_id, owner_sub=owner)
    mode = sub.get("injection_mode") or "none"
    return JSONResponse({"server_id": server_id, "injection_mode": mode, "prompts": generate_prompts(mode)})


@router.get("/api/v1/submissions/{server_id}/scaffold")
async def download_scaffold(server_id: str, request: Request) -> StreamingResponse:
    """Download a scaffold zip for the no-code path."""
    owner = _client_id(request)
    sub = await _get_submission(server_id, owner_sub=owner)
    mode = sub.get("injection_mode") or "none"
    name = sub["name"]
    files = generate_scaffold(name, mode)

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
                   reviewed_by, reviewed_at, created_at, updated_at
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


@router.post("/api/v1/admin/submissions/{server_id}/approve")
async def approve_submission(server_id: str, body: ReviewAction, request: Request) -> JSONResponse:
    """Approve submission — moves to approved_pending_url state."""
    _require_admin(request)
    reviewer = _client_id(request)
    sub = await _get_submission(server_id)
    if sub["submission_status"] != "awaiting_review":
        raise HTTPException(status_code=409, detail="submission is not awaiting review")
    # L2 fix: block approving a scan-blocked submission (e.g. if state was set externally).
    if sub.get("scan_status") == "blocked":
        raise HTTPException(status_code=409, detail="cannot approve a scan-blocked submission")
    async with AsyncSessionLocal() as session:
        await session.execute(text("""
            UPDATE server_registry
            SET submission_status = 'approved_pending_url',
                review_notes = :notes,
                reviewed_by = :reviewer,
                reviewed_at = now(),
                updated_at = now()
            WHERE server_id = :sid
        """), {"notes": body.notes, "reviewer": reviewer, "sid": server_id})
        await session.commit()
    return JSONResponse({"server_id": server_id, "submission_status": "approved_pending_url"})


@router.post("/api/v1/admin/submissions/{server_id}/reject")
async def reject_submission(server_id: str, body: ReviewAction, request: Request) -> JSONResponse:
    """Reject a submission permanently."""
    _require_admin(request)
    reviewer = _client_id(request)
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
    return JSONResponse({"server_id": server_id, "submission_status": "rejected"})


@router.post("/api/v1/admin/submissions/{server_id}/request-changes")
async def request_changes(server_id: str, body: ReviewAction, request: Request) -> JSONResponse:
    """Return a submission to the submitter with change notes."""
    _require_admin(request)
    reviewer = _client_id(request)
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
    return JSONResponse({"server_id": server_id, "submission_status": "changes_requested"})


@router.post("/api/v1/submissions/{server_id}/provide-url")
async def provide_running_url(server_id: str, request: Request) -> JSONResponse:
    """Submitter provides the running server URL after approval."""
    owner = _client_id(request)
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
    try:
        validate_server_url(upstream_url)
    except SSRFError as exc:
        raise HTTPException(status_code=422, detail=f"upstream_url rejected: {exc}") from exc

    async with AsyncSessionLocal() as session:
        await session.execute(text("""
            UPDATE server_registry
            SET upstream_url = :url,
                submission_status = 'active',
                status = 'pending',
                updated_at = now()
            WHERE server_id = :sid
        """), {"url": upstream_url, "sid": server_id})
        await session.commit()
    return JSONResponse({"server_id": server_id, "submission_status": "active",
                         "next": "Tool discovery will run shortly."})


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
    files = generate_scaffold("my-mcp-server", safe_mode)
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
                        "per_user": {"recommended_mode": "oauth_user_token"},
                    },
                },
            ],
            "all_modes": list(_VALID_MODES),
        })

    # Mode-specific design questions
    prompts = generate_prompts(mode)
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
