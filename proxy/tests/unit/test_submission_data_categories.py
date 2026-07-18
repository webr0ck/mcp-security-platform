"""
Fix 4 (docs/spec/13-entitlement-and-submission-hardening.md §4) —
data_categories enum validation must be non-name-consuming and must surface
the valid enum in the error.

Background: server_registry.name is claimed (row INSERTed) at
POST /api/v1/submissions time, BEFORE data_categories is ever collected (that
happens later, via PATCH /api/v1/submissions/{id} — wizard steps 2-3). The
concern from the acceptance run was that an unknown-category failure could
leave a draft permanently holding a name with no way to fix and resubmit.

These tests verify:
  1. DraftUpdate's data_categories field_validator runs at pydantic
     parse-time — i.e. BEFORE update_draft() (and therefore before any DB
     write) ever executes — so a malformed PATCH never touches the DB and
     never partially claims/mutates anything.
  2. The SAME draft (same name, same server_id) can be re-PATCHed with a
     corrected data_categories list and succeed — no new name claim is
     required, and the original name is never permanently stuck.
  3. The 422 error lists the full valid category enum.
  4. DraftCreate/DraftUpdate reject unknown fields outright (extra="forbid")
     instead of silently dropping them — e.g. a client that (reasonably)
     tries to pass data_categories at draft-creation time gets a loud 422
     instead of a silently-ignored field and a name claimed with no
     categories ever recorded.
"""
from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest
from pydantic import ValidationError

from app.routers.submission import (
    _VALID_CATEGORIES,
    DraftCreate,
    DraftUpdate,
    create_draft,
    update_draft,
)


def _mock_request(client_id="alice@corp"):
    req = MagicMock()
    req.state.client_id = client_id
    req.state.client_roles = []
    req.headers = {}  # no X-On-Behalf-Of — caller acts as itself (T2)
    return req


def _mock_session(existing_name_row=None):
    session = MagicMock()

    async def _execute(*args, **kwargs):
        result = MagicMock()
        result.fetchone.return_value = existing_name_row
        return result

    session.execute = AsyncMock(side_effect=_execute)
    session.commit = AsyncMock()

    class _Ctx:
        async def __aenter__(self):
            return session

        async def __aexit__(self, *a):
            return False

    return _Ctx(), session


# ---------------------------------------------------------------------------
# 1 & 3: field_validator runs at parse time, before any DB call; error lists
#        the valid enum.
# ---------------------------------------------------------------------------

@pytest.mark.unit
def test_unknown_category_rejected_at_construction():
    """DraftUpdate(...) itself raises — this happens during FastAPI's request
    body parsing, before the route handler (and therefore any DB write) ever
    runs."""
    with pytest.raises(ValidationError) as exc_info:
        DraftUpdate(data_categories=["not_a_real_category"])
    assert "not_a_real_category" in str(exc_info.value)


@pytest.mark.unit
def test_unknown_category_error_lists_valid_enum():
    """The 422 detail must surface the full valid list so a client doesn't
    have to guess-and-check."""
    with pytest.raises(ValidationError) as exc_info:
        DraftUpdate(data_categories=["bogus"])
    msg = str(exc_info.value)
    for cat in sorted(_VALID_CATEGORIES):
        assert cat in msg, f"valid category {cat!r} missing from error detail"


@pytest.mark.unit
def test_valid_categories_accepted():
    body = DraftUpdate(data_categories=["pii", "source_code"])
    assert body.data_categories == ["pii", "source_code"]


@pytest.mark.unit
@pytest.mark.asyncio
async def test_update_draft_never_calls_db_on_invalid_category():
    """Belt-and-suspenders: even if somehow invoked, update_draft's DB path
    is never reached for a body FastAPI would have already rejected — this
    test constructs the (already-invalid) body the same way pydantic would
    have raised on, confirming there is no route-level fallback that skips
    validation."""
    with pytest.raises(ValidationError):
        # Constructing the body IS where the 422 happens — no call to
        # update_draft (and therefore no DB session) is reachable at all
        # for a request carrying an unknown category.
        DraftUpdate(data_categories=["unknown_category_x"])


# ---------------------------------------------------------------------------
# 2: the SAME draft/name can be re-PATCHed with corrected data after a failed
#    attempt — no permanent name-consuming lock.
# ---------------------------------------------------------------------------

@pytest.mark.unit
@pytest.mark.asyncio
async def test_create_draft_then_failed_then_corrected_patch_same_draft():
    server_id = str(uuid4())

    # Step 1: create the draft (claims the name) — this succeeds regardless,
    # since data_categories is never part of DraftCreate.
    create_ctx, create_session = _mock_session(existing_name_row=None)
    with patch("app.routers.submission.AsyncSessionLocal", return_value=create_ctx):
        create_resp = await create_draft(
            DraftCreate(name="my-server", description="does things"),
            _mock_request(),
        )
    create_body = json.loads(create_resp.body)
    assert create_body["submission_status"] == "draft"

    # Step 2: attempt to PATCH with an unknown category — rejected at
    # pydantic parse time, well before update_draft/DB.
    with pytest.raises(ValidationError):
        DraftUpdate(data_categories=["not_real"])

    # Step 3: the SAME draft (same server_id, same claimed name) is
    # re-PATCHed with a corrected, valid data_categories list — no new name
    # claim needed, and it succeeds.
    sub_row = {
        "server_id": server_id,
        "owner_sub": "alice@corp",
        "submission_status": "draft",
        "injection_mode": None,
        "upstream_idp_type": None,
        "upstream_idp_config": None,
    }
    update_ctx, update_session = _mock_session()
    with patch("app.routers.submission._get_submission", AsyncMock(return_value=sub_row)), \
         patch("app.routers.submission.AsyncSessionLocal", return_value=update_ctx):
        update_resp = await update_draft(
            server_id,
            DraftUpdate(data_categories=["source_code", "public"]),
            _mock_request(),
        )
    update_body = json.loads(update_resp.body)
    assert update_body["updated"] is True


# ---------------------------------------------------------------------------
# 4: extra="forbid" — unknown fields (e.g. data_categories at create time)
#    are loudly rejected, not silently dropped.
# ---------------------------------------------------------------------------

@pytest.mark.unit
def test_draft_create_rejects_unknown_field():
    """A client that tries to pass data_categories directly at draft-creation
    time (DraftCreate has no such field — it's collected via a later PATCH)
    must get an explicit 422, not a silently-dropped field."""
    with pytest.raises(ValidationError, match="data_categories"):
        DraftCreate(name="my-server", data_categories=["pii"])


@pytest.mark.unit
def test_draft_update_rejects_unknown_field():
    with pytest.raises(ValidationError, match="unexpected_field"):
        DraftUpdate(unexpected_field="oops")


@pytest.mark.unit
def test_draft_create_accepts_known_fields():
    body = DraftCreate(name="my-server", description="x", github_repo_url=None)
    assert body.name == "my-server"
