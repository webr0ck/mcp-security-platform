"""
MCP Security Platform — OPA Data Sync Service

Fetches grants from the client_grants table and pushes them to OPA's data API
at PUT /v1/data/mcp_grants (NOT owned by the signed bundle — see .manifest).
Runs a background 60s reconciliation loop to keep OPA grants in sync with DB.

Design (Task 4.4b — SELF-F6):
  - Startup: fetch grants from client_grants, push to OPA immediately (fail-logged)
  - Mutation: before DB commit, call push_grants() (fail-closed, rolls back on error)
  - Reconcile: every 60s, fetch and push again (fail-logged, continues on error)
  - Idempotent: pushing the same grant dict multiple times is safe

OPA Data API:
  - PUT /v1/data/mcp_grants with JSON body:
    {
      "alice@corp": {
        "allowed_tools": ["ping", "echo_args", ...],
        "allowed_tags": ["lab", "testing"],
        "max_risk_level": "medium"
      },
      ...
    }
  - Path "mcp_grants" is NOT owned by the signed bundle (see policies/rego/.manifest),
    so data-API writes succeed without bundle conflict (INV-012 preserved).
  - Pairwise network only (opa-net between proxy and OPA)

Schema:
  client_grants table (V034):
    - client_id      TEXT: "alice@corp", "agent-001", etc.
    - allowed_tools  JSONB: ["ping", "echo_args", ...]
    - allowed_tags   JSONB: ["lab", "testing"]
    - max_risk_level TEXT: "low" | "medium" | "high" | "critical"
    - granted_by     TEXT: identity of the admin who created this grant
    - created_at     TIMESTAMPTZ
    - updated_at     TIMESTAMPTZ
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any

import asyncpg

from app.services.policy import OPAClient, PolicyEngineError

logger = logging.getLogger(__name__)

# OPA data path for grants (NOT owned by the signed bundle — see .manifest)
# authz.rego reads data.mcp_grants[client_id] after Task 4.4b migration.
_OPA_GRANTS_PATH = "/mcp_grants"


def build_grants_data(grant_rows: list[dict[str, Any]]) -> dict[str, Any]:
    """
    Convert client_grants rows to OPA data structure.

    The structure pushed to OPA is a flat dict keyed by client_id:
      {
        "alice@corp": {
          "allowed_tools": [...],
          "allowed_tags": [...],
          "max_risk_level": "medium"
        },
        ...
      }

    This is pushed to PUT /v1/data/mcp_grants, making it readable in Rego as
    data.mcp_grants["alice@corp"].allowed_tools etc.

    Args:
        grant_rows: List of dicts from client_grants query, each containing:
            - client_id     (str)
            - allowed_tools (list[str])
            - allowed_tags  (list[str])
            - max_risk_level (str)

    Returns:
        Flat dict: {client_id -> {allowed_tools, allowed_tags, max_risk_level}}

    Raises:
        KeyError: if any row is missing required fields (fail-closed)
    """
    grants: dict[str, Any] = {}

    for row in grant_rows:
        client_id = row["client_id"]
        # asyncpg returns JSONB columns as raw JSON strings, not decoded Python objects.
        # Parse them here; if already a list (e.g. in tests), pass through as-is.
        def _as_list(v: Any) -> list:
            if isinstance(v, str):
                import json as _json
                return _json.loads(v)
            return list(v) if v is not None else []

        grants[client_id] = {
            "allowed_tools": _as_list(row["allowed_tools"]),
            "allowed_tags": _as_list(row["allowed_tags"]),
            "max_risk_level": row["max_risk_level"],
        }

    return grants


class OPADataSync:
    """
    Synchronizes grants from the client_grants table to OPA's data API.

    Task 4.4b: Grants are pushed to PUT /v1/data/mcp_grants — a path NOT owned
    by the signed bundle (see policies/rego/.manifest: roots=["mcp"]). This allows
    runtime grant updates without bundle re-sign + deploy (SELF-F6 fix).

    Provides:
      - push_grants(): fetch from DB, push to OPA (fail-closed)
      - start_reconcile_loop(): background 60s reconciliation task
      - stop_reconcile_loop(): cancel the background task
    """

    def __init__(self, db_pool: asyncpg.Pool, opa_client: OPAClient | None = None) -> None:
        """
        Initialize OPADataSync.

        Args:
            db_pool: asyncpg connection pool
            opa_client: OPA client instance (defaults to OPAClient if not provided)
        """
        self.db_pool = db_pool
        self.opa_client = opa_client or OPAClient()
        self._reconcile_task: asyncio.Task[None] | None = None

    async def push_grants(self) -> None:
        """
        Fetch grants from client_grants and push to OPA at /v1/data/mcp_grants.

        Executes a SELECT query against client_grants, builds the OPA data
        structure, and calls opa_client.put_data(_OPA_GRANTS_PATH, data).

        Raises:
            PolicyEngineError: on DB query failure or OPA push failure (fail-closed)

        Called by:
          - Startup: in lifespan initialization
          - Mutation: before DB commit in grant/revoke transactions
          - Reconcile: periodically (60s loop)
          - Admin endpoint: POST /api/v1/admin/sync-grants
        """
        try:
            # Fetch grants from client_grants table (V034)
            query = """
            SELECT
                client_id,
                allowed_tools,
                allowed_tags,
                max_risk_level
            FROM client_grants
            ORDER BY client_id
            """
            grant_rows = await self.db_pool.fetch(query)

            # Build flat OPA data structure keyed by client_id
            grants_data = build_grants_data([dict(row) for row in grant_rows])

            # Push to OPA via the injected client instance (supports mock injection in tests)
            # Path: /mcp_grants (not owned by bundle — see .manifest)
            await self.opa_client.put_data(path=_OPA_GRANTS_PATH, data=grants_data)

            logger.info(
                "OPA grants pushed successfully",
                extra={"grant_count": len(grant_rows), "opa_path": _OPA_GRANTS_PATH},
            )

        except PolicyEngineError:
            raise
        except Exception as exc:
            logger.error(
                "Failed to push grants to OPA — failing closed",
                extra={"error": str(exc), "error_type": type(exc).__name__},
            )
            raise PolicyEngineError(f"OPA grants push failed: {exc}") from exc

    async def start_reconcile_loop(self) -> None:
        """
        Start the background 60s reconciliation loop.

        The loop runs independently and logs errors without stopping on failure.
        It continues even if push_grants() fails (fail-logged).

        Safe to call multiple times (idempotent via _reconcile_task check).
        """
        if self._reconcile_task is not None:
            logger.warning("Reconcile loop already running — skipping duplicate start")
            return

        async def _reconcile_loop() -> None:
            """Background task: every 60s, push_grants()."""
            while True:
                try:
                    await asyncio.sleep(60)
                    await self.push_grants()
                except asyncio.CancelledError:
                    logger.info("OPA reconcile loop cancelled")
                    raise
                except Exception as exc:
                    logger.error(
                        "Reconcile loop: push_grants() failed — continuing",
                        extra={"error": str(exc)},
                    )
                    # Continue looping, don't re-raise

        self._reconcile_task = asyncio.create_task(_reconcile_loop())
        logger.info("OPA reconcile loop started (60s interval)")

    async def stop_reconcile_loop(self) -> None:
        """
        Stop the background reconciliation task.

        Idempotent: safe to call even if the task is not running.
        """
        if self._reconcile_task is None:
            return

        if not self._reconcile_task.done():
            self._reconcile_task.cancel()
            try:
                await self._reconcile_task
            except asyncio.CancelledError:
                pass

        self._reconcile_task = None
        logger.info("OPA reconcile loop stopped")


# Module-level singleton — initialized by app lifespan, injected for tests.
opa_data_sync_instance: OPADataSync | None = None
