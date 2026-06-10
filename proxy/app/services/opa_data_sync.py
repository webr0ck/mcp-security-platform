"""
MCP Security Platform — OPA Data Sync Service

Fetches grants from the database and pushes them to OPA's data API.
Runs a background 60s reconciliation loop to keep OPA grants in sync with DB.

Design:
  - Startup: fetch grants from DB, push to OPA immediately (fail-logged)
  - Mutation: before DB commit, call push_grants() (fail-closed, rolls back on error)
  - Reconcile: every 60s, fetch and push again (fail-logged, continues on error)
  - Idempotent: pushing the same grant dict multiple times is safe

OPA Data API:
  - PUT /v1/data/mcp/grants with JSON body: {"mcp": {"grants": {...}}}
  - Pairwise network only (opa-net between proxy and OPA)
  - Never exposed to the internet

Schema:
  role_assignments table must have:
    - principal_id (TEXT): "alice@corp", "agent-001", "kc_group:admins", etc.
    - principal_type (TEXT): "human", "agent", "kc_group"
    - allowed_tools (JSON array or TEXT[]): ["read", "write", "delete"]
    - allowed_tags (JSON array or TEXT[]): ["safe", "internal"]
    - max_risk_level (TEXT): "low", "medium", "high", "critical"

Output structure for OPA:
  {
    "mcp": {
      "grants": {
        "alice@corp": {
          "principal_type": "human",
          "allowed_tools": ["read", "write"],
          "allowed_tags": ["safe"],
          "max_risk_level": "high"
        },
        ...
      }
    }
  }
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any

import asyncpg

from app.services.policy import OPAClient, PolicyEngineError

logger = logging.getLogger(__name__)


def build_grants_data(grant_rows: list[dict[str, Any]]) -> dict[str, Any]:
    """
    Convert role_assignments rows to OPA data structure.

    Args:
        grant_rows: List of dicts from role_assignments query, each containing:
            - principal_id (str)
            - principal_type (str)
            - allowed_tools (list[str])
            - allowed_tags (list[str])
            - max_risk_level (str)

    Returns:
        OPA data structure: {"mcp": {"grants": {principal_id -> grant_obj}}}

    Raises:
        KeyError: if any row is missing required fields (fail-closed)
    """
    grants: dict[str, Any] = {}

    for row in grant_rows:
        principal_id = row["principal_id"]
        grants[principal_id] = {
            "principal_type": row["principal_type"],
            "allowed_tools": row["allowed_tools"],
            "allowed_tags": row["allowed_tags"],
            "max_risk_level": row["max_risk_level"],
        }

    return {"mcp": {"grants": grants}}


class OPADataSync:
    """
    Synchronizes grants from the database to OPA's data API.

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
        Fetch grants from the database and push to OPA.

        Executes a SELECT query against role_assignments, builds the OPA
        data structure, and calls opa_client.put_data().

        Raises:
            Exception: on DB query failure (fail-closed)
            PolicyEngineError: on OPA push failure (fail-closed)

        Called by:
          - Startup: in lifespan initialization
          - Mutation: before DB commit in grant/revoke transactions
          - Reconcile: periodically (60s loop)
        """
        try:
            # Fetch grants from role_assignments table
            # Query returns rows with: principal_id, principal_type, allowed_tools,
            # allowed_tags, max_risk_level
            query = """
            SELECT
                principal_id,
                principal_type,
                allowed_tools,
                allowed_tags,
                max_risk_level
            FROM role_assignments
            WHERE expires_at IS NULL OR expires_at > NOW()
            ORDER BY principal_id
            """
            grant_rows = await self.db_pool.fetch(query)

            # Build OPA data structure
            grants_data = build_grants_data([dict(row) for row in grant_rows])

            # Push to OPA
            await OPAClient.put_data(path="/mcp/grants", data=grants_data)

            logger.info(
                "OPA grants pushed successfully",
                extra={"grant_count": len(grant_rows)},
            )

        except Exception as exc:
            logger.error(
                "Failed to push grants to OPA — failing closed",
                extra={"error": str(exc), "error_type": type(exc).__name__},
            )
            raise

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
