"""
Integration test — scanner_worker_app DB role enforcement (CR-14 / WP-B1).

Verifies the execution/adjudication split is enforced at the DB-role level,
not just in application code: a connection authenticated AS the worker's own
role must be structurally unable to write an adjudication verdict
(server_registry.scan_status/block) or forge one via scan_raw_results —
even if the worker process were fully compromised by malicious repo content.

Run: pytest tests/integration/test_scanner_worker_db_role.py -m integration
Requires: docker/podman compose up (postgres reachable), V063 migration applied.
"""
from __future__ import annotations

import os
import uuid

import asyncpg
import pytest

from app.core.config import settings as _settings

ADMIN_DSN = os.environ.get("TEST_DB_DSN") or (
    f"postgresql://{_settings.DB_USER}:{_settings.DB_PASSWORD}"
    f"@{_settings.DB_HOST}:{_settings.DB_PORT}/{_settings.DB_NAME}"
)

WORKER_DSN = os.environ.get("TEST_SCANNER_WORKER_DB_DSN") or (
    f"postgresql://{os.environ.get('SCANNER_WORKER_DB_USER', 'scanner_worker_app')}:"
    f"{os.environ.get('SCANNER_WORKER_DB_PASSWORD', '')}"
    f"@{_settings.DB_HOST}:{_settings.DB_PORT}/{_settings.DB_NAME}"
)

pytestmark = pytest.mark.integration


@pytest.fixture
async def admin_conn():
    conn = await asyncpg.connect(ADMIN_DSN)
    try:
        yield conn
    finally:
        await conn.close()


@pytest.fixture
async def worker_conn():
    if not os.environ.get("SCANNER_WORKER_DB_PASSWORD") and not os.environ.get("TEST_SCANNER_WORKER_DB_DSN"):
        pytest.skip("SCANNER_WORKER_DB_PASSWORD not set in this environment")
    conn = await asyncpg.connect(WORKER_DSN)
    try:
        yield conn
    finally:
        await conn.close()


@pytest.fixture
async def test_server_and_job(admin_conn):
    """Create a throwaway server_registry row + queued scan_jobs row."""
    server_id = str(uuid.uuid4())
    await admin_conn.execute(
        """
        INSERT INTO server_registry
            (server_id, name, upstream_url, owner_sub, github_repo_url, submission_status, scan_status)
        VALUES ($1, 'test-cr14-role-check', 'http://example.invalid', 'test-owner',
                'https://github.com/example/example', 'scan_pending', 'pending')
        """,
        server_id,
    )
    job_id = await admin_conn.fetchval(
        """
        INSERT INTO scan_jobs (server_id, github_url, job_type)
        VALUES ($1, 'https://github.com/example/example', 'submission_scan')
        RETURNING job_id
        """,
        server_id,
    )
    yield server_id, str(job_id)
    await admin_conn.execute("DELETE FROM scan_raw_results WHERE server_id = $1", server_id)
    await admin_conn.execute("DELETE FROM scan_jobs WHERE server_id = $1", server_id)
    await admin_conn.execute("DELETE FROM server_registry WHERE server_id = $1", server_id)


async def test_worker_cannot_write_scan_status_directly(worker_conn, test_server_and_job):
    """
    The core non-negotiable: a corrupted worker cannot forge a PASS by
    writing server_registry.scan_status/block directly — it must have no
    GRANT on server_registry at all.
    """
    server_id, _job_id = test_server_and_job
    with pytest.raises(asyncpg.InsufficientPrivilegeError):
        await worker_conn.execute(
            "UPDATE server_registry SET scan_status = 'passed' WHERE server_id = $1",
            server_id,
        )


async def test_worker_cannot_select_server_registry(worker_conn, test_server_and_job):
    """scanner_worker_app has no SELECT on server_registry either (V063)."""
    with pytest.raises(asyncpg.InsufficientPrivilegeError):
        await worker_conn.fetchval("SELECT count(*) FROM server_registry")


async def test_worker_can_insert_raw_result_but_not_select_it_back(worker_conn, test_server_and_job):
    """INSERT-only on scan_raw_results — no SELECT/UPDATE/DELETE even on its own row."""
    server_id, job_id = test_server_and_job
    await worker_conn.execute(
        """
        INSERT INTO scan_raw_results (job_id, server_id, raw_findings)
        VALUES ($1, $2, '[]'::jsonb)
        """,
        uuid_or_str(job_id), server_id,
    )
    with pytest.raises(asyncpg.InsufficientPrivilegeError):
        await worker_conn.fetchval("SELECT count(*) FROM scan_raw_results WHERE server_id = $1", server_id)


async def test_worker_cannot_alter_job_identity_columns(worker_conn, test_server_and_job):
    """
    scanner_worker_app may update ONLY its own claim/heartbeat/attempt
    columns on scan_jobs — never job identity (github_url here).
    """
    _server_id, job_id = test_server_and_job
    with pytest.raises(asyncpg.InsufficientPrivilegeError):
        await worker_conn.execute(
            "UPDATE scan_jobs SET github_url = 'https://github.com/attacker/evil' WHERE job_id = $1",
            uuid_or_str(job_id),
        )


async def test_worker_can_claim_and_heartbeat_its_own_job(worker_conn, test_server_and_job):
    """Sanity check: the narrow grant is not so narrow it breaks the real claim path."""
    _server_id, job_id = test_server_and_job
    await worker_conn.execute(
        """
        UPDATE scan_jobs
        SET status = 'running', claimed_by = 'test-worker', claimed_at = now(), heartbeat_at = now()
        WHERE job_id = $1
        """,
        uuid_or_str(job_id),
    )


def uuid_or_str(v):
    return uuid.UUID(v) if isinstance(v, str) else v
