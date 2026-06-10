"""
Integration Test — db_migrate.sh idempotent migration runner

Tests the scripts/db_migrate.sh script against a live PostgreSQL container.

Requirements:
  - podman-compose up (postgres service running, container name: mcp-db)
  - Accessible from host at postgresql://mcp_app:devpassword@localhost:5432/mcp_security
  - scripts/db_migrate.sh present at project root

Invariants covered:
  - All V0xx migrations land in schema_migrations on a fresh-ish run
  - Re-running the script is a no-op (idempotent)
  - A failing migration causes exit 1; subsequent migrations are NOT recorded

Run:
  pytest proxy/tests/integration/test_db_migrate.py -m integration -v
"""
from __future__ import annotations

import asyncio
import os
import subprocess
import tempfile
from pathlib import Path
from typing import AsyncIterator

import asyncpg
import pytest
import pytest_asyncio

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DB_DSN = os.environ.get(
    "TEST_DB_DSN",
    "postgresql://mcp_app:devpassword@localhost:5432/mcp_security",
)

# Project root — scripts/db_migrate.sh lives here
PROJECT_ROOT = Path(__file__).parents[3]
MIGRATIONS_DIR = PROJECT_ROOT / "infra" / "db" / "migrations"
SCRIPT_PATH = PROJECT_ROOT / "scripts" / "db_migrate.sh"

# Env vars forwarded to the script so it can call podman-compose exec
SCRIPT_ENV: dict[str, str] = {
    **os.environ,
    "COMPOSE": os.environ.get("COMPOSE", "podman-compose"),
    "DB_CONTAINER": os.environ.get("DB_CONTAINER", "mcp-db"),
    "DB_USER": os.environ.get("DB_USER", "mcp_app"),
    "DB_NAME": os.environ.get("DB_NAME", "mcp_security"),
    "MIGRATIONS_DIR": str(MIGRATIONS_DIR),
    "MIGRATIONS_GUEST": "/docker-entrypoint-initdb.d",
}


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def db_conn() -> AsyncIterator[asyncpg.Connection]:
    """Live asyncpg connection — only valid when postgres is running."""
    conn = await asyncpg.connect(DB_DSN)
    try:
        yield conn
    finally:
        await conn.close()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _run_script(env_overrides: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    """Invoke scripts/db_migrate.sh and return the completed process."""
    env = {**SCRIPT_ENV, **(env_overrides or {})}
    return subprocess.run(
        ["bash", str(SCRIPT_PATH)],
        capture_output=True,
        text=True,
        cwd=str(PROJECT_ROOT),
        env=env,
    )


async def _applied_versions(conn: asyncpg.Connection) -> set[str]:
    """Return the set of versions recorded in schema_migrations."""
    rows = await conn.fetch("SELECT version FROM schema_migrations;")
    return {row["version"] for row in rows}


async def _expected_versions() -> set[str]:
    """Return version tokens for every V*.sql file present on disk."""
    versions = set()
    for path in sorted(MIGRATIONS_DIR.glob("V*.sql")):
        version = path.name.split("__")[0]
        versions.add(version)
    return versions


# ---------------------------------------------------------------------------
# Test 1: Fresh run — all migrations recorded
# ---------------------------------------------------------------------------


@pytest.mark.integration
@pytest.mark.asyncio
async def test_all_migrations_applied_on_fresh_run(db_conn: asyncpg.Connection) -> None:
    """
    Run db_migrate.sh against the live database.
    After completion, every V*.sql file on disk must have an entry in
    schema_migrations (even if the table already existed from docker-entrypoint-initdb.d).

    This covers the core correctness invariant: all 24+ migrations are tracked,
    not just V001–V003.
    """
    result = _run_script()

    assert result.returncode == 0, (
        f"db_migrate.sh exited {result.returncode}.\n"
        f"STDOUT:\n{result.stdout}\n"
        f"STDERR:\n{result.stderr}"
    )

    applied = await _applied_versions(db_conn)
    expected = await _expected_versions()

    missing = expected - applied
    assert not missing, (
        f"The following migrations were NOT recorded in schema_migrations after a full run: "
        f"{sorted(missing)}\n"
        f"Script output:\n{result.stdout}"
    )


# ---------------------------------------------------------------------------
# Test 2: Idempotency — re-run is a no-op
# ---------------------------------------------------------------------------


@pytest.mark.integration
@pytest.mark.asyncio
async def test_rerun_is_idempotent(db_conn: asyncpg.Connection) -> None:
    """
    Running db_migrate.sh a second time must:
      - Exit 0
      - Produce no changes to schema_migrations (all versions already present)
      - Report every migration as SKIP in stdout
    """
    # First run to ensure everything is applied
    first = _run_script()
    assert first.returncode == 0, (
        f"First run failed (returncode={first.returncode}).\n"
        f"STDOUT:\n{first.stdout}\nSTDERR:\n{first.stderr}"
    )

    versions_before = await _applied_versions(db_conn)
    timestamps_before = await db_conn.fetch(
        "SELECT version, applied_at FROM schema_migrations ORDER BY version;"
    )

    # Second run — must be a no-op
    second = _run_script()
    assert second.returncode == 0, (
        f"Second (idempotent) run failed (returncode={second.returncode}).\n"
        f"STDOUT:\n{second.stdout}\nSTDERR:\n{second.stderr}"
    )

    versions_after = await _applied_versions(db_conn)
    timestamps_after = await db_conn.fetch(
        "SELECT version, applied_at FROM schema_migrations ORDER BY version;"
    )

    assert versions_before == versions_after, (
        "schema_migrations changed between run 1 and run 2 — not idempotent.\n"
        f"Before: {sorted(versions_before)}\nAfter: {sorted(versions_after)}"
    )

    # applied_at timestamps must be unchanged (rows not re-inserted)
    assert list(timestamps_before) == list(timestamps_after), (
        "applied_at timestamps changed on second run — migrations were re-applied."
    )

    # All lines should show SKIP (no APPLY lines)
    assert "APPLY" not in second.stdout, (
        f"Second run applied a migration that should have been skipped.\n"
        f"STDOUT:\n{second.stdout}"
    )


# ---------------------------------------------------------------------------
# Test 3: Failure stops execution; subsequent versions not recorded
# ---------------------------------------------------------------------------


@pytest.mark.integration
@pytest.mark.asyncio
async def test_failing_migration_stops_execution(db_conn: asyncpg.Connection) -> None:
    """
    Inject a syntactically invalid migration into a temporary migrations directory
    that contains two valid sentinel migrations and the bad one in between.
    The script must:
      - Exit 1
      - Record the versions applied BEFORE the failure
      - NOT record the failing version or any version after it

    Uses a temp directory with synthetic migration files to avoid touching the
    real infra/db/migrations/ files.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)

        # V900: valid — creates a harmless temp table
        (tmp_path / "V900__sentinel_before.sql").write_text(
            "CREATE TABLE IF NOT EXISTS _migrate_test_sentinel_900 (id INT);\n"
        )

        # V901: intentionally broken SQL
        (tmp_path / "V901__bad_migration.sql").write_text(
            "THIS IS NOT VALID SQL AND WILL FAIL;\n"
        )

        # V902: valid — should NOT be applied because V901 failed
        (tmp_path / "V902__sentinel_after.sql").write_text(
            "CREATE TABLE IF NOT EXISTS _migrate_test_sentinel_902 (id INT);\n"
        )

        result = _run_script(env_overrides={"MIGRATIONS_DIR": str(tmp_path)})

        # Script must exit non-zero
        assert result.returncode != 0, (
            f"Expected non-zero exit from a failing migration, got 0.\n"
            f"STDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
        )

        applied = await _applied_versions(db_conn)

        # V900 must be recorded (it ran before the failure)
        assert "V900" in applied, (
            f"V900 (pre-failure migration) should have been recorded. "
            f"Applied: {sorted(applied)}"
        )

        # V901 must NOT be recorded (it failed)
        assert "V901" not in applied, (
            f"V901 (failing migration) should NOT be recorded. Applied: {sorted(applied)}"
        )

        # V902 must NOT be recorded (execution stopped at V901)
        assert "V902" not in applied, (
            f"V902 (post-failure migration) should NOT be recorded. Applied: {sorted(applied)}"
        )

        # Cleanup: drop the sentinel table and remove the test schema_migrations entries
        await db_conn.execute(
            "DROP TABLE IF EXISTS _migrate_test_sentinel_900; "
            "DROP TABLE IF EXISTS _migrate_test_sentinel_902; "
            "DELETE FROM schema_migrations WHERE version IN ('V900', 'V901', 'V902');"
        )
