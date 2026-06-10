#!/usr/bin/env bash
# =============================================================================
# db_migrate.sh — Idempotent, ordered database migration runner
# =============================================================================
# Applies all V*.sql migrations in version-natural sort order.
# Tracks applied migrations in schema_migrations(version TEXT PRIMARY KEY).
# Skips already-applied versions. Exits non-zero on the first failure.
#
# Transaction behaviour:
#   - Default: each migration runs inside a BEGIN/COMMIT block.
#   - Exception: migrations whose first line is exactly "-- no-txn" run in
#     autocommit mode. Required for ALTER TYPE ... ADD VALUE which PostgreSQL
#     forbids inside a transaction that also references the new label.
#
# Usage (called from Makefile via podman-compose exec):
#   bash scripts/db_migrate.sh
#
# Environment (forwarded by Makefile targets):
#   COMPOSE          — compose command (default: podman-compose)
#   DB_CONTAINER     — container name (default: mcp-db)
#   DB_USER          — PostgreSQL user (default: mcp_app)
#   DB_NAME          — PostgreSQL database (default: mcp_security)
#   MIGRATIONS_DIR   — path to migration files on HOST (default: infra/db/migrations)
#   MIGRATIONS_GUEST — path inside the container (default: /docker-entrypoint-initdb.d)
# =============================================================================

set -euo pipefail

COMPOSE="${COMPOSE:-podman-compose}"
DB_CONTAINER="${DB_CONTAINER:-mcp-db}"
DB_USER="${DB_USER:-mcp_app}"
DB_NAME="${DB_NAME:-mcp_security}"
MIGRATIONS_DIR="${MIGRATIONS_DIR:-infra/db/migrations}"
MIGRATIONS_GUEST="${MIGRATIONS_GUEST:-/docker-entrypoint-initdb.d}"

# ---------------------------------------------------------------------------
# Helper: run psql inside the container
# ---------------------------------------------------------------------------
psql_exec() {
    # -v ON_ERROR_STOP=1 makes psql exit non-zero on any SQL error.
    # -X suppresses ~/.psqlrc which could change output format.
    $COMPOSE exec -T "$DB_CONTAINER" \
        psql -U "$DB_USER" -d "$DB_NAME" -v ON_ERROR_STOP=1 -X "$@"
}

# ---------------------------------------------------------------------------
# Step 1: Ensure schema_migrations table exists (idempotent)
# ---------------------------------------------------------------------------
echo "[db_migrate] Ensuring schema_migrations table exists..."
psql_exec -c "
CREATE TABLE IF NOT EXISTS schema_migrations (
    version    TEXT PRIMARY KEY,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
"

# ---------------------------------------------------------------------------
# Step 2: Collect migration files in version-natural order
# ---------------------------------------------------------------------------
# sort -V performs version-natural sort so V10 > V9 (not lexicographic).
mapfile -t MIGRATION_FILES < <(
    ls "${MIGRATIONS_DIR}"/V*.sql 2>/dev/null | sort -V
)

if [[ ${#MIGRATION_FILES[@]} -eq 0 ]]; then
    echo "[db_migrate] No migration files found in ${MIGRATIONS_DIR}. Nothing to do."
    exit 0
fi

echo "[db_migrate] Found ${#MIGRATION_FILES[@]} migration file(s)."

APPLIED_COUNT=0
SKIPPED_COUNT=0

# ---------------------------------------------------------------------------
# Step 3: Apply each migration (idempotent skip if already recorded)
# ---------------------------------------------------------------------------
for host_path in "${MIGRATION_FILES[@]}"; do
    filename="$(basename "$host_path")"
    # Extract version token: everything up to (but not including) the first '__'
    # e.g. "V023__tool_server_fk.sql" → "V023"
    version="${filename%%__*}"

    # Guard: reject any version token that doesn't match ^V[0-9]+$ before it
    # can be interpolated into SQL. This prevents path-traversal or injection
    # via a malformed or unexpected filename in the migrations directory.
    if [[ ! "${version}" =~ ^V[0-9]+$ ]]; then
        echo "[db_migrate] ERROR: unexpected version token '${version}' in filename '${filename}' — aborting"
        exit 1
    fi

    guest_path="${MIGRATIONS_GUEST}/${filename}"

    # Check whether this version is already recorded
    already_applied=$(
        psql_exec -tAc \
            "SELECT COUNT(*) FROM schema_migrations WHERE version = '${version}';" \
        2>/dev/null
    )

    if [[ "${already_applied}" == "1" ]]; then
        echo "[db_migrate] SKIP  ${version} (already applied)"
        (( SKIPPED_COUNT++ )) || true
        continue
    fi

    # Detect no-txn marker: read first non-blank line of the migration file
    first_line=$(grep -m1 . "$host_path" || true)
    no_txn=0
    if [[ "${first_line}" == "-- no-txn" ]]; then
        no_txn=1
    fi

    echo "[db_migrate] APPLY ${version} (${filename})${no_txn:+ [no-txn]}"

    if [[ $no_txn -eq 1 ]]; then
        # Run in autocommit — no wrapping transaction.
        psql_exec -f "${guest_path}"
    else
        # Wrap in an explicit transaction so partial failures roll back cleanly.
        # We pipe a heredoc that wraps the -f execution via \i inside a transaction.
        psql_exec -c "BEGIN;" -f "${guest_path}" -c "COMMIT;"
    fi

    # Record the version only after a successful apply
    psql_exec -c \
        "INSERT INTO schema_migrations (version) VALUES ('${version}') ON CONFLICT DO NOTHING;"

    echo "[db_migrate] OK    ${version}"
    (( APPLIED_COUNT++ )) || true
done

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "[db_migrate] Done. Applied: ${APPLIED_COUNT}  Skipped (already up-to-date): ${SKIPPED_COUNT}"
