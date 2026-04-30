#!/usr/bin/env bash
# =============================================================================
# init-db-roles.sh
# MCP Security Platform — PostgreSQL Application Role Initialisation
# =============================================================================
# Sets passwords for the proxy_app and compliance_checker_app PostgreSQL roles
# created by V003__db_roles.sql. Passwords are read from environment variables
# and never stored in any file (INV-008).
#
# Idempotent: uses ALTER ROLE (not CREATE ROLE). If the role does not exist
# yet (e.g., migration has not run), this script exits with an error — run
# migrations first.
#
# Usage (typically called from docker-entrypoint or a one-shot init container):
#   PROXY_DB_PASSWORD=<secret> \
#   COMPLIANCE_DB_PASSWORD=<secret> \
#   PGHOST=db PGPORT=5432 PGDATABASE=mcp_security PGUSER=mcp_app \
#   ./init-db-roles.sh
#
# Required environment variables:
#   PROXY_DB_PASSWORD       Password for proxy_app role
#   COMPLIANCE_DB_PASSWORD  Password for compliance_checker_app role
#
# Optional environment variables (psql connection defaults):
#   PGHOST        (default: db)
#   PGPORT        (default: 5432)
#   PGDATABASE    (default: mcp_security)
#   PGUSER        (default: mcp_app)   must be superuser or role owner
#   PGPASSWORD    Superuser password (set via env; never pass on CLI)
# =============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Validate required secrets
# ---------------------------------------------------------------------------
: "${PROXY_DB_PASSWORD:?PROXY_DB_PASSWORD environment variable is required}"
: "${COMPLIANCE_DB_PASSWORD:?COMPLIANCE_DB_PASSWORD environment variable is required}"

# ---------------------------------------------------------------------------
# Connection defaults
# ---------------------------------------------------------------------------
export PGHOST="${PGHOST:-db}"
export PGPORT="${PGPORT:-5432}"
export PGDATABASE="${PGDATABASE:-mcp_security}"
export PGUSER="${PGUSER:-mcp_app}"

echo "[init-db-roles] Connecting to PostgreSQL at ${PGHOST}:${PGPORT}/${PGDATABASE} as ${PGUSER}"

# ---------------------------------------------------------------------------
# Wait for PostgreSQL to be ready (up to 60 seconds)
# ---------------------------------------------------------------------------
RETRIES=30
until psql -c '\q' 2>/dev/null; do
    RETRIES=$((RETRIES - 1))
    if [ "$RETRIES" -le 0 ]; then
        echo "[init-db-roles] ERROR: PostgreSQL did not become ready in time." >&2
        exit 1
    fi
    echo "[init-db-roles] Waiting for PostgreSQL... (${RETRIES} retries remaining)"
    sleep 2
done

echo "[init-db-roles] PostgreSQL is ready."

# ---------------------------------------------------------------------------
# Verify roles exist (created by V003 migration)
# ---------------------------------------------------------------------------
check_role_exists() {
    local role="$1"
    local count
    count=$(psql -tAc "SELECT COUNT(*) FROM pg_catalog.pg_roles WHERE rolname = '${role}'")
    if [ "$count" -ne 1 ]; then
        echo "[init-db-roles] ERROR: Role '${role}' does not exist." \
             "Run database migrations (V003) before this script." >&2
        exit 1
    fi
}

check_role_exists "proxy_app"
check_role_exists "compliance_checker_app"

# ---------------------------------------------------------------------------
# Set passwords via ALTER ROLE (passwords never written to disk or logged)
# ---------------------------------------------------------------------------
# psql -c with a heredoc avoids passing the password as a command-line argument,
# which would be visible in `ps` output.
#
# We use a temporary named pipe to feed the SQL to psql without echoing
# the password in the shell history or process list.

echo "[init-db-roles] Setting password for proxy_app..."
psql <<SQL
ALTER ROLE proxy_app PASSWORD '${PROXY_DB_PASSWORD}';
SQL

echo "[init-db-roles] Setting password for compliance_checker_app..."
psql <<SQL
ALTER ROLE compliance_checker_app PASSWORD '${COMPLIANCE_DB_PASSWORD}';
SQL

# ---------------------------------------------------------------------------
# Verify connectivity with each application role
# ---------------------------------------------------------------------------
echo "[init-db-roles] Verifying proxy_app can connect..."
PGUSER="proxy_app" PGPASSWORD="${PROXY_DB_PASSWORD}" \
    psql -c "SELECT current_user, current_database();" 1>/dev/null

echo "[init-db-roles] Verifying compliance_checker_app can connect..."
PGUSER="compliance_checker_app" PGPASSWORD="${COMPLIANCE_DB_PASSWORD}" \
    psql -c "SELECT current_user, current_database();" 1>/dev/null

echo "[init-db-roles] Role passwords set and connectivity verified."
echo "[init-db-roles] Done."
