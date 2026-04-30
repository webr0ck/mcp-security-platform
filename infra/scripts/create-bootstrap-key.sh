#!/usr/bin/env bash
# =============================================================================
# create-bootstrap-key.sh
# MCP Security Platform — Bootstrap Admin API Key Generator
# =============================================================================
# Generates a cryptographically random 32-byte API key, prints it to stdout
# ONCE, computes its SHA-256 hex digest, and updates the placeholder row in
# the api_keys table (seeded by V002__rbac_seed.sql) with the real hash.
#
# IMPORTANT: The raw API key is printed to stdout exactly once and never stored
# anywhere. Copy it to a secrets manager immediately. If lost, run this script
# again (it will overwrite the previous hash and invalidate the old key).
#
# This script is for FIRST-TIME SETUP only. Do not run it in normal operation.
# After the initial admin logs in, create per-user API keys via the API and
# revoke the bootstrap key.
#
# Usage:
#   PGHOST=db PGPORT=5432 PGDATABASE=mcp_security \
#   PGUSER=mcp_app PGPASSWORD=<superuser-password> \
#   ./create-bootstrap-key.sh
#
# Required tools: openssl, psql
# Required environment: PostgreSQL connection vars (PGHOST, PGPORT, etc.)
# =============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Validate tooling
# ---------------------------------------------------------------------------
command -v openssl >/dev/null 2>&1 || {
    echo "[bootstrap-key] ERROR: openssl is required but not installed." >&2
    exit 1
}
command -v psql >/dev/null 2>&1 || {
    echo "[bootstrap-key] ERROR: psql is required but not installed." >&2
    exit 1
}

# ---------------------------------------------------------------------------
# Connection defaults
# ---------------------------------------------------------------------------
export PGHOST="${PGHOST:-db}"
export PGPORT="${PGPORT:-5432}"
export PGDATABASE="${PGDATABASE:-mcp_security}"
export PGUSER="${PGUSER:-mcp_app}"

# ---------------------------------------------------------------------------
# Generate raw API key: 32 random bytes → base64url (no padding, URL-safe)
# Result is ~43 characters; we prefix with 'mcp_' for easy identification.
# ---------------------------------------------------------------------------
RAW_KEY="mcp_$(openssl rand -base64 32 | tr -d '=\n' | tr '+/' '-_')"

# ---------------------------------------------------------------------------
# Compute SHA-256 hex digest of the raw key (lowercase, no trailing newline)
# This is what gets stored in the database (never the raw key).
# ---------------------------------------------------------------------------
KEY_HASH=$(printf '%s' "${RAW_KEY}" | openssl dgst -sha256 -hex | awk '{print $2}')

# Sanity check: hash must be exactly 64 hex chars
if [ "${#KEY_HASH}" -ne 64 ]; then
    echo "[bootstrap-key] ERROR: SHA-256 hash length unexpected: ${#KEY_HASH}" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Update the placeholder row in api_keys
# Row was inserted by V002 with key_id = '00000000-0000-0000-0000-000000000001'
# and a placeholder hash of 64 zeroes.
# ---------------------------------------------------------------------------
UPDATED_ROWS=$(psql -tAc "
UPDATE api_keys
   SET key_hash   = '${KEY_HASH}',
       updated_at = NOW()
 WHERE key_id = '00000000-0000-0000-0000-000000000001'
   AND client_id = 'bootstrap';
SELECT ROW_COUNT();
")

# psql returns empty string for 0 rows; check via a count query instead
AFFECTED=$(psql -tAc "
SELECT COUNT(*) FROM api_keys
 WHERE key_id = '00000000-0000-0000-0000-000000000001'
   AND key_hash = '${KEY_HASH}';
")

if [ "${AFFECTED}" -ne 1 ]; then
    echo "[bootstrap-key] ERROR: Bootstrap row not found or hash not updated." \
         "Ensure V002 migration has been applied." >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Print the raw key to stdout — THIS IS THE ONLY TIME IT WILL EVER BE SHOWN
# ---------------------------------------------------------------------------
echo ""
echo "============================================================"
echo "  BOOTSTRAP ADMIN API KEY (copy to secrets manager NOW)"
echo "============================================================"
echo ""
echo "  ${RAW_KEY}"
echo ""
echo "  SHA-256: ${KEY_HASH}"
echo "  Stored in api_keys.key_hash for client_id='bootstrap'"
echo ""
echo "  Usage: Authorization: Bearer ${RAW_KEY}"
echo ""
echo "  IMPORTANT: This key has admin role and no expiry."
echo "  Revoke it after creating role-specific keys via the API."
echo "============================================================"
echo ""

echo "[bootstrap-key] Done. Raw key displayed above; hash stored in database."
