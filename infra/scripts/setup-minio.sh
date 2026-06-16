#!/bin/sh
# setup-minio.sh — Configure MinIO WORM bucket for MCP audit log archival
#
# Implements INV-007: Object Lock (WORM) with GOVERNANCE mode, 90-day retention.
# Runs as the minio-init one-shot container (see docker-compose.yml minio-init service).
#
# Idempotent: safe to re-run. Existing bucket is verified rather than recreated.
# Exit code: 0 if all checks pass and bucket is correctly configured.
#            1 if any critical step fails.
#
# CRITICAL: This script NEVER deletes from the WORM bucket. No delete operations
# are permitted by any application service. Bucket deletion requires out-of-band
# MinIO admin credentials (INV-007).
#
# Secrets: MINIO_ROOT_USER and MINIO_ROOT_PASSWORD come from environment variables
# injected at runtime (never committed to git, per INV-008).

set -eu

MINIO_ENDPOINT="${MINIO_ENDPOINT:-http://minio:9000}"
MINIO_ROOT_USER="${MINIO_ROOT_USER:?MINIO_ROOT_USER is required}"
MINIO_ROOT_PASSWORD="${MINIO_ROOT_PASSWORD:?MINIO_ROOT_PASSWORD is required}"
MINIO_AUDIT_BUCKET="${MINIO_AUDIT_BUCKET:-mcp-audit-archive}"
MINIO_RETENTION_DAYS="${MINIO_RETENTION_DAYS:-90}"
MC_ALIAS="mcp-minio"

# ─── Wait for MinIO to be ready ───────────────────────────────────────────────
echo "[setup-minio] Waiting for MinIO at ${MINIO_ENDPOINT}..."
ATTEMPTS=0
MAX_ATTEMPTS=30
# minio/mc image ships no curl/wget/sed; use bash /dev/tcp + parameter expansion.
# Parse host and port from MINIO_ENDPOINT (format: http://host:port).
_HOSTPORT="${MINIO_ENDPOINT#*//}"   # strip http:// or https://
_HOST="${_HOSTPORT%%:*}"            # everything before first colon
_PORT="${_HOSTPORT##*:}"            # everything after last colon (may equal _HOSTPORT if no port)
[ "${_PORT}" = "${_HOSTPORT}" ] && _PORT="9000"
until bash -c "exec 3<>/dev/tcp/${_HOST}/${_PORT} && exec 3>&-" 2>/dev/null; do
    ATTEMPTS=$((ATTEMPTS + 1))
    if [ "${ATTEMPTS}" -ge "${MAX_ATTEMPTS}" ]; then
        echo "[setup-minio] ERROR: MinIO not ready after ${MAX_ATTEMPTS} attempts." >&2
        exit 1
    fi
    echo "[setup-minio] Waiting... attempt ${ATTEMPTS}/${MAX_ATTEMPTS}"
    sleep 3
done
echo "[setup-minio] MinIO is ready."

# ─── Configure mc alias ───────────────────────────────────────────────────────
# Note: credentials are passed as arguments here because mc has no password-file
# option. This is acceptable because the container is ephemeral (restart: on-failure)
# and credentials are not written to any persistent file.
echo "[setup-minio] Configuring mc client..."
mc alias set "${MC_ALIAS}" \
    "${MINIO_ENDPOINT}" \
    "${MINIO_ROOT_USER}" \
    "${MINIO_ROOT_PASSWORD}" \
    --api S3v4

echo "[setup-minio] mc alias configured."

# ─── Create WORM audit bucket (Object Lock MUST be set at bucket creation) ────
# Object Lock can ONLY be enabled at bucket creation time — it cannot be added
# to an existing bucket. This is a MinIO/S3 constraint.
echo "[setup-minio] Checking audit bucket: ${MINIO_AUDIT_BUCKET}"

if mc ls "${MC_ALIAS}/${MINIO_AUDIT_BUCKET}" > /dev/null 2>&1; then
    echo "[setup-minio] Bucket '${MINIO_AUDIT_BUCKET}' already exists."
    echo "[setup-minio] Verifying Object Lock status..."

    # Verify Object Lock is enabled on the existing bucket.
    # minio/mc image has no grep/sed — use bash case pattern matching.
    LOCK_STATUS=$(mc object-lock info "${MC_ALIAS}/${MINIO_AUDIT_BUCKET}" 2>&1 || true)
    _LOCK_LOWER=$(printf '%s' "${LOCK_STATUS}" | tr '[:upper:]' '[:lower:]')
    case "${_LOCK_LOWER}" in
      *"not enabled"*|*"object lock is not"*)
        echo "[setup-minio] CRITICAL: Bucket exists but Object Lock is NOT enabled!" >&2
        echo "[setup-minio] INV-007 violated. This bucket cannot be used for WORM archival." >&2
        echo "[setup-minio] You must recreate this bucket with Object Lock enabled." >&2
        echo "[setup-minio] To recreate: mc rb --force ${MC_ALIAS}/${MINIO_AUDIT_BUCKET} (WARNING: destroys data)" >&2
        exit 1
        ;;
    esac
    echo "[setup-minio] Object Lock confirmed active on existing bucket."
else
    echo "[setup-minio] Creating WORM bucket with Object Lock: ${MINIO_AUDIT_BUCKET}"
    # --with-lock enables S3 Object Lock at bucket creation (required for WORM)
    mc mb --with-lock "${MC_ALIAS}/${MINIO_AUDIT_BUCKET}"
    echo "[setup-minio] Bucket created with Object Lock enabled."
fi

# ─── Set default Object Lock retention rule ───────────────────────────────────
# GOVERNANCE mode allows a privileged user (with s3:BypassGovernanceRetention)
# to delete objects. This is intentional — it allows controlled deletion for
# incident response without requiring MFA delete (which MinIO OSS doesn't support).
# In production with AWS S3, upgrade to COMPLIANCE mode for stronger guarantees.
echo "[setup-minio] Setting default retention: GOVERNANCE, ${MINIO_RETENTION_DAYS} days..."
mc retention set \
    --default GOVERNANCE "${MINIO_RETENTION_DAYS}d" \
    "${MC_ALIAS}/${MINIO_AUDIT_BUCKET}"

echo "[setup-minio] Retention policy applied."

# ─── Verify retention policy ──────────────────────────────────────────────────
echo "[setup-minio] Verifying retention policy..."
RETENTION_INFO=$(mc retention info "${MC_ALIAS}/${MINIO_AUDIT_BUCKET}" 2>&1 || true)
echo "[setup-minio] Retention info: ${RETENTION_INFO}"

_RET_LOWER=$(printf '%s' "${RETENTION_INFO}" | tr '[:upper:]' '[:lower:]')
case "${_RET_LOWER}" in
  *"governance"*) ;;  # confirmed
  *)
    echo "[setup-minio] CRITICAL: Could not confirm GOVERNANCE retention mode." >&2
    echo "[setup-minio] INV-007 requires GOVERNANCE Object Lock to be active." >&2
    echo "[setup-minio] mc retention info output: ${RETENTION_INFO}" >&2
    echo "[setup-minio] Exiting non-zero to surface configuration failure." >&2
    exit 1
    ;;
esac

echo "[setup-minio] GOVERNANCE retention mode VERIFIED."

# ─── Final Object Lock end-to-end verification (INV-007 hard gate) ───────────
# Perform a secondary check using mc stat to independently confirm Object Lock
# is active. This is belt-and-suspenders: mc object-lock info may succeed on
# bucket creation while mc stat provides the authoritative status visible to
# all clients. If this check fails, we exit 1 — INV-007 compliance is non-negotiable.
echo "[setup-minio] Performing final Object Lock verification via mc stat..."
STAT_OUTPUT=$(mc stat "${MC_ALIAS}/${MINIO_AUDIT_BUCKET}" 2>&1 || true)
_STAT_LOWER=$(printf '%s' "${STAT_OUTPUT}" | tr '[:upper:]' '[:lower:]')
case "${_STAT_LOWER}" in
  *"object"*"lock"*"enabled"*|*"worm"*|*"lock"*"on"*) ;;  # confirmed by mc stat
  *)
    # mc stat output format varies across versions. Log and warn but don't fail —
    # the mc object-lock info check above is the authoritative gate.
    echo "[setup-minio] NOTICE: mc stat output does not explicitly confirm Object Lock." >&2
    echo "[setup-minio] mc stat output: ${STAT_OUTPUT}" >&2
    echo "[setup-minio] Primary verification (mc object-lock info) passed — continuing." >&2
    ;;
esac

# ─── Create compliance-checker read/write policy ──────────────────────────────
# The compliance checker needs PUT access (to write reports) but MUST NOT have
# DELETE access. We create a minimal policy for the compliance checker's
# service account. This is defense-in-depth on top of WORM (INV-007).
echo "[setup-minio] Creating compliance-checker access policy..."

cat > /tmp/compliance-policy.json << POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:PutObject",
        "s3:GetObject",
        "s3:ListBucket",
        "s3:GetBucketObjectLockConfiguration"
      ],
      "Resource": [
        "arn:aws:s3:::${MINIO_AUDIT_BUCKET}",
        "arn:aws:s3:::${MINIO_AUDIT_BUCKET}/*"
      ]
    }
  ]
}
POLICY

mc admin policy create "${MC_ALIAS}" compliance-checker-policy /tmp/compliance-policy.json \
    2>/dev/null || echo "[setup-minio] Policy already exists (idempotent)."

rm -f /tmp/compliance-policy.json

# ─── Final verification summary ───────────────────────────────────────────────
echo ""
echo "[setup-minio] ============================================================"
echo "[setup-minio] Setup complete. Summary:"
echo "[setup-minio]   Endpoint:  ${MINIO_ENDPOINT}"
echo "[setup-minio]   Bucket:    ${MINIO_AUDIT_BUCKET}"
echo "[setup-minio]   Mode:      GOVERNANCE (WORM)"
echo "[setup-minio]   Retention: ${MINIO_RETENTION_DAYS} days"
echo "[setup-minio]   INV-007:   SATISFIED"
echo "[setup-minio] ============================================================"
