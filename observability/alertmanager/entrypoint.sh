#!/bin/sh
# entrypoint.sh — alertmanager-config-renderer init container
#
# Renders observability/alertmanager/alertmanager.yml (template) into the
# shared tmpfs volume at /run/alertmanager/alertmanager.yml so that
# Alertmanager can mount it read-only.
#
# Constraints obeyed:
#   - Runs in an alpine image (has envsubst via gettext package)
#   - Does NOT run inside the prom/alertmanager image (busybox, no envsubst)
#   - Alertmanager UID 65534 mounts the output volume read-only; we write as
#     root (init container exits before alertmanager starts)
#   - GNU envsubst does not support ${VAR:-default}; we export fallback values
#     in shell before running envsubst
#
# Exit codes:
#   0 — rendered config written with no surviving placeholders
#   1 — rendering failed or placeholder leak detected
set -eu

TEMPLATE=/etc/alertmanager-template/alertmanager.yml
OUTDIR=/run/alertmanager
OUTFILE="${OUTDIR}/alertmanager.yml"

# ---------------------------------------------------------------------------
# Step 1: Apply fallback logic for variables that have defaults.
# This must happen BEFORE envsubst so we only emit plain ${VAR} in the
# template (GNU envsubst does not expand ${VAR:-fallback} syntax).
# ---------------------------------------------------------------------------

# ALERT_WEBHOOK_URL_CRITICAL defaults to ALERT_WEBHOOK_URL when not set.
# Both must end up as non-empty strings for the config to be valid.
if [ -z "${ALERT_WEBHOOK_URL:-}" ]; then
  echo "ERROR: ALERT_WEBHOOK_URL is not set. Cannot render alertmanager config." >&2
  exit 1
fi

export ALERT_WEBHOOK_URL_CRITICAL="${ALERT_WEBHOOK_URL_CRITICAL:-${ALERT_WEBHOOK_URL}}"

# ---------------------------------------------------------------------------
# Step 2: Render the template via envsubst.
# Only substitute the two ALERT_WEBHOOK_URL* vars — do not accidentally
# expand any other ${...} sequences that may appear in comments.
# ---------------------------------------------------------------------------
mkdir -p "${OUTDIR}"
envsubst '${ALERT_WEBHOOK_URL} ${ALERT_WEBHOOK_URL_CRITICAL}' \
  < "${TEMPLATE}" > "${OUTFILE}"

# ---------------------------------------------------------------------------
# Step 3: Grep gate — fail hard if any ${...} placeholder survived.
# This catches template bugs (e.g. a new placeholder added without a
# corresponding export above) before Alertmanager tries to load an invalid
# config.
# ---------------------------------------------------------------------------
if grep -E '\$\{[A-Z_]+\}' "${OUTFILE}" | grep -qvE '^\s*#'; then
  echo "ERROR: rendered config still contains unresolved placeholders:" >&2
  grep -nE '\$\{[A-Z_]+\}' "${OUTFILE}" | grep -vE '^\s*[0-9]+\s*#' >&2
  exit 1
fi

echo "OK: alertmanager config rendered to ${OUTFILE}"
echo "--- rendered config (webhook URLs redacted) ---"
sed 's|url:.*|url: [REDACTED]|g' "${OUTFILE}"
echo "--- end rendered config ---"
