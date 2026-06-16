#!/usr/bin/env bash
# check_loki_labels.sh — CI gate: ensure no stale {job="mcp-audit"} label remains
# in the Loki alert rules.
#
# Background: alert rules must query {job="mcp-proxy", log_type="audit"} to match
# the labels that Promtail actually assigns to proxy container logs.  The old label
# {job="mcp-audit"} is a vestigial mismatch that causes all 8 alert rules to fire
# zero results.  This gate prevents the label from re-appearing after a merge.
#
# Run standalone:   bash scripts/check_loki_labels.sh
# Run via make:     make security-check  (included in that target)
set -euo pipefail
cd "$(cd "$(dirname "$0")/.." && pwd)" || exit 1

RULES_FILE="observability/loki/rules/mcp_alerts.yml"

if [ ! -f "${RULES_FILE}" ]; then
  echo "ERROR: ${RULES_FILE} not found"
  exit 1
fi

# Match lines containing job="mcp-audit" that are NOT pure comment lines.
# Pure comment lines start with optional whitespace then '#'.
STALE=$(grep -n 'job="mcp-audit"' "${RULES_FILE}" | grep -v '^[0-9]*:[[:space:]]*#' || true)

if [ -n "${STALE}" ]; then
  echo "ERROR: stale job=\"mcp-audit\" label found in ${RULES_FILE} — use job=\"mcp-proxy\", log_type=\"audit\" instead:"
  echo "${STALE}"
  exit 1
fi

echo "OK: no stale mcp-audit labels in ${RULES_FILE}"
