#!/usr/bin/env bash
# ship-check.sh — pre-publish gate for an honest public release (Path A).
# Fails closed. Run before every push:  bash scripts/ship-check.sh   (or: make ship-check)
# Full smoke (compose up + isolation demo) only when SHIP_FULL=1 (needs docker).
set -uo pipefail
cd "$(cd "$(dirname "$0")/.." && pwd)" || exit 1
RC=0
hr(){ printf '── %s %s\n' "$1" "────────────────────────────────────────" | cut -c1-60; }

hr "1. Docs-honesty gate (README — the public face)"
# Scoped to README.md: the primary public-facing doc. The reality-annotated docs
# (ARCHITECTURE-v2 / ROADMAP / SHIP) are ALLOWED to enumerate what's not built, so they're
# out of scope. Patterns are affirmative over-claims + brand leaks that must NOT appear.
PATTERNS='alexromanov|for every tool call|intercepts all MCP|\+ ?SPDX|SPDX 2\.3|\b92%|Lilith-zero|MCP Spine|Vectimus|compliance-grade'
if [ -f README.md ]; then
  hits=$(grep -nEi "$PATTERNS" README.md 2>/dev/null || true)
  if [ -n "$hits" ]; then echo "FAIL — retired over-claim / brand leak in README:"; echo "$hits"; RC=1
  else echo "OK — README clean of retired over-claims / brand leaks"; fi
else echo "FAIL — README.md missing"; RC=1; fi

hr "2. Secret scan"
if command -v trufflehog >/dev/null 2>&1; then
  if trufflehog git "file://$PWD" --only-verified --fail >/dev/null 2>&1; then echo "OK — no verified secrets in git history"
  else echo "FAIL — trufflehog found verified secrets"; RC=1; fi
else
  # Best-effort WARN-only fallback (trufflehog is the real gate). Excludes examples, docs, and CI/test fixtures.
  GP='(VAULT_TOKEN|_SECRET|PASSWORD|API_KEY|PRIVATE_KEY)[=:][[:space:]]*["'\''"]?[A-Za-z0-9]{12,}'
  cand=$(git grep -nE "$GP" -- ':!*.example' ':!.env.example' ':!docs/**' ':!ci/**' ':!**/tests/**' ':!*test*' 2>/dev/null || true)
  if [ -n "$cand" ]; then echo "WARN — trufflehog absent; grep found possible hardcoded secrets (review manually, not auto-failing):"; echo "$cand" | head
  else echo "OK (grep fallback clean; install trufflehog for full git-history scan)"; fi
fi

hr "3. Compose smoke"
if command -v docker >/dev/null 2>&1; then
  if docker compose config >/dev/null 2>&1; then echo "OK — docker compose config valid"
  else echo "FAIL — docker compose config invalid"; RC=1; fi
  if [ "${SHIP_FULL:-0}" = "1" ]; then
    if docker compose up -d >/dev/null 2>&1 && sleep 20 && make health >/dev/null 2>&1; then echo "OK — stack healthy"
    else echo "FAIL — stack did not come up healthy"; RC=1; fi
    docker compose down -v >/dev/null 2>&1 || true
  else echo "(full 'compose up' skipped — set SHIP_FULL=1 to run it)"; fi
else echo "WARN — docker not available; compose smoke skipped"; fi

hr "4. Network-isolation demo (verified control)"
if [ -f scripts/check_network_isolation.py ]; then
  if [ "${SHIP_FULL:-0}" = "1" ]; then
    if python3 scripts/check_network_isolation.py >/dev/null 2>&1; then echo "OK — F-001 isolation proven"
    else echo "FAIL — isolation check failed"; RC=1; fi
  else echo "(isolation demo runs with SHIP_FULL=1)"; fi
else echo "WARN — scripts/check_network_isolation.py missing"; fi

hr "5. Alertmanager config render smoke (Task 0.3)"
# Verifies the template renders without surviving placeholders.
# Uses sh + envsubst (requires gettext installed on the host, or skip with WARN).
# This replicates exactly what the alertmanager-config-renderer init container does.
TMPL="observability/alertmanager/alertmanager.yml"
RENDERER="observability/alertmanager/entrypoint.sh"
if [ ! -f "${TMPL}" ]; then
  echo "FAIL — ${TMPL} missing"; RC=1
elif [ ! -f "${RENDERER}" ]; then
  echo "FAIL — ${RENDERER} missing"; RC=1
elif ! command -v envsubst >/dev/null 2>&1; then
  echo "WARN — envsubst not available (install gettext); alertmanager render smoke skipped"
else
  # Confirm template itself has no nested ${VAR:-...} that envsubst can't handle.
  # Exclude comment lines (lines beginning with optional whitespace then #).
  if grep -E '\$\{[A-Z_]+:-' "${TMPL}" | grep -qvE '^\s*#'; then
    echo "FAIL — ${TMPL} contains \${VAR:-default} syntax on non-comment lines; use plain \${VAR} (renderer handles fallbacks)"
    grep -nE '\$\{[A-Z_]+:-' "${TMPL}" | grep -vE '^\s*[0-9]+:\s*#'
    RC=1
  else
    # Render with test values into a temp file
    TMPOUT=$(mktemp)
    ALERT_WEBHOOK_URL="https://hooks.example.com/test" \
    ALERT_WEBHOOK_URL_CRITICAL="https://hooks.example.com/test-critical" \
    envsubst '${ALERT_WEBHOOK_URL} ${ALERT_WEBHOOK_URL_CRITICAL}' \
      < "${TMPL}" > "${TMPOUT}" 2>/dev/null
    # Check for surviving placeholders on non-comment lines only
    if grep -E '\$\{[A-Z_]+\}' "${TMPOUT}" | grep -qvE '^\s*#'; then
      echo "FAIL — rendered alertmanager config still contains unresolved placeholders:"
      grep -nE '\$\{[A-Z_]+\}' "${TMPOUT}" | grep -vE '^\s*[0-9]+:\s*#'
      rm -f "${TMPOUT}"; RC=1
    else
      echo "OK — alertmanager config renders with no surviving placeholders"
    fi
    rm -f "${TMPOUT}"
  fi
fi

printf '────────────────────────────────────────────\n'
[ $RC -eq 0 ] && echo "ship-check PASSED — ready to publish" || echo "ship-check FAILED (rc=$RC) — fix before publishing"
exit $RC
