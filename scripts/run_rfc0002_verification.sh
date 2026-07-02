#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# RFC-0002 verification runner — one command, offline-first, auto-detects a live
# gateway. See docs/rfc/RFC-0002-verification-plan.md for the full plan.
#
#   Layer 1 (oracle)     : pure RFC-0002 §4-6 decision logic vs Appendix B vectors
#   Layer 2 (substrate)  : the REAL implemented RFC-0001 labeler/verifier/taint
#   Layer 3 (demo)       : scripts/demo_trust_envelope.py round-trip smoke
#   Layer 4 (conformance): RFC-0002 §4-6 gateway integration — SKIP until built
#   Layer 5 (live)       : end-to-end vs a running proxy (auto-skipped if down)
#
# Exit code: non-zero ONLY on real failures/errors. Skips (unbuilt features, no
# live proxy) never fail the run.
#
# Usage:
#   scripts/run_rfc0002_verification.sh                # everything (auto-detect)
#   RFC0002_PROXY_URL=http://host:8000 scripts/run_rfc0002_verification.sh
#   scripts/run_rfc0002_verification.sh --offline      # skip live detection
# ─────────────────────────────────────────────────────────────────────────────
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROXY_DIR="${REPO_ROOT}/proxy"
RESULTS_DIR="${RFC0002_RESULTS_DIR:-${PROXY_DIR}/tests/rfc0002/_results}"
PROXY_URL="${RFC0002_PROXY_URL:-http://localhost:8000}"
STAMP="$(date -u +%Y-%m-%dT%H-%M-%SZ)"
mkdir -p "${RESULTS_DIR}"
JUNIT="${RESULTS_DIR}/rfc0002-junit-${STAMP}.xml"
LOG="${RESULTS_DIR}/rfc0002-run-${STAMP}.log"
REPORT="${RESULTS_DIR}/rfc0002-report-${STAMP}.md"

OFFLINE=0
[ "${1:-}" = "--offline" ] && OFFLINE=1

# Settings() validation env (the repo normally runs pytest INSIDE the container
# where compose injects these; outside it we supply test-only placeholders).
export ENVIRONMENT="${ENVIRONMENT:-development}"
for v in DB_PASSWORD REDIS_PASSWORD PROXY_SECRET_KEY API_KEY_HMAC_KEY \
         SBOM_SIGNING_KEY AUDIT_LOG_HMAC_KEY WEBHOOK_SIGNING_KEY \
         MINIO_ROOT_USER MINIO_ROOT_PASSWORD; do
  export "${v}=${!v:-test}"
done

c_red=$'\033[31m'; c_grn=$'\033[32m'; c_yel=$'\033[33m'; c_blu=$'\033[34m'; c_off=$'\033[0m'
say() { printf '%s\n' "$*"; }
hdr() { printf '\n%s== %s ==%s\n' "$c_blu" "$*" "$c_off"; }

cd "${PROXY_DIR}" || { say "${c_red}cannot cd ${PROXY_DIR}${c_off}"; exit 2; }

# ── Phase 0: preflight ───────────────────────────────────────────────────────
hdr "Phase 0 — preflight"
PYBIN="${PYTHON:-python3}"
"${PYBIN}" --version || { say "${c_red}python3 not found${c_off}"; exit 2; }
miss=0
for mod in pytest cryptography jcs; do
  if ! "${PYBIN}" -c "import ${mod}" 2>/dev/null; then
    say "${c_red}MISSING required module: ${mod}${c_off} (pip install -r proxy/requirements.txt)"
    miss=1
  fi
done
[ "${miss}" -eq 1 ] && { say "${c_red}preflight failed — install deps and retry${c_off}"; exit 2; }
if ! "${PYBIN}" -c "import freezegun" 2>/dev/null; then
  say "${c_yel}optional 'freezegun' not installed — the freshness/replay test will SKIP."
  say "  enable it with: pip install freezegun${c_off}"
fi
say "${c_grn}preflight OK${c_off}  (results → ${RESULTS_DIR})"

# ── Phases 1-4 + live: single pytest pass over the suite ─────────────────────
# A single invocation keeps one coherent junit/report; markers tag the layers.
hdr "Phases 1-5 — pytest (oracle + substrate + conformance + live)"
PYTEST_ARGS=(tests/rfc0002 -rs -ra --tb=short --junitxml="${JUNIT}" -o "junit_family=xunit2")
if [ "${OFFLINE}" -eq 1 ]; then
  PYTEST_ARGS+=(-m "not live")
  say "${c_yel}--offline: live layer disabled${c_off}"
else
  if curl -fsS --max-time 3 "${PROXY_URL}/health" >/dev/null 2>&1; then
    say "${c_grn}live proxy detected at ${PROXY_URL} — live layer ENABLED${c_off}"
  else
    say "${c_yel}no live proxy at ${PROXY_URL} — live layer will auto-skip${c_off}"
  fi
fi

set -o pipefail
"${PYBIN}" -m pytest "${PYTEST_ARGS[@]}" 2>&1 | tee "${LOG}"
PYTEST_RC=${PIPESTATUS[0]}

# ── Demo smoke (the implemented RFC-0001 round-trip) ─────────────────────────
hdr "Demo smoke — scripts/demo_trust_envelope.py"
DEMO_RC=0
if [ -f "${REPO_ROOT}/scripts/demo_trust_envelope.py" ]; then
  "${PYBIN}" "${REPO_ROOT}/scripts/demo_trust_envelope.py" 2>&1 | tee -a "${LOG}"
  DEMO_RC=${PIPESTATUS[0]}
else
  say "${c_yel}demo script not found — skipping smoke${c_off}"
fi

# ── Summary report ───────────────────────────────────────────────────────────
SUMMARY_LINE="$(grep -E '[0-9]+ (passed|failed|skipped|error)' "${LOG}" | tail -1)"
hdr "Summary"
say "pytest : ${SUMMARY_LINE:-<no summary parsed>}"
say "demo   : $( [ "${DEMO_RC}" -eq 0 ] && echo "${c_grn}PASS${c_off}" || echo "${c_red}FAIL${c_off}" )"

{
  echo "# RFC-0002 Verification Report"
  echo
  echo "- **Run (UTC):** ${STAMP}"
  echo "- **Proxy URL:** ${PROXY_URL} ($( [ "${OFFLINE}" -eq 1 ] && echo offline || echo auto-detect ))"
  echo "- **pytest summary:** \`${SUMMARY_LINE:-n/a}\`"
  echo "- **demo round-trip:** $( [ "${DEMO_RC}" -eq 0 ] && echo PASS || echo FAIL )"
  echo "- **JUnit XML:** \`${JUNIT}\`"
  echo "- **Full log:** \`${LOG}\`"
  echo
  echo "## What passed vs what is pending"
  echo
  echo "- **Oracle (RFC-0002 §4-6 logic)** and **Substrate (RFC-0001)** layers should be all-green."
  echo "- **Conformance §4-6** skips are the implementation backlog (each skip names the module/file to build)."
  echo "- **Live** skips mean no running gateway was detected."
  echo
  echo "### Skips (backlog + environment)"
  echo '```'
  grep -E 'SKIPPED' "${LOG}" || echo "(none)"
  echo '```'
} > "${REPORT}"
say "report : ${REPORT}"

# ── Exit code: real failures only. pytest rc 0=ok,1=fail,5=no tests collected ─
RC=0
if [ "${PYTEST_RC}" -ne 0 ] && [ "${PYTEST_RC}" -ne 5 ]; then RC=1; fi
[ "${DEMO_RC}" -ne 0 ] && RC=1
if [ "${RC}" -eq 0 ]; then
  say "${c_grn}RFC-0002 verification: PASS (skips are expected backlog/live-absent)${c_off}"
else
  say "${c_red}RFC-0002 verification: FAILURES present — see ${LOG}${c_off}"
fi
exit "${RC}"
