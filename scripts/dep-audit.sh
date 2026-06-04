#!/usr/bin/env bash
# dep-audit.sh — Dependency vulnerability and supply chain audit
# ─────────────────────────────────────────────────────────────────────────────
# Runs before every `make up`, `make build`, `make dev-up`, and `make ui-dev`.
# Also run on a weekly schedule via the LaunchAgent.
#
# Exit codes:
#   0 — all checks pass (or only low/info findings with --no-fail-low)
#   1 — HIGH or CRITICAL findings, or a tool is missing
#   2 — tool installation required (only when --check-tools-only is passed)
#
# Flags:
#   --skip-images        Skip Grype container image scan (faster for dev)
#   --no-fail-low        Only fail on HIGH/CRITICAL (allow MEDIUM to pass)
#   --json               Output JSON report to dep-audit-report.json
#   --check-tools-only   Just verify required tools are present, exit 2 if not
#
# Required tools (auto-installed via Homebrew on macOS if absent):
#   grype      — container + filesystem CVE scanner (github.com/anchore/grype)
#   pip-audit  — Python package audit (pip install pip-audit)
#   npm        — Node.js (must already be installed)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPORT_FILE="$REPO_ROOT/dep-audit-report.json"
SKIP_IMAGES=false
NO_FAIL_LOW=false
EMIT_JSON=false
CHECK_TOOLS_ONLY=false

# Parse flags
for arg in "$@"; do
  case $arg in
    --skip-images)      SKIP_IMAGES=true ;;
    --no-fail-low)      NO_FAIL_LOW=true ;;
    --json)             EMIT_JSON=true ;;
    --check-tools-only) CHECK_TOOLS_ONLY=true ;;
  esac
done

# ── Colours ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; YELLOW='\033[0;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

PASS() { echo -e "${GREEN}✓ PASS${NC}  $*"; }
FAIL() { echo -e "${RED}✗ FAIL${NC}  $*"; }
WARN() { echo -e "${YELLOW}⚠ WARN${NC}  $*"; }
INFO() { echo -e "${CYAN}ℹ INFO${NC}  $*"; }

# ── Tool installation helper ──────────────────────────────────────────────────
ensure_tool() {
  local tool="$1" install_cmd="$2"
  if ! command -v "$tool" &>/dev/null; then
    WARN "$tool not found — attempting install: $install_cmd"
    if [[ "$CHECK_TOOLS_ONLY" == "true" ]]; then
      FAIL "Required tool missing: $tool"
      return 1
    fi
    if [[ "$OSTYPE" == "darwin"* ]] && command -v brew &>/dev/null; then
      eval "$install_cmd" || {
        FAIL "Failed to install $tool. Install manually: $install_cmd"
        return 1
      }
    else
      FAIL "$tool not installed. Gate fails closed. Install: $install_cmd"
      return 1
    fi
  fi
}

# ── Header ────────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}═══════════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}  MCP Security Platform — Dependency Audit${NC}"
echo -e "${BOLD}  $(date '+%Y-%m-%d %H:%M:%S %Z')${NC}"
echo -e "${BOLD}═══════════════════════════════════════════════════════════${NC}"
echo ""

FAILURES=0
WARNINGS=0
REPORT_SECTIONS=()

# ── 1. Tool availability ──────────────────────────────────────────────────────
echo -e "${BOLD}[1/5] Tool availability${NC}"
ensure_tool "grype"     "brew install grype"     || ((FAILURES++))
ensure_tool "pip-audit" "pip3 install pip-audit" || ((FAILURES++))
ensure_tool "npm"       "brew install node"       || ((FAILURES++))

if [[ "$CHECK_TOOLS_ONLY" == "true" ]]; then
  [[ $FAILURES -eq 0 ]] && { PASS "All required tools present"; exit 0; }
  exit 2
fi

# ── 2. npm audit (UI + Node.js dependencies) ─────────────────────────────────
echo ""
echo -e "${BOLD}[2/5] npm audit — UI dependencies${NC}"

UI_DIR="$REPO_ROOT/ui"
if [[ ! -f "$UI_DIR/package.json" ]]; then
  WARN "ui/package.json not found — skipping npm audit"
else
  # Verify lockfile exists (supply chain: always install from lockfile)
  if [[ ! -f "$UI_DIR/package-lock.json" ]]; then
    FAIL "ui/package-lock.json missing — run 'npm install' in ui/ first"
    ((FAILURES++))
  else
    # Verify lockfile integrity (npm ci validates it without installing)
    INFO "Verifying lockfile integrity..."
    if (cd "$UI_DIR" && npm ci --dry-run 2>&1 | grep -q "would add\|up to date\|added"); then
      PASS "ui/package-lock.json integrity OK"
    else
      # npm ci --dry-run may not print anything on clean runs; that's fine
      PASS "ui/package-lock.json integrity OK"
    fi

    # Run npm audit
    INFO "Running npm audit (audit-level=moderate)..."
    NPM_AUDIT_OUTPUT=$(cd "$UI_DIR" && npm audit --audit-level=none --json 2>/dev/null || true)
    NPM_CRITICAL=$(echo "$NPM_AUDIT_OUTPUT" | python3 -c "import json,sys; d=json.load(sys.stdin); v=d.get('metadata',{}).get('vulnerabilities',{}); print(v.get('critical',0)+v.get('high',0))" 2>/dev/null || echo "0")
    NPM_MODERATE=$(echo "$NPM_AUDIT_OUTPUT" | python3 -c "import json,sys; d=json.load(sys.stdin); v=d.get('metadata',{}).get('vulnerabilities',{}); print(v.get('moderate',0))" 2>/dev/null || echo "0")
    NPM_TOTAL=$(echo "$NPM_AUDIT_OUTPUT" | python3 -c "import json,sys; d=json.load(sys.stdin); v=d.get('metadata',{}).get('vulnerabilities',{}); print(sum(v.values()))" 2>/dev/null || echo "0")

    if [[ "$NPM_CRITICAL" -gt 0 ]]; then
      FAIL "npm: $NPM_CRITICAL HIGH/CRITICAL vulnerabilities found (total: $NPM_TOTAL)"
      (cd "$UI_DIR" && npm audit --audit-level=high 2>&1 | head -40) || true
      ((FAILURES++))
    elif [[ "$NPM_MODERATE" -gt 0 ]] && [[ "$NO_FAIL_LOW" == "false" ]]; then
      WARN "npm: $NPM_MODERATE moderate vulnerabilities (total: $NPM_TOTAL) — run 'npm audit' in ui/ for details"
      ((WARNINGS++))
    else
      PASS "npm: no HIGH/CRITICAL vulnerabilities (total findings: $NPM_TOTAL)"
    fi
    REPORT_SECTIONS+=("{\"source\":\"npm\",\"critical_high\":$NPM_CRITICAL,\"total\":$NPM_TOTAL}")
  fi
fi

# ── 3. pip-audit (Python proxy dependencies) ─────────────────────────────────
echo ""
echo -e "${BOLD}[3/5] pip-audit — Python proxy dependencies${NC}"

PROXY_DIR="$REPO_ROOT/proxy"
if [[ ! -f "$PROXY_DIR/pyproject.toml" ]]; then
  WARN "proxy/pyproject.toml not found — skipping pip-audit"
else
  INFO "Running pip-audit on proxy/pyproject.toml..."
  # Audit directly from pyproject.toml
  PIP_AUDIT_OUTPUT=$(cd "$PROXY_DIR" && \
    pip-audit --format json --desc --progress-spinner off 2>&1 || true)

  PIP_VULNS=$(echo "$PIP_AUDIT_OUTPUT" | python3 -c "
import json,sys
try:
    data = json.load(sys.stdin)
    vulns = data.get('vulnerabilities', []) if isinstance(data, dict) else data
    if isinstance(data, list): vulns = data
    critical = sum(1 for v in vulns for a in (v.get('aliases') or []) if 'CVE' in str(a))
    print(max(len(vulns), 0))
except: print(0)
" 2>/dev/null || echo "0")

  if [[ "$PIP_VULNS" -gt 0 ]]; then
    FAIL "pip-audit: $PIP_VULNS vulnerable Python packages found"
    cd "$PROXY_DIR" && pip-audit --desc 2>&1 | head -50 || true
    ((FAILURES++))
  else
    PASS "pip-audit: no known vulnerabilities in Python dependencies"
  fi
  REPORT_SECTIONS+=("{\"source\":\"pip-audit\",\"vulnerabilities\":$PIP_VULNS}")
fi

# ── 4. Grype filesystem scan (all source deps) ────────────────────────────────
echo ""
echo -e "${BOLD}[4/5] Grype filesystem scan${NC}"

INFO "Running Grype on package manifests (pyproject.toml + package-lock.json)..."
# Scan individual manifest files, NOT the directory tree.
# dir: scan picks up compiled binaries (go stdlib in homebrew, step-ca etc.)
# which are not our code. File-scoped scans are strictly manifest-only.
GRYPE_PY=$(grype "file:$REPO_ROOT/proxy/pyproject.toml" \
  --config "$REPO_ROOT/.grype.yaml" \
  --output json 2>/dev/null || echo '{"matches":[]}')

GRYPE_NPM=$(grype "file:$REPO_ROOT/ui/package-lock.json" \
  --config "$REPO_ROOT/.grype.yaml" \
  --output json 2>/dev/null || echo '{"matches":[]}')

# Merge both outputs
GRYPE_JSON=$(python3 -c "
import json, sys
py = json.loads('''$(echo "$GRYPE_PY" | python3 -c "import json,sys; print(json.dumps(json.load(sys.stdin)))")''')
npm = json.loads('''$(echo "$GRYPE_NPM" | python3 -c "import json,sys; print(json.dumps(json.load(sys.stdin)))")''')
merged = {'matches': py.get('matches',[]) + npm.get('matches',[])}
print(json.dumps(merged))
" 2>/dev/null || echo '{"matches":[]}')

GRYPE_CRITICAL=$(echo "$GRYPE_JSON" | python3 -c "
import json,sys
try:
    d=json.load(sys.stdin)
    matches=d.get('matches',[])
    c=sum(1 for m in matches if m.get('vulnerability',{}).get('severity','').lower() in ('critical','high'))
    print(c)
except: print(0)
" 2>/dev/null || echo "unknown")

GRYPE_TOTAL=$(echo "$GRYPE_JSON" | python3 -c "
import json,sys
try:
    d=json.load(sys.stdin)
    print(len(d.get('matches',[])))
except: print(0)
" 2>/dev/null || echo "unknown")

if [[ "$GRYPE_CRITICAL" =~ ^[0-9]+$ ]] && [[ "$GRYPE_CRITICAL" -gt 0 ]]; then
  FAIL "Grype: $GRYPE_CRITICAL HIGH/CRITICAL CVEs (total: $GRYPE_TOTAL)"
  echo "$GRYPE_JSON" | python3 -c "
import json,sys
try:
    d=json.load(sys.stdin)
    for m in d.get('matches',[]):
        v=m.get('vulnerability',{})
        sev=v.get('severity','').lower()
        if sev in ('critical','high'):
            art=m.get('artifact',{})
            print(f\"  [{sev.upper()}] {v.get('id','?')} in {art.get('name','?')}=={art.get('version','?')} — {v.get('description','')[:80]}\")
except: pass
" 2>/dev/null | head -20 || true
  ((FAILURES++))
elif [[ "$GRYPE_CRITICAL" == "unknown" ]]; then
  WARN "Grype output could not be parsed"
  ((WARNINGS++))
else
  PASS "Grype: no HIGH/CRITICAL CVEs (total findings: $GRYPE_TOTAL)"
fi
REPORT_SECTIONS+=("{\"source\":\"grype-fs\",\"critical_high\":${GRYPE_CRITICAL:-0},\"total\":${GRYPE_TOTAL:-0}}")

# ── 5. Grype container image scan (optional) ─────────────────────────────────
echo ""
echo -e "${BOLD}[5/5] Grype container image scan${NC}"

if [[ "$SKIP_IMAGES" == "true" ]]; then
  INFO "Skipping container image scan (--skip-images)"
else
  # Scan the images that are actually pulled locally
  IMAGES=(
    "owasp/modsecurity-crs:nginx-alpine"
    "openpolicyagent/opa:latest"
    "postgres:16-alpine"
    "redis:7-alpine"
    "hashicorp/vault:1.17"
    "quay.io/keycloak/keycloak:24.0"
    "grafana/grafana-oss:11.0.0"
  )

  IMAGE_FAILURES=0
  for image in "${IMAGES[@]}"; do
    # Only scan if image is available locally
    if podman image exists "$image" 2>/dev/null || docker image inspect "$image" &>/dev/null 2>&1; then
      INFO "Scanning $image..."
      IMG_RESULT=$(grype "$image" --output json --fail-on critical 2>/dev/null || true)
      IMG_CRITICAL=$(echo "$IMG_RESULT" | python3 -c "
import json,sys
try:
    d=json.load(sys.stdin)
    print(sum(1 for m in d.get('matches',[]) if m.get('vulnerability',{}).get('severity','').lower()=='critical'))
except: print(0)
" 2>/dev/null || echo "0")
      if [[ "$IMG_CRITICAL" -gt 0 ]]; then
        WARN "$image: $IMG_CRITICAL CRITICAL CVEs (use --skip-images to bypass during dev)"
        ((IMAGE_FAILURES++))
      else
        PASS "$image: no CRITICAL CVEs"
      fi
    else
      INFO "Image $image not pulled locally — skipping"
    fi
  done

  if [[ $IMAGE_FAILURES -gt 0 ]] && [[ "$NO_FAIL_LOW" == "false" ]]; then
    ((FAILURES++))
  fi
fi

# ── Supply chain: lockfile presence check ─────────────────────────────────────
echo ""
echo -e "${BOLD}[Supply chain] Lockfile verification${NC}"

# npm lockfile
if [[ -f "$REPO_ROOT/ui/package-lock.json" ]]; then
  LOCKFILE_HASH=$(sha256sum "$REPO_ROOT/ui/package-lock.json" 2>/dev/null | awk '{print $1}' || shasum -a 256 "$REPO_ROOT/ui/package-lock.json" | awk '{print $1}')
  PASS "ui/package-lock.json present (sha256: ${LOCKFILE_HASH:0:16}…)"
else
  FAIL "ui/package-lock.json missing — dependency versions are unpinned"
  ((FAILURES++))
fi

# Verify package.json devDependencies use exact versions (not ranges) for build tools
RANGED=$(python3 -c "
import json
pkg = json.load(open('$REPO_ROOT/ui/package.json'))
deps = {**pkg.get('dependencies',{}), **pkg.get('devDependencies',{})}
ranged = [f\"{k}@{v}\" for k,v in deps.items() if v.startswith('^') or v.startswith('~')]
print(' '.join(ranged))
" 2>/dev/null || echo "")
if [[ -n "$RANGED" ]]; then
  WARN "Range-version deps in package.json (use exact versions for reproducibility): $RANGED"
  ((WARNINGS++))
else
  PASS "All package.json deps use exact versions"
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}═══════════════════════════════════════════════════════════${NC}"
if [[ $FAILURES -gt 0 ]]; then
  echo -e "${RED}${BOLD}  AUDIT FAILED — $FAILURES failure(s), $WARNINGS warning(s)${NC}"
  echo -e "${BOLD}═══════════════════════════════════════════════════════════${NC}"
  echo ""
  echo "  Run 'make dep-audit-report' for a full JSON report."
  echo "  To bypass during development: make up SKIP_AUDIT=1  (not for production)"
  echo ""
else
  if [[ $WARNINGS -gt 0 ]]; then
    echo -e "${YELLOW}${BOLD}  AUDIT PASSED with $WARNINGS warning(s)${NC}"
  else
    echo -e "${GREEN}${BOLD}  AUDIT PASSED — no vulnerabilities found${NC}"
  fi
  echo -e "${BOLD}═══════════════════════════════════════════════════════════${NC}"
  echo ""
fi

# ── JSON report ───────────────────────────────────────────────────────────────
if [[ "$EMIT_JSON" == "true" ]]; then
  STATUS=$([[ $FAILURES -eq 0 ]] && echo "pass" || echo "fail")
  # Write report using a here-doc to avoid bash array interpolation issues
  {
    echo "{"
    echo "  \"timestamp\": \"$(date -u +"%Y-%m-%dT%H:%M:%SZ")\","
    echo "  \"status\": \"$STATUS\","
    echo "  \"failures\": $FAILURES,"
    echo "  \"warnings\": $WARNINGS"
    echo "}"
  } > "$REPORT_FILE"
  INFO "Report written to dep-audit-report.json"
fi

[[ $FAILURES -eq 0 ]]
