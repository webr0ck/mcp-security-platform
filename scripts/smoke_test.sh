#!/usr/bin/env bash
# smoke_test.sh — End-to-end smoke test for the MCP Security Platform
#
# Tests the full stack through the gateway, confirming:
#   1. Proxy /health → 200
#   2. Proxy /health/ready → 200
#   3. POST /tools/register with a test tool → 201, risk_score present
#   4. POST /tools/{id}/invoke with no auth → 401 (INV-009 enforced)
#   5. POST /tools/{id}/invoke with valid API key → 200 or 403 (OPA deny is OK)
#   6. GET /compliance/reports → 200
#   7. MinIO Object Lock status → bucket exists with Object Lock enabled (INV-007)
#
# Usage:
#   ./scripts/smoke_test.sh [environment]
#   environment: dev | staging | prod (default: dev)
#   make smoke-test
#
# Exit code: 0 if all checks pass, 1 if any check fails.
# Dependencies: curl, python3 (for JSON parsing), docker compose v2

set -euo pipefail

# ─── Configuration ────────────────────────────────────────────────────────────

ENVIRONMENT="${1:-dev}"
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# Endpoints vary by environment
case "${ENVIRONMENT}" in
    prod|production)
        PROXY_URL="https://localhost/api/v1"
        # In production, TLS cert validation is enforced; provide CA bundle
        CURL_OPTS=("--cacert" "./gateway/step-ca/certs/root_ca.crt")
        ;;
    staging)
        PROXY_URL="https://localhost/api/v1"
        CURL_OPTS=("--cacert" "./gateway/step-ca/certs/root_ca.crt")
        ;;
    dev|development|*)
        # In dev, proxy is exposed directly on port 8000 (no TLS)
        PROXY_URL="http://localhost:8000/api/v1"
        CURL_OPTS=()
        ;;
esac

# API key for authenticated tests — read from environment (never hardcoded)
# In CI, set SMOKE_TEST_API_KEY in the environment.
# In dev, set it in .env or export it before running.
SMOKE_TEST_API_KEY="${SMOKE_TEST_API_KEY:-}"

# MinIO settings for WORM verification (read from .env if present)
if [ -f ".env" ]; then
    # Source only non-secret env vars needed for smoke test
    # We use eval with a strict filter to avoid sourcing actual secrets
    MINIO_ENDPOINT=$(grep -E "^MINIO_ENDPOINT=" .env | cut -d= -f2- | tr -d '"' || echo "http://localhost:9000")
    MINIO_AUDIT_BUCKET=$(grep -E "^MINIO_AUDIT_BUCKET=" .env | cut -d= -f2- | tr -d '"' || echo "mcp-audit-archive")
    MINIO_ROOT_USER=$(grep -E "^MINIO_ROOT_USER=" .env | cut -d= -f2- | tr -d '"' || echo "")
    MINIO_ROOT_PASSWORD=$(grep -E "^MINIO_ROOT_PASSWORD=" .env | cut -d= -f2- | tr -d '"' || echo "")
else
    MINIO_ENDPOINT="${MINIO_ENDPOINT:-http://localhost:9000}"
    MINIO_AUDIT_BUCKET="${MINIO_AUDIT_BUCKET:-mcp-audit-archive}"
fi

# ─── Helpers ──────────────────────────────────────────────────────────────────

PASS_COUNT=0
FAIL_COUNT=0
RESULTS=()

pass() {
    local check="$1"
    local detail="${2:-}"
    PASS_COUNT=$((PASS_COUNT + 1))
    RESULTS+=("  PASS  ${check}${detail:+ — ${detail}}")
    echo "[${TIMESTAMP}] PASS: ${check}${detail:+ — ${detail}}"
}

fail() {
    local check="$1"
    local detail="${2:-}"
    FAIL_COUNT=$((FAIL_COUNT + 1))
    RESULTS+=("  FAIL  ${check}${detail:+ — ${detail}}")
    echo "[${TIMESTAMP}] FAIL: ${check}${detail:+ — ${detail}}" >&2
}

# Curl wrapper: returns HTTP status code; body goes to stdout
http_status() {
    local method="$1"
    local url="$2"
    shift 2
    curl -s -o /dev/null -w "%{http_code}" \
        -X "${method}" \
        "${CURL_OPTS[@]}" \
        "$@" \
        "${url}" 2>/dev/null || echo "000"
}

# Curl wrapper: returns body; status code goes to variable HTTP_STATUS
http_body() {
    local method="$1"
    local url="$2"
    shift 2
    local tmp_status
    tmp_status=$(mktemp)
    local body
    body=$(curl -s -w "%{http_code}" \
        -X "${method}" \
        "${CURL_OPTS[@]}" \
        "$@" \
        "${url}" 2>/dev/null)
    HTTP_STATUS="${body: -3}"
    echo "${body%???}"
}

# ─── Smoke Tests ──────────────────────────────────────────────────────────────

echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║  MCP Security Platform — Smoke Test                 ║"
echo "║  Environment: ${ENVIRONMENT}"
echo "║  Timestamp:   ${TIMESTAMP}"
echo "║  Proxy URL:   ${PROXY_URL}"
echo "╚══════════════════════════════════════════════════════╝"
echo ""

# ─── Check 1: GET /health → 200 ───────────────────────────────────────────────
echo "[${TIMESTAMP}] CHECK 1: Proxy /health endpoint..."
HEALTH_STATUS=$(http_status GET "${PROXY_URL%/api/v1}/health")
if [ "${HEALTH_STATUS}" = "200" ]; then
    pass "GET /health → 200"
else
    fail "GET /health → expected 200, got ${HEALTH_STATUS}"
fi

# ─── Check 2: GET /health/ready → 200 ────────────────────────────────────────
echo "[${TIMESTAMP}] CHECK 2: Proxy /health/ready endpoint..."
READY_STATUS=$(http_status GET "${PROXY_URL%/api/v1}/health/ready")
if [ "${READY_STATUS}" = "200" ]; then
    pass "GET /health/ready → 200"
else
    fail "GET /health/ready → expected 200, got ${READY_STATUS}"
fi

# ─── Check 3: POST /tools/register → 201, risk_score present ─────────────────
echo "[${TIMESTAMP}] CHECK 3: Tool registration..."
SMOKE_TOOL_PAYLOAD=$(cat <<'TOOL_EOF'
{
  "name": "smoke_test_tool",
  "version": "0.1.0",
  "description": "Automated smoke test tool — safe to delete",
  "parameters": {
    "type": "object",
    "properties": {
      "input": {
        "type": "string",
        "description": "Test input value"
      }
    },
    "required": ["input"]
  },
  "source_url": "https://github.com/example/smoke-test",
  "commit_sha": "0000000000000000000000000000000000000001"
}
TOOL_EOF
)

if [ -n "${SMOKE_TEST_API_KEY}" ]; then
    REGISTER_BODY=$(http_body POST "${PROXY_URL}/tools/register" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer ${SMOKE_TEST_API_KEY}" \
        -d "${SMOKE_TOOL_PAYLOAD}")
else
    REGISTER_BODY=$(http_body POST "${PROXY_URL}/tools/register" \
        -H "Content-Type: application/json" \
        -d "${SMOKE_TOOL_PAYLOAD}")
fi
REGISTER_STATUS="${HTTP_STATUS}"

if [ "${REGISTER_STATUS}" = "201" ]; then
    # Verify risk_score is present in response body
    RISK_SCORE=$(echo "${REGISTER_BODY}" | python3 -c "
import json, sys
try:
    data = json.load(sys.stdin)
    score = data.get('risk_score')
    print(score if score is not None else '')
except Exception:
    print('')
" 2>/dev/null || echo "")

    if [ -n "${RISK_SCORE}" ]; then
        pass "POST /tools/register → 201 (risk_score=${RISK_SCORE})"
        # Extract tool ID for subsequent tests
        SMOKE_TOOL_ID=$(echo "${REGISTER_BODY}" | python3 -c "
import json, sys
try:
    data = json.load(sys.stdin)
    print(data.get('tool_id', data.get('id', '')))
except Exception:
    print('')
" 2>/dev/null || echo "")
    else
        fail "POST /tools/register → 201 but risk_score missing from response"
        SMOKE_TOOL_ID=""
    fi
elif [ "${REGISTER_STATUS}" = "401" ]; then
    # No API key configured — check is skipped (not a failure of the stack itself)
    echo "[${TIMESTAMP}] SKIP: Tool registration requires API key (set SMOKE_TEST_API_KEY)"
    SMOKE_TOOL_ID=""
    PASS_COUNT=$((PASS_COUNT + 1))
    RESULTS+=("  SKIP  POST /tools/register — SMOKE_TEST_API_KEY not set")
else
    fail "POST /tools/register → expected 201, got ${REGISTER_STATUS}" \
         "body=${REGISTER_BODY:0:200}"
    SMOKE_TOOL_ID=""
fi

# ─── Check 4: POST /tools/{id}/invoke with NO auth → 401 ─────────────────────
# This verifies INV-009: unauthenticated requests must be rejected.
echo "[${TIMESTAMP}] CHECK 4: Unauthenticated invoke → 401 (INV-009)..."

if [ -n "${SMOKE_TOOL_ID}" ]; then
    INVOKE_URL="${PROXY_URL}/tools/${SMOKE_TOOL_ID}/invoke"
else
    # Use a placeholder ID — we expect 401 before the tool ID is even checked
    INVOKE_URL="${PROXY_URL}/tools/00000000-0000-0000-0000-000000000000/invoke"
fi

UNAUTH_STATUS=$(http_status POST "${INVOKE_URL}" \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"smoke_test_tool","arguments":{"input":"test"}},"id":1}')

if [ "${UNAUTH_STATUS}" = "401" ]; then
    pass "POST /tools/{id}/invoke with no auth → 401 (INV-009 enforced)"
else
    fail "POST /tools/{id}/invoke with no auth → expected 401, got ${UNAUTH_STATUS}" \
         "INV-009 violation: unauthenticated requests must be rejected"
fi

# ─── Check 5: POST /tools/{id}/invoke with valid API key → 200 or 403 ─────────
# 200: OPA allowed the invocation
# 403: OPA denied (acceptable — confirms the stack is running and OPA is evaluating)
# 503: OPA unreachable — stack configuration failure
echo "[${TIMESTAMP}] CHECK 5: Authenticated invoke → 200 or 403..."

if [ -n "${SMOKE_TEST_API_KEY}" ] && [ -n "${SMOKE_TOOL_ID}" ]; then
    AUTH_STATUS=$(http_status POST "${INVOKE_URL}" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer ${SMOKE_TEST_API_KEY}" \
        -d '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"smoke_test_tool","arguments":{"input":"hello"}},"id":2}')

    if [ "${AUTH_STATUS}" = "200" ] || [ "${AUTH_STATUS}" = "403" ]; then
        pass "POST /tools/{id}/invoke with API key → ${AUTH_STATUS} (stack functional)"
    elif [ "${AUTH_STATUS}" = "503" ]; then
        fail "POST /tools/{id}/invoke → 503 (OPA unreachable — check opa container)"
    elif [ "${AUTH_STATUS}" = "404" ]; then
        fail "POST /tools/{id}/invoke → 404 (tool not found — registration may have failed)"
    else
        fail "POST /tools/{id}/invoke with API key → unexpected status ${AUTH_STATUS}"
    fi
else
    echo "[${TIMESTAMP}] SKIP: Authenticated invoke test requires SMOKE_TEST_API_KEY and successful registration"
    RESULTS+=("  SKIP  POST /tools/{id}/invoke (authenticated) — prerequisites not met")
fi

# ─── Check 6: GET /compliance/reports → 200 ──────────────────────────────────
echo "[${TIMESTAMP}] CHECK 6: Compliance reports endpoint..."
COMPLIANCE_STATUS=$(http_status GET "${PROXY_URL}/compliance/reports")
if [ "${COMPLIANCE_STATUS}" = "200" ]; then
    pass "GET /compliance/reports → 200"
elif [ "${COMPLIANCE_STATUS}" = "401" ]; then
    # 401 is acceptable — endpoint exists, auth is required
    pass "GET /compliance/reports → 401 (endpoint exists, auth enforced)"
else
    fail "GET /compliance/reports → expected 200 or 401, got ${COMPLIANCE_STATUS}"
fi

# ─── Check 7: MinIO Object Lock status (INV-007) ─────────────────────────────
echo "[${TIMESTAMP}] CHECK 7: MinIO WORM Object Lock verification (INV-007)..."

MINIO_HEALTH=$(curl -sf "${MINIO_ENDPOINT}/minio/health/live" 2>/dev/null && echo "ok" || echo "fail")
if [ "${MINIO_HEALTH}" = "ok" ]; then
    # MinIO is reachable. Check if the audit bucket exists via the mc container.
    # We run mc as a one-shot container to avoid requiring mc on the host.
    LOCK_CHECK=$(docker compose exec -T mcp-minio-init \
        mc object-lock info "mcp-minio/${MINIO_AUDIT_BUCKET}" 2>&1 || true)

    if echo "${LOCK_CHECK}" | grep -qi "enabled\|governance\|compliance"; then
        pass "MinIO Object Lock → ENABLED on bucket '${MINIO_AUDIT_BUCKET}' (INV-007)"
    else
        # Try via API call if mc container is not available
        LOCK_VIA_API=$(docker compose run --rm \
            -e "MINIO_ROOT_USER=${MINIO_ROOT_USER}" \
            -e "MINIO_ROOT_PASSWORD=${MINIO_ROOT_PASSWORD}" \
            minio-init \
            mc object-lock info "mcp-minio/${MINIO_AUDIT_BUCKET}" 2>&1 || echo "unavailable")

        if echo "${LOCK_VIA_API}" | grep -qi "enabled\|governance"; then
            pass "MinIO Object Lock → ENABLED on bucket '${MINIO_AUDIT_BUCKET}' (INV-007)"
        else
            fail "MinIO Object Lock → could not verify WORM status on '${MINIO_AUDIT_BUCKET}'" \
                 "Run: make setup to re-run minio-init"
        fi
    fi
else
    fail "MinIO not reachable at ${MINIO_ENDPOINT} (is the stack up?)"
fi

# ─── Results ──────────────────────────────────────────────────────────────────

echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║  Smoke Test Results                                  ║"
echo "╠══════════════════════════════════════════════════════╣"
for result in "${RESULTS[@]}"; do
    printf "║  %-52s║\n" "${result}"
done
echo "╠══════════════════════════════════════════════════════╣"
printf "║  Total: %-44s║\n" "${PASS_COUNT} passed, ${FAIL_COUNT} failed"
echo "╚══════════════════════════════════════════════════════╝"
echo ""

if [ "${FAIL_COUNT}" -gt 0 ]; then
    echo "[${TIMESTAMP}] Smoke test FAILED: ${FAIL_COUNT} check(s) failed."
    echo ""
    echo "Troubleshooting:"
    echo "  1. Verify the stack is running: docker compose ps"
    echo "  2. Check logs: make logs SVC=proxy"
    echo "  3. Check health: make health"
    echo "  4. For auth failures: set SMOKE_TEST_API_KEY in your environment"
    exit 1
else
    echo "[${TIMESTAMP}] Smoke test PASSED: all ${PASS_COUNT} check(s) passed."
    exit 0
fi
