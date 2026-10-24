#!/usr/bin/env bash
# Full-chain smoke test: auth -> policy -> invoke -> audit. Not just "is the
# port open" — this exercises the SAME choke point
# (mcphub_gateway::invocation::invoke) real traffic goes through, for both
# the allow and deny paths, and then confirms the audit record for the
# invoke actually landed (invariant 4: audit precedes/gates the response,
# so if invoke succeeded the audit row MUST exist).
#
# Usage: smoke_test.sh <env> <gateway_base_url>
# Required env vars (never passed as CLI args — args land in `ps`):
#   SMOKE_CLIENT_ID, SMOKE_CLIENT_SECRET, SMOKE_TOKEN_ENDPOINT
# Exit code: 0 = all checks passed, non-zero = first failure's check number.

set -euo pipefail

ENV_NAME="${1:?usage: smoke_test.sh <env> <gateway_base_url>}"
BASE_URL="${2:?usage: smoke_test.sh <env> <gateway_base_url>}"
: "${SMOKE_CLIENT_ID:?SMOKE_CLIENT_ID must be set}"
: "${SMOKE_CLIENT_SECRET:?SMOKE_CLIENT_SECRET must be set}"
: "${SMOKE_TOKEN_ENDPOINT:?SMOKE_TOKEN_ENDPOINT must be set}"

ts() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }
log() { printf '[%s] [%s] %s\n' "$(ts)" "$ENV_NAME" "$1"; }
fail() { log "FAIL: $1"; exit "${2:-1}"; }

CURL=(curl -sS -k --max-time 10)

# ── 1. Liveness ──────────────────────────────────────────────────────────
log "1/5 checking ${BASE_URL}/health/ready"
STATUS=$("${CURL[@]}" -o /dev/null -w '%{http_code}' "${BASE_URL}/health/ready") || fail "health/ready unreachable" 1
[ "$STATUS" = "200" ] || fail "health/ready returned $STATUS" 1
log "  ok"

# ── 2. Auth: client_credentials against the platform IDP ───────────────────
log "2/5 minting a token via ${SMOKE_TOKEN_ENDPOINT}"
TOKEN_RESPONSE=$("${CURL[@]}" -X POST "$SMOKE_TOKEN_ENDPOINT" \
  -d "grant_type=client_credentials&client_id=${SMOKE_CLIENT_ID}&client_secret=${SMOKE_CLIENT_SECRET}") \
  || fail "token endpoint unreachable" 2
ACCESS_TOKEN=$(printf '%s' "$TOKEN_RESPONSE" | jq -r '.access_token // empty')
[ -n "$ACCESS_TOKEN" ] || fail "no access_token in response: $TOKEN_RESPONSE" 2
log "  ok"

REQ_ID="smoke-$(date +%s)-$$"

# ── 3. Invoke: allowed tool must succeed end to end ─────────────────────────
log "3/5 tools/call on an allowed tool"
ALLOW_RESP=$("${CURL[@]}" -X POST "${BASE_URL}/mcp" \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  -H "Content-Type: application/json" \
  -H "X-Request-Id: ${REQ_ID}-allow" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"smoke-allowed-tool","arguments":{}}}') \
  || fail "invoke (allow) unreachable" 3
echo "$ALLOW_RESP" | jq -e '.result' >/dev/null 2>&1 \
  || fail "allowed tool call did not return .result: $ALLOW_RESP" 3
log "  ok"

# ── 4. Invoke: denied tool must be REJECTED, and via the same fast fail-closed path ──
log "4/5 tools/call on a policy-denied tool (must be rejected, not silently allowed)"
DENY_RESP=$("${CURL[@]}" -X POST "${BASE_URL}/mcp" \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  -H "Content-Type: application/json" \
  -H "X-Request-Id: ${REQ_ID}-deny" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"smoke-denied-tool","arguments":{}}}') \
  || fail "invoke (deny) unreachable" 4
echo "$DENY_RESP" | jq -e '.error' >/dev/null 2>&1 \
  || fail "denied tool call was NOT rejected (fail-open regression!): $DENY_RESP" 4
log "  ok (denied as expected)"

# ── 5. Audit: the allowed invoke above must have produced a durable record ─
log "5/5 confirming an audit record for request ${REQ_ID}-allow"
sleep 1   # audit emission is synchronous per invariant 4, but the query
          # endpoint may lag a beat behind a fresh write under load — this
          # is a smoke test, not a latency assertion (that's loadgen's job).
AUDIT_RESP=$("${CURL[@]}" -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  "${BASE_URL}/api/v1/audit/events?request_id=${REQ_ID}-allow") \
  || fail "audit query unreachable" 5
echo "$AUDIT_RESP" | jq -e '.events[0] // .[0]' >/dev/null 2>&1 \
  || fail "no audit record found for ${REQ_ID}-allow: $AUDIT_RESP" 5
log "  ok"

log "ALL CHECKS PASSED (auth -> policy -> invoke -> audit)"
exit 0
