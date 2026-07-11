#!/usr/bin/env bash
# mtls_agent_identity.sh — PRD-0006 R-2 setup + smoke test for the lab mTLS
# agent-identity path (step-ca client cert -> nginx verify -> agent:{ca}:{cn}).
#
# Idempotent SETUP (safe to re-run): extracts the step-ca root CA, generates the
# gitignored X-Gateway-Secret include from GATEWAY_SHARED_SECRET, and mints a
# short-lived agent client cert — the three gitignored artifacts the mTLS lab
# nginx conf needs. Then SMOKE-TESTS the full path.
#
# Usage: bash lab/tests/mtls_agent_identity.sh
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BASE="${BASE:-https://100.119.138.35:8443}"
# :8443's ssl_verify_client is 'off' (an optional client-cert request during
# the TLS handshake broke Windows Schannel-based MCP clients) — the actual
# mTLS-required /api/v1/tools/ path now lives on its own listener instead.
MTLS_BASE="${MTLS_BASE:-https://100.119.138.35:8445}"
CERTS="$ROOT/lab/nginx/lab-certs"
SECRETS="$ROOT/lab/nginx/secrets"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
PASS=0; FAIL=0
ok()  { echo "  ✓ $1"; PASS=$((PASS+1)); }
bad() { echo "  ✗ $1"; FAIL=$((FAIL+1)); }
chk() { [ "$1" = "$2" ] && ok "$3 ($1)" || bad "$3 (want $2 got $1)"; }

echo "== R-2 mTLS agent-identity setup + smoke =="

# --- setup (idempotent) ---
mkdir -p "$CERTS" "$SECRETS"
# nginx's ssl_client_certificate needs the FULL chain, not just the root —
# step ca certificate issues agent certs signed by the intermediate CA, and
# nginx (unlike a browser) won't fetch/complete an intermediate on its own.
# Root-only here previously chain-verified as: intermediate-signed leaf ->
# untrusted intermediate -> 400 "The SSL certificate error" for every
# freshly minted agent cert.
podman exec mcp-step-ca cat /home/step/certs/intermediate_ca.crt /home/step/certs/root_ca.crt > "$CERTS/step-ca-root.crt"
[ -s "$CERTS/step-ca-root.crt" ] && ok "step-ca root+intermediate CA chain extracted" || { bad "CA extract"; exit 1; }

SECRET=$(grep -E '^GATEWAY_SHARED_SECRET=' "$ROOT/.env.lab" | cut -d= -f2)
printf 'proxy_set_header X-Gateway-Secret "%s";\n' "$SECRET" > "$SECRETS/gateway-secret.conf"
ok "gateway-secret include generated"

# Mint a fresh 24h agent client cert from step-ca.
podman exec mcp-step-ca sh -c 'step ca certificate "agent-lab-01" /tmp/a.crt /tmp/a.key \
    --provisioner admin --password-file /home/step/secrets/password --not-after 24h --force >/dev/null 2>&1'
podman exec mcp-step-ca cat /tmp/a.crt > "$WORK/agent.crt"
podman exec mcp-step-ca cat /tmp/a.key > "$WORK/agent.key"
[ -s "$WORK/agent.crt" ] && ok "agent client cert minted (CN=agent-lab-01, 24h)" || { bad "cert mint"; exit 1; }

# nginx must be valid + up
podman exec mcp-gateway nginx -t >/dev/null 2>&1 && ok "gateway nginx config valid" || bad "nginx -t failed"

# --- smoke ---
# 1. OIDC path unbroken (no cert, non-tools path)
code=$(curl -sk -o /dev/null -w '%{http_code}' "$BASE/api/v1/auth/oidc/login?redirect=%2Fportal")
chk "$code" "307" "OIDC login redirect unbroken (no cert)"

# 2. /api/v1/tools/ WITHOUT a client cert -> 401 (both listeners, different
#    layers: :8443 now forwards to the app and gets 401 from AuthMiddleware
#    since no session/bearer is presented either; :8445 still 401s at nginx
#    for lacking a cert).
code=$(curl -sk -o /dev/null -w '%{http_code}' "$BASE/api/v1/tools/list")
chk "$code" "401" "no-cert, no-session /api/v1/tools/ rejected on :8443 (app-layer now)"
code=$(curl -sk -o /dev/null -w '%{http_code}' "$MTLS_BASE/api/v1/tools/list")
chk "$code" "401" "no-cert /api/v1/tools/ rejected by the :8445 mTLS gateway"

# 3. /api/v1/tools/ WITH the agent cert, on the dedicated mTLS listener ->
#    cert accepted; proxy resolves the agent principal and denies via
#    entitlement (fail-closed) => 403, not 401.
code=$(curl -sk --cert "$WORK/agent.crt" --key "$WORK/agent.key" -o /dev/null -w '%{http_code}' "$MTLS_BASE/api/v1/tools/list")
chk "$code" "403" "agent-cert accepted on :8445; unentitled agent fail-closed denied"

# 4. the proxy actually logged the agent principal (client_id=agent-lab-01).
#    The audit event is emitted just after the response; poll briefly.
# NB: grep -c (not -q) — with `set -o pipefail`, grep -q closes the pipe early,
# SIGPIPEs `podman logs`, and the pipeline returns non-zero despite a match.
found=""
for _ in $(seq 1 10); do
  n=$(podman logs --since 180s mcp-proxy 2>&1 | grep -c 'agent-lab-01')
  [ "${n:-0}" -gt 0 ] && { found=1; break; }
  sleep 2
done
[ -n "$found" ] && ok "proxy resolved agent:{ca}:agent-lab-01 principal (audited)" \
                || bad "proxy did not log the agent principal"

echo "== result: $PASS passed, $FAIL failed =="
[ "$FAIL" -eq 0 ]
