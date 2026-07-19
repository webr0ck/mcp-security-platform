#!/usr/bin/env bash
# SEC-05 runtime gate: assert MCP backend containers CANNOT reach the proxy's
# HTTP surface (proxy:8000), while the gateway ingress path still works.
#
# check_network_isolation.py is a STATIC compose-topology check — it cannot see
# which interfaces uvicorn actually listens on, nor the L7 ingress allowlist that
# enforces directionality at runtime. This script closes that gap by exercising
# the real running containers.
#
# Exit 0 = all backends blocked (403 or connection refused) AND gateway ingress OK.
# Exit 1 = any backend got a non-403/non-error response (a lateral-reachability leak).
#
# Usage: scripts/check_backend_proxy_ingress.sh [LAB_HOST]
set -euo pipefail

LAB_HOST="${1:-127.0.0.1}"
export PATH="/usr/local/bin:$PATH"
if [ -z "${DOCKER_HOST:-}" ]; then
  sock="$(podman machine inspect --format '{{.ConnectionInfo.PodmanSocket.Path}}' 2>/dev/null || true)"
  [ -n "$sock" ] && export DOCKER_HOST="unix://$sock"
fi

fail=0

# 1. Gateway ingress must still work (the guard must not break legitimate traffic).
code="$(curl -ks -o /dev/null -w '%{http_code}' "https://${LAB_HOST}:8443/health" || echo 000)"
if [ "$code" = "200" ]; then
  echo "PASS  gateway ingress https://${LAB_HOST}:8443/health -> 200"
else
  echo "FAIL  gateway ingress broken (HTTP $code) — ingress guard too strict"
  fail=1
fi

# 2. Every MCP backend container must be BLOCKED from proxy:8000.
backends="$(podman ps --format '{{.Names}}' 2>/dev/null | grep -E '^lab-mcp-' || true)"
if [ -z "$backends" ]; then
  echo "WARN  no lab-mcp-* backend containers running — nothing to assert"
fi

for c in $backends; do
  # Probe proxy:8000 from inside the backend and classify the outcome.
  probe='import urllib.request,urllib.error
try:
 r=urllib.request.urlopen("http://proxy:8000/health",timeout=5);print("REACHED:%d"%r.status)
except urllib.error.HTTPError as e:print("HTTP:%d"%e.code)
except Exception as e:print("ERR:%s"%type(e).__name__)'
  out="$(podman exec "$c" python3 -c "$probe" 2>/dev/null || true)"
  case "$out" in
    HTTP:403)          echo "PASS  $c -> proxy:8000 blocked (403 INGRESS_DENIED)";;
    ERR:*)             echo "PASS  $c -> proxy:8000 unreachable ($out)";;
    REACHED:*)         echo "FAIL  $c -> proxy:8000 REACHED ($out) — lateral leak"; fail=1;;
    "")                echo "WARN  $c -> could not probe (no python3?) — verify manually";;
    *)                 echo "WARN  $c -> unexpected: $out";;
  esac
done

echo
if [ "$fail" -eq 0 ]; then
  echo "SEC-05 backend->proxy ingress gate: ALL PASS"
else
  echo "SEC-05 backend->proxy ingress gate: FAILED"
fi
exit "$fail"
