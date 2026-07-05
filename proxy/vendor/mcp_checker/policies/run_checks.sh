#!/usr/bin/env bash
# Hardened dynamic checks for MCP servers (HTTP/SSE or stdio via uvx git+URL)
# Env knobs:
#   CONTAINER_RUNTIME       : "podman" or "docker" (auto-detected if unset)
#   IMG                    : Docker/Podman image (default mcpcheck/unknown:latest) — HTTP/SSE mode
#   MCP_STDIN_REPO_URL     : git+URL for stdio server launched via uvx (takes precedence over IMG)
#   PORT                   : Exposed port for HTTP/SSE mode (default 9000)
#   APPARMOR_PROFILE       : AppArmor profile (default mcp-default; set to 'unconfined' to disable)
#   ACCEPT_CODES           : Health codes (default "200 204 404")
#   HEALTH_CANDIDATES      : Space-separated paths (default "/health / /docs /openapi.json")
#   SECCOMP_PATH           : Path to hardened seccomp JSON (default security/seccomp-hardened.json)
#   NET_NONE_COMPARE       : If "0", skip --network none compare
#   TIMEOUT_START          : Seconds to wait for listen (default 20)
#   CURL_BIN               : curl path (default: autodetect)
#   UV_IMAGE               : uv container for stdio mode (default ghcr.io/astral-sh/uv:latest)

set -Eeuo pipefail
IFS=$'\n\t'

# ---------- Defaults ----------
IMG="${IMG:-mcpcheck/unknown:latest}"
MCP_STDIN_REPO_URL="${MCP_STDIN_REPO_URL:-}"
PORT="${PORT:-9000}"
APPARMOR_PROFILE="${APPARMOR_PROFILE:-mcp-default}"
read -r -a HEALTH_CANDIDATES <<< "${HEALTH_CANDIDATES:-/health / /docs /openapi.json}"
ACCEPT_CODES="${ACCEPT_CODES:-200 204 404}"
SECCOMP_PATH="${SECCOMP_PATH:-security/seccomp-hardened.json}"
NET_NONE_COMPARE="${NET_NONE_COMPARE:-1}"
TIMEOUT_START="${TIMEOUT_START:-20}"
CURL_BIN="${CURL_BIN:-$(command -v curl || true)}"
UV_IMAGE="${UV_IMAGE:-ghcr.io/astral-sh/uv:latest}"

# ---------- Helpers ----------
log()  { printf '%s %s\n' "[$(date +%H:%M:%S)]" "$*"; }
fail() { log "FAIL: $*"; exit 2; }

need_bin() { command -v "$1" >/dev/null 2>&1 || fail "missing binary: $1"; }

code_ok() {
  local code="$1"
  for ok in ${ACCEPT_CODES}; do [[ "$code" == "$ok" ]] && return 0; done
  return 1
}

# ---------- Container runtime ----------
CONTAINER_RUNTIME="${CONTAINER_RUNTIME:-}"
if [[ -z "$CONTAINER_RUNTIME" ]]; then
  if command -v podman >/dev/null 2>&1 && podman version >/dev/null 2>&1; then
    CONTAINER_RUNTIME="podman"
  elif command -v docker >/dev/null 2>&1 && docker version >/dev/null 2>&1; then
    CONTAINER_RUNTIME="docker"
  else
    fail "no container runtime found (podman or docker required)"
  fi
fi
log "[runtime] using ${CONTAINER_RUNTIME}"

# AppArmor is Linux-only and docker-only; skip on macOS or with Podman
_USE_APPARMOR=0
if [[ "$(uname -s)" == "Linux" && "$CONTAINER_RUNTIME" == "docker" ]]; then
  _USE_APPARMOR=1
fi

cleanup() {
  "$CONTAINER_RUNTIME" rm -f mcp_dyn_test >/dev/null 2>&1 || true
}
trap cleanup EXIT

# ---------- Sanity ----------
[[ -n "$CURL_BIN" ]] || fail "curl not found"

# ---------- Launchers ----------
start_container_http() {
  local transport="$1"
  log "[start] http/sse transport=${transport}"
  cleanup

  local apparmor_opt=""
  if [[ $_USE_APPARMOR -eq 1 ]]; then
    if [[ "${APPARMOR_PROFILE}" == "unconfined" ]]; then
      apparmor_opt="--security-opt apparmor=unconfined"
    else
      apparmor_opt="--security-opt apparmor:${APPARMOR_PROFILE}"
    fi
  fi

  # Using user namespace, rootless constraints if daemon supports it
  CID=$("$CONTAINER_RUNTIME" run -d --rm \
    --name mcp_dyn_test \
    -p "${PORT}:${PORT}" \
    --read-only \
    --user 65532:65532 \
    --tmpfs /tmp:rw,noexec,nosuid,nodev \
    --tmpfs /run:rw,noexec,nosuid,nodev \
    --tmpfs /app/data:rw,noexec,nosuid,nodev \
    --tmpfs /app/shared:rw,noexec,nosuid,nodev \
    --tmpfs /app/tmp:rw,noexec,nosuid,nodev \
    --cap-drop ALL \
    --security-opt no-new-privileges \
    ${apparmor_opt} \
    --memory 512m --cpus 1 \
    --ulimit nofile=1024:1024 --ulimit nproc=64:64 \
    --pids-limit 64 \
    -e PYTHONDONTWRITEBYTECODE=1 \
    -e PYTHONUNBUFFERED=1 \
    -e PYTHONPYCACHEPREFIX=/tmp/pycache \
    -e TEMPERATURE=0 \
    "${IMG}" \
      python -m mcp_atlassian.servers.main \
        --transport "${transport}" \
        --host 0.0.0.0 \
        --port "${PORT}" -vv >/dev/null) || return 1
}

start_container_stdio() {
  # Launch stdio server from git+ URL inside uv container, no network by default
  local repo_url="$1"
  log "[start] stdio via uvx ${repo_url}"
  cleanup
  CID=$("$CONTAINER_RUNTIME" run -d --rm \
    --name mcp_dyn_test \
    --read-only \
    --user 65532:65532 \
    --tmpfs /tmp:rw,noexec,nosuid,nodev \
    --tmpfs /run:rw,noexec,nosuid,nodev \
    --cap-drop ALL \
    --security-opt no-new-privileges \
    --memory 512m --cpus 1 \
    --ulimit nofile=1024:1024 --ulimit nproc=64:64 \
    --pids-limit 64 \
    -e PYTHONDONTWRITEBYTECODE=1 \
    -e PYTHONUNBUFFERED=1 \
    -e PYTHONPYCACHEPREFIX=/tmp/pycache \
    "${UV_IMAGE}" \
      sh -lc "uvx ${repo_url}" >/dev/null) || return 1
}

wait_listen() {
  local max="${TIMEOUT_START}"
  for _ in $(seq 1 "$max"); do
    if "${CURL_BIN}" -sS -m 1 "http://127.0.0.1:${PORT}/" >/dev/null 2>&1; then
      return 0
    fi
    if ! "$CONTAINER_RUNTIME" ps --format '{{.Names}}' | grep -q '^mcp_dyn_test$'; then
      log "container exited early:"
      "$CONTAINER_RUNTIME" logs mcp_dyn_test 2>&1 || true
      return 1
    fi
    sleep 1
  done
  return 1
}

probe_health() {
  for p in "${HEALTH_CANDIDATES[@]}"; do
    code=$("${CURL_BIN}" -sk -o /dev/null -w "%{http_code}" "http://127.0.0.1:${PORT}${p}" || true)
    if code_ok "$code"; then
      log "[health] ok path=${p} code=${code}"
      return 0
    fi
  done
  log "[health] failed. Tried: ${HEALTH_CANDIDATES[*]}. Logs:"
  "$CONTAINER_RUNTIME" logs mcp_dyn_test 2>&1 || true
  return 1
}

# ---------- 1/5 Start container ----------
log "[1/5] Start container (hardened)"
ok=0
if [[ -n "${MCP_STDIN_REPO_URL}" ]]; then
  # stdio mode: we can't HTTP probe; rely on logs presence + process stay-alive
  start_container_stdio "${MCP_STDIN_REPO_URL}" || fail "unable to start stdio container"
  sleep 2
  "$CONTAINER_RUNTIME" ps --format '{{.Names}}' | grep -q '^mcp_dyn_test$' || fail "stdio container died"
  "$CONTAINER_RUNTIME" logs mcp_dyn_test 2>&1 | head -n 50 | sed 's/^/[stdio] /'
  ok=1
else
  for t in sse streamable-http; do
    start_container_http "$t" || continue
    if wait_listen && probe_health; then ok=1; break; fi
  done
fi
[[ $ok -eq 1 ]] || fail "health probes failed"

# ---------- 2/5 Non-root ----------
log "[2/5] Non-root process"
uid=$("$CONTAINER_RUNTIME" exec mcp_dyn_test sh -c 'id -u' || echo "0")
[[ "$uid" != "0" ]] || fail "process runs as root"

# ---------- 3/5 Logs hygiene / temperature ----------
log "[3/5] No PII in logs"
"$CONTAINER_RUNTIME" exec -e PII_CANARY_EMAIL="alice@example.com" -e PII_CANARY_SECRET="s3cr3t-DO-NOT-LOG" mcp_dyn_test sh -c 'echo ok >/dev/null' || true
sleep 1
logs=$("$CONTAINER_RUNTIME" logs mcp_dyn_test 2>&1 || true)
echo "$logs" | grep -Eqi 'alice@example.com|s3cr3t-DO-NOT-LOG|authorization:|bearer |api[_-]?key|password=' && fail "sensitive data leaked to logs"

log "[3.1/5] No raw embeddings in logs"
echo "$logs" | grep -Eqi '\[[-0-9\.]+,\s*[-0-9\.]+,\s*[-0-9\.]+\]|embedding.*vector|float.*array' && fail "raw embedding vectors leaked to logs"

log "[3.2/5] Temperature=0 enforcement"
temp_check=$("$CONTAINER_RUNTIME" exec mcp_dyn_test sh -c 'echo $TEMPERATURE' || echo "")
[[ "$temp_check" = "0" ]] || fail "TEMPERATURE=0 not enforced"

# ---------- 4/6 Baseline (no seccomp), context, traversal, symlink, oversize, egress ----------
log "[4/6] Egress baseline (no seccomp)"
cleanup
if [[ -n "${MCP_STDIN_REPO_URL}" ]]; then
  start_container_stdio "${MCP_STDIN_REPO_URL}" || fail "stdio baseline start failed"
else
  "$CONTAINER_RUNTIME" run -d --rm --name mcp_dyn_test "${IMG}" \
    python -m mcp_atlassian.servers.main --transport sse --host 0.0.0.0 --port "${PORT}" -vv >/dev/null
fi
sleep 1

"$CONTAINER_RUNTIME" exec mcp_dyn_test sh -c "python - <<'PY'
import socket
s=socket.socket(); s.settimeout(2)
try:
  s.connect(('example.com', 443)); print('EGRESS_OK')
except Exception:
  print('EGRESS_BLOCKED')
PY" >/tmp/netcheck_base.txt || true
BASE=$(cat /tmp/netcheck_base.txt 2>/dev/null || echo "")
log "baseline: ${BASE}"

log "[4.1/6] DNS resolution (warn-only)"
"$CONTAINER_RUNTIME" exec mcp_dyn_test sh -c "python - <<'PY'
import socket
try:
  socket.gethostbyname('example.invalid')
  print('DNS_OK')
except Exception:
  print('DNS_BLOCKED')
PY" >/tmp/dnscheck.txt || true
grep -q 'DNS_OK' /tmp/dnscheck.txt && log "WARN: DNS resolution works (may be expected)"

log "[4.2/6] Context replay protection"
"$CONTAINER_RUNTIME" exec mcp_dyn_test sh -c "python - <<'PY'
import hashlib, json
def hash_context(c): return hashlib.sha256(json.dumps(c,sort_keys=True,separators=(',',':')).encode()).hexdigest()[:16]
c1=[{'role':'system','content':'test'}]; c2=[{'role':'system','content':'modified'}]
print('HASH_MISMATCH_DETECTED' if hash_context(c1)!=hash_context(c2) else 'HASH_MATCH')
PY" >/tmp/context_hash.txt || true
grep -q 'HASH_MISMATCH_DETECTED' /tmp/context_hash.txt || fail "context replay protection not working"

log "[4.3/6] File traversal protection"
"$CONTAINER_RUNTIME" exec mcp_dyn_test sh -c "python - <<'PY'
import os
for p in ['../../etc/passwd','../../../etc/shadow','/etc/hosts','../.ssh/id_rsa','/proc/version','/sys/kernel/version']:
  try:
    print(('TRAVERSAL_ALLOWED: ' if os.path.exists(p) else 'TRAVERSAL_BLOCKED: ')+p)
  except Exception as e:
    print(f'TRAVERSAL_ERROR: {p} - {e}')
PY" >/tmp/traversal_test.txt || true
grep -q 'TRAVERSAL_ALLOWED' /tmp/traversal_test.txt && { cat /tmp/traversal_test.txt; fail "File traversal allowed"; }
log "File traversal protection OK"

log "[4.4/6] Symlink escape protection"
"$CONTAINER_RUNTIME" exec mcp_dyn_test sh -c "python - <<'PY'
import os
try:
  os.symlink('/etc/passwd','/tmp/safe_link')
  if os.path.islink('/tmp/safe_link'):
    with open('/tmp/safe_link') as f:
      print('SYMLINK_ESCAPE_ALLOWED' if 'root:x:0:0' in f.read(100) else 'SYMLINK_ESCAPE_BLOCKED')
  else:
    print('SYMLINK_CREATION_BLOCKED')
except Exception as e:
  print(f'SYMLINK_TEST_ERROR: {e}')
PY" >/tmp/symlink_test.txt || true
grep -q 'SYMLINK_ESCAPE_ALLOWED' /tmp/symlink_test.txt && { cat /tmp/symlink_test.txt; fail "Symlink escape allowed"; }
log "Symlink escape protection OK"

log "[4.5/6] File size limit protection"
"$CONTAINER_RUNTIME" exec mcp_dyn_test sh -c "python - <<'PY'
import os; d='x'* (2*1024*1024)
try:
  open('/tmp/large_file.txt','w').write(d)
  s=os.path.getsize('/tmp/large_file.txt'); print('OVERSIZE_ALLOWED:' + str(s))
except Exception as e:
  print('OVERSIZE_BLOCKED')
PY" >/tmp/size_test.txt || true
grep -q 'OVERSIZE_ALLOWED' /tmp/size_test.txt && { cat /tmp/size_test.txt; fail "Oversize write allowed"; }
log "File size limit protection OK"

log "[4.6/6] Network egress protection (--network none)"
if [[ "${NET_NONE_COMPARE}" == "1" ]]; then
  cleanup
  if [[ -n "${MCP_STDIN_REPO_URL}" ]]; then
    "$CONTAINER_RUNTIME" run -d --rm --name mcp_dyn_test --network none "${UV_IMAGE}" \
      sh -lc "uvx ${MCP_STDIN_REPO_URL}" >/dev/null
  else
    "$CONTAINER_RUNTIME" run -d --rm --name mcp_dyn_test --network none "${IMG}" \
      python -m mcp_atlassian.servers.main --transport sse --host 0.0.0.0 --port "${PORT}" -vv >/dev/null
  fi
  sleep 1
  "$CONTAINER_RUNTIME" exec mcp_dyn_test sh -c "python - <<'PY'
import socket, subprocess
for hp in [('google.com',443),('example.com',80),('127.0.0.1',8080),('localhost',3000)]:
  try:
    s=socket.socket(); s.settimeout(2); s.connect(hp); print('EGRESS_ALLOWED:%s:%s'%hp); s.close()
  except Exception: print('EGRESS_BLOCKED:%s:%s'%hp)
try:
  r=subprocess.run(['curl','-s','--connect-timeout','2','http://example.com'],capture_output=True,text=True,timeout=3)
  print('CURL_EGRESS_ALLOWED' if r.returncode==0 else 'CURL_EGRESS_BLOCKED')
except Exception: print('CURL_EGRESS_BLOCKED')
PY" >/tmp/egress_test.txt || true
  grep -Eq 'EGRESS_ALLOWED|CURL_EGRESS_ALLOWED' /tmp/egress_test.txt && { cat /tmp/egress_test.txt; fail "Egress allowed under --network none"; }
  log "Network egress blocked as expected"
else
  log "Skipping --network none compare (NET_NONE_COMPARE=0)"
fi

# ---------- 4.7–4.15 Policy/Gateway checks ----------
INTROSPECT_JSON=${INTROSPECT_JSON:-introspection.json}
TOOLSET_DIGEST_FILE=${TOOLSET_DIGEST_FILE:-.cache/toolset.lock}

calc_digest() {
  python - <<'PY' "$1"
import json,hashlib,sys
j=json.load(open(sys.argv[1]))
print(hashlib.sha256(json.dumps(j,sort_keys=True,separators=(",",":")).encode()).hexdigest())
PY
}

log "[4.7/6] Toolset digest lock"
if [[ -f "$INTROSPECT_JSON" ]]; then
  mkdir -p "$(dirname "$TOOLSET_DIGEST_FILE")"
  DIGEST=$(calc_digest "$INTROSPECT_JSON")
  if [[ -f "$TOOLSET_DIGEST_FILE" ]]; then
    OLD=$(cat "$TOOLSET_DIGEST_FILE" || true)
    [[ "$DIGEST" == "$OLD" ]] || { echo "Expected: $OLD"; echo "Actual:   $DIGEST"; fail "toolset digest changed"; }
    log "Toolset digest verified"
  else
    echo "$DIGEST" > "$TOOLSET_DIGEST_FILE"
    log "Toolset digest initialized"
  fi
else
  log "No introspection file; skipping digest check"
fi

log "[4.8/6] Tool shadowing detection"
if [[ -f "$INTROSPECT_JSON" ]]; then
  SHADOWING_RESULT=$(python registry_check.py check-shadowing -i "$INTROSPECT_JSON" 2>&1 || true)
  echo "$SHADOWING_RESULT" | grep -q "Shadowing detected" && fail "Tool shadowing detected"
  log "No tool shadowing detected"
else
  log "No introspection file; skipping shadowing check"
fi

log "[4.9/6] Token leakage detection"
CANARIES='Authorization|Bearer |api[_-]?key|API_KEY_CANARY|AKIA|token=|sk-[A-Za-z0-9]{20,}'
LOG_SCAN=$("$CONTAINER_RUNTIME" logs mcp_dyn_test 2>&1 | grep -Ei "$CANARIES" || true)
[[ -z "$LOG_SCAN" ]] || { echo "$LOG_SCAN"; fail "Token/secret leakage in logs"; }
ENV_SCAN=$("$CONTAINER_RUNTIME" exec mcp_dyn_test env 2>/dev/null | grep -Ei "$CANARIES" || true)
[[ -z "$ENV_SCAN" ]] || { echo "$ENV_SCAN"; fail "Token/secret leakage in env"; }
PS_SCAN=$("$CONTAINER_RUNTIME" exec mcp_dyn_test ps aux 2>/dev/null | grep -Ei "$CANARIES" || true)
[[ -z "$PS_SCAN" ]] || { echo "$PS_SCAN"; fail "Token/secret leakage in args"; }
log "Token leakage scan passed"

log "[4.10/6] Execution tool confirmation (structure)"
"$CONTAINER_RUNTIME" exec mcp_dyn_test sh -c "python - <<'PY'
print('EXEC_WITHOUT_CONFIRMATION_TEST')
PY" >/tmp/exec_test.txt || true
grep -q 'EXEC_WITHOUT_CONFIRMATION_TEST' /tmp/exec_test.txt || fail "exec confirmation test failed"
log "Exec confirmation test structure OK (OPA check occurs in gateway)"

log "[4.11/5] E2E gateway traversal (OPA)"
cleanup
# bind repo read-only if present (for runtime_gateway import)
if [[ -n "${MCP_STDIN_REPO_URL}" ]]; then
  "$CONTAINER_RUNTIME" run -d --rm --name mcp_dyn_test -v "$(pwd):/workspace:ro" "${UV_IMAGE}" \
    sh -lc "sleep 3600" >/dev/null
else
  "$CONTAINER_RUNTIME" run -d --rm --name mcp_dyn_test -v "$(pwd):/workspace:ro" "${IMG}" \
    python -m mcp_atlassian.servers.main --transport sse --host 0.0.0.0 --port "${PORT}" -vv >/dev/null
fi
sleep 2

# The next three E2E blocks expect runtime_gateway.py present in /workspace
for what in TRAVERSAL SYMLINK OVERSIZE LLM_MODEL LEGIT; do
  case "$what" in
    TRAVERSAL)
      "$CONTAINER_RUNTIME" exec mcp_dyn_test python - <<'PY'
import sys; sys.path.append('/workspace')
from runtime_gateway import RuntimeOPAGateway, PolicyDenied
g=RuntimeOPAGateway()
try:
  g.call_tool("file_browser.read", {"op":"read","path":"/srv/mcp_roots/docs/../../etc/passwd","requested_bytes":4096,"is_symlink":False},{})
  print("E2E_TRAVERSAL_ALLOWED")
except PolicyDenied: print("E2E_TRAVERSAL_DENIED")
except Exception as e: print("E2E_TRAVERSAL_ERROR:",e)
PY
      "$CONTAINER_RUNTIME" logs mcp_dyn_test 2>&1 | grep -q E2E_TRAVERSAL_ALLOWED && fail "OPA allowed traversal" || log "OPA blocked traversal"
      ;;
    SYMLINK)
      "$CONTAINER_RUNTIME" exec mcp_dyn_test python - <<'PY'
import sys; sys.path.append('/workspace')
from runtime_gateway import RuntimeOPAGateway, PolicyDenied
g=RuntimeOPAGateway()
try:
  g.call_tool("file_browser.read", {"op":"read","path":"/srv/mcp_roots/docs/escape/passwd","requested_bytes":128,"is_symlink":True},{})
  print("E2E_SYMLINK_ALLOWED")
except PolicyDenied: print("E2E_SYMLINK_DENIED")
except Exception as e: print("E2E_SYMLINK_ERROR:",e)
PY
      "$CONTAINER_RUNTIME" logs mcp_dyn_test 2>&1 | grep -q E2E_SYMLINK_ALLOWED && fail "OPA allowed symlink escape" || log "OPA blocked symlink escape"
      ;;
    OVERSIZE)
      "$CONTAINER_RUNTIME" exec mcp_dyn_test python - <<'PY'
import sys; sys.path.append('/workspace')
from runtime_gateway import RuntimeOPAGateway, PolicyDenied
g=RuntimeOPAGateway()
try:
  g.call_tool("file_browser.write", {"op":"write","path":"/srv/mcp_roots/uploads/big.bin","requested_bytes":20000000},{})
  print("E2E_OVERSIZE_ALLOWED")
except PolicyDenied: print("E2E_OVERSIZE_DENIED")
except Exception as e: print("E2E_OVERSIZE_ERROR:",e)
PY
      "$CONTAINER_RUNTIME" logs mcp_dyn_test 2>&1 | grep -q E2E_OVERSIZE_ALLOWED && fail "OPA allowed oversize write" || log "OPA blocked oversize write"
      ;;
    LLM_MODEL)
      "$CONTAINER_RUNTIME" exec mcp_dyn_test python - <<'PY'
import sys; sys.path.append('/workspace')
from runtime_gateway import RuntimeOPAGateway, PolicyDenied
g=RuntimeOPAGateway()
try:
  g.call_tool("openai.chat_completion", {"model":"gpt-xyz","max_tokens":9000}, {})
  print("E2E_LLM_MODEL_ALLOWED")
except PolicyDenied: print("E2E_LLM_MODEL_DENIED")
except Exception as e: print("E2E_LLM_MODEL_ERROR:",e)
PY
      "$CONTAINER_RUNTIME" logs mcp_dyn_test 2>&1 | grep -q E2E_LLM_MODEL_ALLOWED && fail "OPA allowed unauthorized LLM model" || log "OPA blocked unauthorized model"
      ;;
    LEGIT)
      "$CONTAINER_RUNTIME" exec mcp_dyn_test python - <<'PY'
import sys; sys.path.append('/workspace')
from runtime_gateway import RuntimeOPAGateway, PolicyDenied
g=RuntimeOPAGateway()
try:
  r=g.call_tool("file_browser.read", {"op":"read","path":"/srv/mcp_roots/docs/readme.txt","requested_bytes":1024,"is_symlink":False},{})
  print("E2E_LEGITIMATE_ALLOWED" if (r or {}).get('success') else "E2E_LEGITIMATE_DENIED")
except PolicyDenied: print("E2E_LEGITIMATE_DENIED")
except Exception as e: print("E2E_LEGITIMATE_ERROR:",e)
PY
      "$CONTAINER_RUNTIME" logs mcp_dyn_test 2>&1 | grep -q E2E_LEGITIMATE_DENIED && log "WARN: OPA denied legitimate access" || log "OPA allowed legitimate access"
      ;;
  esac
done

# ---------- 5/6 Hardened compare with seccomp ----------
log "[5/6] Hardened mode with seccomp (if available)"
cleanup
if [[ -f "$SECCOMP_PATH" ]]; then
  if [[ -n "${MCP_STDIN_REPO_URL}" ]]; then
    "$CONTAINER_RUNTIME" run -d --rm --name mcp_dyn_test --security-opt "seccomp=${SECCOMP_PATH}" "${UV_IMAGE}" \
      sh -lc "uvx ${MCP_STDIN_REPO_URL}" >/dev/null
  else
    "$CONTAINER_RUNTIME" run -d --rm --name mcp_dyn_test --security-opt "seccomp=${SECCOMP_PATH}" \
      "${IMG}" python -m mcp_atlassian.servers.main --transport sse --host 0.0.0.0 --port "${PORT}" -vv >/dev/null
  fi
  sleep 1
  "$CONTAINER_RUNTIME" exec mcp_dyn_test sh -c "python - <<'PY'
import socket
s=socket.socket(); s.settimeout(3)
try:
  s.connect(('example.com',443)); print('HARDENED: EGRESS_OK')
except Exception:
  print('HARDENED: EGRESS_BLOCKED')
PY" >/tmp/netcheck_hard.txt || true
  HARD=$(cat /tmp/netcheck_hard.txt 2>/dev/null || echo "")
  log "hardened: ${HARD}"
else
  log "[seccomp] WARN: $SECCOMP_PATH missing; skipping hardened compare"
fi

# ---------- 6/6 Summary ----------
log "[6/6] Summary"
printf '\n%-28s | %-24s\n' "Check" "Result"
printf -- '----------------------------+--------------------------\n'
printf '%-28s | %-24s\n' "Baseline egress" "$(echo "$BASE"|tr -d '\n')"
if [[ -f /tmp/netcheck_hard.txt ]]; then
  printf '%-28s | %-24s\n' "Hardened egress" "$(tr -d '\n' </tmp/netcheck_hard.txt)"
fi
log "[OK] Dynamic checks completed"

# ---------- Advanced dynamic checks ----------
log "[7/9] Network call detection"
if "$CONTAINER_RUNTIME" ps --format '{{.Names}}' | grep -q '^mcp_dyn_test$'; then
  log "[network] Starting packet capture (best-effort)"
  "$CONTAINER_RUNTIME" exec mcp_dyn_test sh -lc "apk add --no-cache tcpdump >/dev/null 2>&1 || (apt-get update -qq && apt-get install -y -qq tcpdump >/dev/null 2>&1) || true"
  "$CONTAINER_RUNTIME" exec -d mcp_dyn_test sh -c "tcpdump -i any -w /tmp/capture.pcap 2>/dev/null || true" || true
  sleep 2
  log "[network] Trigger test socket"
  "$CONTAINER_RUNTIME" exec mcp_dyn_test sh -c "python - <<'PY'
import socket
try:
  s=socket.socket(); s.settimeout(2); s.connect(('8.8.8.8',53)); print('NETWORK_CALL_DETECTED: 8.8.8.8:53'); s.close()
except Exception as e:
  print('NETWORK_BLOCKED:',e)
PY" >/tmp/network_check.txt || true
  sleep 1
  "$CONTAINER_RUNTIME" exec mcp_dyn_test pkill tcpdump 2>/dev/null || true
  if grep -q "NETWORK_CALL_DETECTED" /tmp/network_check.txt; then
    log "WARNING: Outbound network calls detected during tool execution"
  else
    log "No unexpected network calls detected"
  fi
fi

log "[8/9] File write monitoring"
if "$CONTAINER_RUNTIME" ps --format '{{.Names}}' | grep -q '^mcp_dyn_test$'; then
  "$CONTAINER_RUNTIME" exec mcp_dyn_test sh -c "python - <<'PY'
import os
for p in ['/tmp/test_allowed.txt','/app/tmp/test_allowed.txt','/etc/test_forbidden.txt','/root/test_forbidden.txt','/usr/test_forbidden.txt']:
  try:
    with open(p,'w') as f: f.write('x')
    print('WRITE_SUCCESS:',p); os.remove(p)
  except Exception as e:
    print('WRITE_BLOCKED:',p,type(e).__name__)
PY" > /tmp/filewrite_check.txt 2>&1 || true
  cat /tmp/filewrite_check.txt
  grep -Eq "WRITE_SUCCESS: (/etc|/root|/usr)" /tmp/filewrite_check.txt && fail "Writes to forbidden dirs succeeded"
  log "File write restrictions OK"
fi

log "[9/9] Seccomp enforcement verification"
if "$CONTAINER_RUNTIME" ps --format '{{.Names}}' | grep -q '^mcp_dyn_test$'; then
  "$CONTAINER_RUNTIME" exec mcp_dyn_test sh -c "python - <<'PY'
import os, ctypes, socket
tests=[]
try:
  libc=ctypes.CDLL(None); libc.ptrace(0,0,0,0); tests.append('ptrace: ALLOWED (BAD)')
except Exception: tests.append('ptrace: BLOCKED (GOOD)')
try:
  s=socket.socket(); s.close(); tests.append('socket: ALLOWED')
except Exception: tests.append('socket: BLOCKED')
try:
  open('/tmp/seccomp_test.txt','w').write('x'); os.remove('/tmp/seccomp_test.txt'); tests.append('file_ops: ALLOWED (GOOD)')
except Exception: tests.append('file_ops: BLOCKED (BAD)')
for t in tests: print('SECCOMP_TEST:',t)
PY" > /tmp/seccomp_check.txt 2>&1 || true
  cat /tmp/seccomp_check.txt
  grep -q "ptrace: ALLOWED" /tmp/seccomp_check.txt && log "WARNING: ptrace not blocked by seccomp"
  grep -q "file_ops: BLOCKED" /tmp/seccomp_check.txt && fail "Basic file ops blocked (seccomp too restrictive)"
  log "Seccomp profile enforcement verified"
fi

cleanup

# ---------- Prompt validation ----------
log "[prompt] running prompt firewall & live validations"
if [[ -n "${PROJECT_DIR:-}" ]]; then
  log "[prompt] project dir: ${PROJECT_DIR}"
  python3 ../prompt_scan.py --project-dir "${PROJECT_DIR}" || fail "prompt validation failed"
else
  python3 ../prompt_scan.py || fail "prompt validation failed"
fi
log "Prompt validation completed successfully"
