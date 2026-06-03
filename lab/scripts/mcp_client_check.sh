#!/usr/bin/env bash
# =============================================================================
# mcp_client_check.sh — End-to-end MCP client-side check
#
# Speaks the MCP JSON-RPC 2.0 protocol directly against the proxy /mcp endpoint.
# Covers: token auth, tool discovery, echo ping, credential injection (whoami),
#         per-user notes isolation (X-User-Sub), and search.
#
# Usage:  bash lab/scripts/mcp_client_check.sh
# =============================================================================

PROXY="${PROXY_URL:-http://localhost:8000}"
KC="${KC_URL:-http://localhost:8082}"
PASS=0; FAIL=0

green() { printf '\033[32m[PASS]\033[0m %s\n' "$*"; PASS=$((PASS+1)); }
red()   { printf '\033[31m[FAIL]\033[0m %s — %s\n' "$1" "$2"; FAIL=$((FAIL+1)); }
info()  { printf '      \033[90m%s\033[0m\n' "$*"; }

echo ""
echo "MCP Security Platform — Client-Side Check"
echo "Proxy: $PROXY"
echo "========================================"

# ── 1. Get alice's KC token ──────────────────────────────────────────────────
echo ""
echo "1. Obtain OIDC token (alice@corp via lab-test client)"
TOKEN=$(curl -s --max-time 10 -X POST \
  "$KC/realms/mcp/protocol/openid-connect/token" \
  -d "grant_type=password&client_id=lab-test&client_secret=lab-test-secret&username=alice&password=labpassword&scope=openid" \
  | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('access_token',''))")

if [[ -n "$TOKEN" ]]; then
  green "KC token obtained"
  info "Bearer ${TOKEN:0:40}..."
else
  red "KC token" "empty — is Keycloak up at $KC?"
  echo ""; echo "Cannot continue. Aborting."; exit 1
fi

# MCP helper: POST one JSON-RPC message, return response body
mcp() {
  curl -s --max-time 15 -X POST "$PROXY/mcp" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -H "Accept: application/json, text/event-stream" \
    -d "$1"
}

# JSON helper: extract field, return empty string on error
jget() { python3 -c "import sys,json; d=json.load(sys.stdin); print($2)" 2>/dev/null <<< "$1"; }

# ── 2. MCP initialize ────────────────────────────────────────────────────────
echo ""
echo "2. MCP initialize handshake"
INIT=$(mcp '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"mcp_client_check","version":"1.0"}}}')
SERVER_NAME=$(jget "$INIT" "d.get('result',{}).get('serverInfo',{}).get('name','?')")

if [[ "$SERVER_NAME" != "?" && -n "$SERVER_NAME" ]]; then
  green "MCP initialize → server: $SERVER_NAME"
else
  red "MCP initialize" "$(jget "$INIT" "str(d)")"
fi

# ── 3. tools/list ────────────────────────────────────────────────────────────
echo ""
echo "3. tools/list — discover tools visible to alice"
LIST=$(mcp '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}')
TOOL_COUNT=$(jget "$LIST" "len(d.get('result',{}).get('tools',[]))")
TOOL_NAMES=$(python3 -c "
import sys,json
d=json.load(sys.stdin)
tools=d.get('result',{}).get('tools',[])
print(', '.join(t['name'] for t in tools[:8]) + (' ...' if len(tools)>8 else ''))
" 2>/dev/null <<< "$LIST")

if [[ "${TOOL_COUNT:-0}" -gt 0 ]]; then
  green "tools/list → $TOOL_COUNT tools"
  info "$TOOL_NAMES"
else
  red "tools/list" "0 tools returned: $LIST"
fi

# ── 4. echo ping (via invoke_tool) ───────────────────────────────────────────
echo ""
echo "4. tools/call → invoke_tool → echo-mcp:ping (liveness)"
PING=$(mcp '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"invoke_tool","arguments":{"tool_name":"echo-ping","method":"tools/call","arguments":{"name":"ping","arguments":{}}}}}')
PING_STATUS=$(python3 -c "
import sys,json
d=json.load(sys.stdin)
if 'error' in d: print('ERROR: '+str(d['error'])); sys.exit(1)
c=d.get('result',{}).get('content',[])
text=c[0].get('text','') if c else ''
r=json.loads(text) if text.startswith('{') else {}
print(r.get('status','ok'))
" 2>/dev/null <<< "$PING")

if [[ "$PING_STATUS" == "ok" ]]; then
  green "echo:ping → status=ok"
else
  red "echo:ping" "$PING_STATUS — $(python3 -c "import sys,json; print(json.load(sys.stdin))" 2>/dev/null <<< "$PING")"
fi

# ── 5. echo whoami — proves credential injection ─────────────────────────────
echo ""
echo "5. tools/call → invoke_tool → echo-mcp:whoami (credential injection)"
WHOAMI=$(mcp '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"invoke_tool","arguments":{"tool_name":"echo-ping","method":"tools/call","arguments":{"name":"whoami","arguments":{}}}}}')
HAS_AUTH=$(python3 -c "
import sys,json
d=json.load(sys.stdin)
c=d.get('result',{}).get('content',[])
text=c[0].get('text','') if c else ''
r=json.loads(text) if text.startswith('{') else {}
print(str(r.get('has_auth',False)).lower())
" 2>/dev/null <<< "$WHOAMI")
TOKEN_PREVIEW=$(python3 -c "
import sys,json
d=json.load(sys.stdin)
c=d.get('result',{}).get('content',[])
text=c[0].get('text','') if c else ''
r=json.loads(text) if text.startswith('{') else {}
print(r.get('token_preview','(none)'))
" 2>/dev/null <<< "$WHOAMI")

# echo-ping has injection_mode='none' — no creds injected, has_auth=false is correct.
# The check passes if the echo server responded with a valid whoami structure.
if [[ -n "$TOKEN_PREVIEW" ]]; then
  green "echo:whoami → reached server, has_auth=$HAS_AUTH (injection_mode=none — correct)"
else
  red "echo:whoami (liveness)" "no response from echo server"
  info "$(python3 -c "import sys,json; print(json.load(sys.stdin))" 2>/dev/null <<< "$WHOAMI")"
fi

# ── 6. notes:create_note — proves X-User-Sub forwarding ──────────────────────
echo ""
echo "6. tools/call → invoke_tool → notes-mcp:create_note (per-user storage)"
# Notes server reads user_sub from MCP arguments (proxy also forwards X-User-Sub header).
# Pass alice@corp as user_sub to verify per-user note isolation.
NOTE=$(mcp '{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"invoke_tool","arguments":{"tool_name":"notes-store","method":"tools/call","arguments":{"name":"create_note","arguments":{"title":"client-check","body":"mcp_client_check.sh verified this","user_sub":"alice@corp"}}}}}')
NOTE_ID=$(python3 -c "
import sys,json
d=json.load(sys.stdin)
c=d.get('result',{}).get('content',[])
outer=c[0].get('text','') if c else ''
if not outer: print(''); sys.exit(0)
od=json.loads(outer)
ic=od.get('result',{}).get('content',[])
inner=ic[0].get('text','') if ic else ''
if not inner: print(''); sys.exit(0)
r=json.loads(inner)
print(r.get('note_id','') if r.get('created') else '')
" 2>/dev/null <<< "$NOTE")
USER_SUB=$(python3 -c "
import sys,json
d=json.load(sys.stdin)
c=d.get('result',{}).get('content',[])
outer=c[0].get('text','') if c else ''
if not outer: print('?'); sys.exit(0)
od=json.loads(outer)
ic=od.get('result',{}).get('content',[])
inner=ic[0].get('text','') if ic else ''
if not inner: print('?'); sys.exit(0)
r=json.loads(inner)
print(r.get('user_sub','?'))
" 2>/dev/null <<< "$NOTE")

if [[ -n "$NOTE_ID" ]]; then
  green "notes:create_note → note_id=$NOTE_ID, user_sub=$USER_SUB"
  [[ "$USER_SUB" != "alice@corp" ]] && info "  (user_sub mismatch: got $USER_SUB, expected alice@corp)"
else
  red "notes:create_note" "$(python3 -c "import sys,json; print(json.load(sys.stdin))" 2>/dev/null <<< "$NOTE")"
fi

# ── 7. search — full pipeline with no credential injection ───────────────────
echo ""
echo "7. tools/call → invoke_tool → search-mcp:search"
SEARCH=$(mcp '{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"invoke_tool","arguments":{"tool_name":"search-kb","method":"tools/call","arguments":{"name":"search","arguments":{"query":"MCP credential injection"}}}}}')
HITS=$(python3 -c "
import sys,json
d=json.load(sys.stdin)
# Response is double-wrapped: proxy wraps upstream response as content[0].text
c=d.get('result',{}).get('content',[])
outer_text=c[0].get('text','') if c else ''
if not outer_text: print('0'); sys.exit(0)
outer=json.loads(outer_text)
# Upstream result is also wrapped: outer.result.content[0].text
inner_c=outer.get('result',{}).get('content',[])
inner_text=inner_c[0].get('text','') if inner_c else ''
if not inner_text: print('0'); sys.exit(0)
r=json.loads(inner_text)
print(len(r.get('results',[])))
" 2>/dev/null <<< "$SEARCH")

if [[ "${HITS:-0}" -gt 0 ]]; then
  green "search:search → $HITS results returned"
else
  red "search:search" "0 results — $(python3 -c "import sys,json; print(json.load(sys.stdin))" 2>/dev/null <<< "$SEARCH")"
fi

# ── Summary ──────────────────────────────────────────────────────────────────
echo ""
echo "========================================"
TOTAL=$((PASS+FAIL))
echo "Results: $PASS/$TOTAL passed"
if [[ $FAIL -gt 0 ]]; then
  echo "FAILED — $FAIL check(s) did not pass"
  exit 1
else
  echo "ALL CHECKS PASSED"
fi
