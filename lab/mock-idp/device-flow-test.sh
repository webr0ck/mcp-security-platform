#!/usr/bin/env bash
# RFC 8628 Device Authorization Grant — end-to-end test
# Two-layer session attestation: IP binding + PKCE-style device_verifier
#
# Usage: ./device-flow-test.sh [idp-base-url]
# Default IdP: http://localhost:8888

IDP="${1:-http://localhost:8888}"

# ── Step 1: generate verifier + challenge ────────────────────────────────
VERIFIER=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
CHALLENGE=$(python3 -c "
import base64, hashlib
v='$VERIFIER'
print(base64.urlsafe_b64encode(hashlib.sha256(v.encode()).digest()).rstrip(b'=').decode())
")

# ── Step 2: request device code ──────────────────────────────────────────
RESP=$(curl -s -X POST "$IDP/oauth/device" \
  -d "client_id=my-cli&device_challenge=$CHALLENGE")

DC=$(echo "$RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['device_code'])")
UC=$(echo "$RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['user_code'])")
VU=$(echo "$RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['verification_uri_complete'])")

echo ""
echo "  User code : $UC"
echo "  Open in browser → $VU"
echo ""
echo "  Waiting for approval (polling every 5s)…"

# ── Step 3: poll until approved ──────────────────────────────────────────
while true; do
  sleep 5
  TOKEN=$(curl -s -X POST "$IDP/oauth/token" \
    -d "grant_type=urn:ietf:params:oauth:grant-type:device_code&device_code=$DC&device_verifier=$VERIFIER&client_id=my-cli")

  ERR=$(echo "$TOKEN" | python3 -c "import sys,json; print(json.load(sys.stdin).get('error',''))" 2>/dev/null)

  if [ "$ERR" = "authorization_pending" ]; then
    echo -n "."
  elif [ -z "$ERR" ]; then
    echo ""
    echo "  Authenticated!"
    echo "$TOKEN" | python3 -c "
import sys, json, base64
d = json.load(sys.stdin)
parts = d['access_token'].split('.')
p = json.loads(base64.urlsafe_b64decode(parts[1] + '=='))
print(f\"  sub:   {p['sub']}\")
print(f\"  roles: {p['roles']}\")
print(f\"  token: {d['access_token'][:40]}…\")
"
    break
  else
    echo ""
    echo "  Error: $ERR"
    break
  fi
done
