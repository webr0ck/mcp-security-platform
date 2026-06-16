#!/usr/bin/env bash
# get-kc-token.sh — fetch a Keycloak access token via ROPC (lab-test client)
#
# Usage:
#   source .env && scripts/get-kc-token.sh [alice|bob|carol]
#
# Prints the raw access_token to stdout so it can be used in curl:
#   TOKEN=$(source .env && scripts/get-kc-token.sh alice)
#   curl -H "Authorization: Bearer $TOKEN" http://localhost:8000/mcp ...
#
# Uses lab-test client (directAccessGrantsEnabled=true).
# KC_URL must match OIDC_ISSUER_URL so the iss claim passes proxy validation.

set -euo pipefail

USER="${1:-alice}"
KC_URL="${KC_URL:-http://localhost:8082}"
KC_REALM="${KC_REALM:-mcp}"
KC_LAB_TEST_SECRET="${KC_LAB_TEST_SECRET:--lab-test-secret}"

case "$USER" in
  alice) PASSWORD="${DEX_ALICE_PASSWORD:?set DEX_ALICE_PASSWORD}" ;;
  bob)   PASSWORD="${DEX_BOB_PASSWORD:?set DEX_BOB_PASSWORD}" ;;
  carol) PASSWORD="${CAROL_PASSWORD:-labpassword}" ;;
  *)     PASSWORD="${2:?usage: $0 <username> <password>}" ;;
esac

curl -sf -X POST \
  "${KC_URL}/realms/${KC_REALM}/protocol/openid-connect/token" \
  -d "grant_type=password" \
  -d "client_id=lab-test" \
  -d "client_secret=${KC_LAB_TEST_SECRET}" \
  -d "username=${USER}" \
  -d "password=${PASSWORD}" \
  -d "scope=openid roles" \
  | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['access_token'])"
