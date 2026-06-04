#!/usr/bin/env bash
# init-poc.sh — First-run bootstrap for Tier 3 (full POC)
# Generates all standard-tier secrets plus Wazuh + demo user passwords.
# Safe to re-run: existing values are preserved.

set -euo pipefail

ENV_FILE="${ENV_FILE:-.env}"

if [[ ! -f "$ENV_FILE" ]]; then
  echo "[init-poc] ERROR: $ENV_FILE not found." >&2
  exit 1
fi

# Source standard-tier secrets first
bash "$(dirname "$0")/init-standard.sh"

_gen20() {
  local p
  p=$(LC_ALL=C tr -dc 'A-Za-z0-9!@#%^&*_+=' </dev/urandom 2>/dev/null | head -c20 || true)
  if [[ ${#p} -lt 20 ]]; then
    echo "[init-poc] ERROR: /dev/urandom unavailable — cannot generate secure passwords" >&2
    exit 1
  fi
  echo "$p"
}

_ensure_var() {
  local var="$1" val="$2"
  if grep -qE "^${var}=.+" "$ENV_FILE" 2>/dev/null; then
    echo "[init-poc] $var already set — skipping."
  else
    echo "${var}=${val}" >> "$ENV_FILE"
    echo "[init-poc] $var generated."
  fi
}

_ensure_var "WAZUH_INDEXER_PASSWORD" "$(_gen20)"
_ensure_var "POC_ALICE_PASSWORD"     "$(_gen20)"
_ensure_var "POC_BOB_PASSWORD"       "$(_gen20)"
_ensure_var "POC_CAROL_PASSWORD"     "$(_gen20)"

echo ""
echo "╔══════════════════════════════════════════════════════════════════════╗"
echo "║  MCP Security Platform — Full POC — Demo Users                      ║"
echo "╠══════════════════════════════════════════════════════════════════════╣"
printf "║  alice  (viewer)  → echo only:             %-26s ║\n" "$(grep '^POC_ALICE_PASSWORD=' "$ENV_FILE" | cut -d= -f2-)"
printf "║  bob    (editor)  → echo + notes:          %-26s ║\n" "$(grep '^POC_BOB_PASSWORD=' "$ENV_FILE" | cut -d= -f2-)"
printf "║  carol  (analyst) → echo + notes + search: %-26s ║\n" "$(grep '^POC_CAROL_PASSWORD=' "$ENV_FILE" | cut -d= -f2-)"
echo "╠══════════════════════════════════════════════════════════════════════╣"
echo "║  Create these users in Keycloak (http://localhost:8082) after start. ║"
echo "║  DB role assignments are auto-applied by poc-seeder on startup.      ║"
echo "║  Wazuh dashboard: http://localhost:5601  admin/WAZUH_INDEXER_PASSWORD ║"
echo "╚══════════════════════════════════════════════════════════════════════╝"
echo ""
echo "[init-poc] Done. Start with:"
echo "  docker compose -f compose.poc.yml up -d"
