#!/usr/bin/env bash
# init-standard.sh — First-run bootstrap for Tier 2 (standard)
# Generates ADMIN_PASSWORD, KC_ADMIN_PASSWORD, and OIDC client secrets.
# Safe to re-run: existing values are never overwritten.

set -euo pipefail

ENV_FILE="${ENV_FILE:-.env}"

if [[ ! -f "$ENV_FILE" ]]; then
  echo "[init-standard] ERROR: $ENV_FILE not found." >&2
  exit 1
fi

_gen20() { LC_ALL=C tr -dc 'A-Za-z0-9!@#%^&*_+=' </dev/urandom 2>/dev/null | head -c20 || true; }
_gen64() { LC_ALL=C tr -dc 'a-f0-9' </dev/urandom 2>/dev/null | head -c64 || true; }

_ensure_var() {
  local var="$1" val="$2"
  if grep -qE "^${var}=.+" "$ENV_FILE" 2>/dev/null; then
    echo "[init-standard] $var already set — skipping."
  else
    echo "${var}=${val}" >> "$ENV_FILE"
    echo "[init-standard] $var generated."
  fi
}

_ensure_var "ADMIN_PASSWORD"           "$(_gen20)"
_ensure_var "KC_ADMIN_PASSWORD"        "$(_gen20)"
_ensure_var "KC_PROXY_CLIENT_SECRET"   "$(_gen64)"
_ensure_var "KC_GRAFANA_CLIENT_SECRET" "$(_gen64)"

echo ""
echo "╔══════════════════════════════════════════════════════════════════════╗"
echo "║  MCP Security Platform — Standard Tier — First Run                  ║"
echo "╠══════════════════════════════════════════════════════════════════════╣"
printf "║  Platform admin:  admin / %-44s ║\n" "$(grep '^ADMIN_PASSWORD=' "$ENV_FILE" | cut -d= -f2-)"
printf "║  Keycloak admin:  admin / %-44s ║\n" "$(grep '^KC_ADMIN_PASSWORD=' "$ENV_FILE" | cut -d= -f2-)"
echo "╠══════════════════════════════════════════════════════════════════════╣"
echo "║  Admin panel:    https://localhost/admin   (LAN only)                ║"
echo "║  Keycloak:       http://localhost:8082     (no users by default)      ║"
echo "║  Grafana:        http://localhost:3000     (SSO via Keycloak)         ║"
echo "╠══════════════════════════════════════════════════════════════════════╣"
echo "║  Save these credentials — they will not be shown again.              ║"
echo "╚══════════════════════════════════════════════════════════════════════╝"
echo ""
echo "[init-standard] Done. Start with:"
echo "  docker compose -f compose.standard.yml up -d"
