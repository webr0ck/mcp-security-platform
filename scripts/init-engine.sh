#!/usr/bin/env bash
# init-engine.sh — First-run bootstrap for Tier 1 (engine-only)
# Generates ADMIN_PASSWORD if absent from .env, writes it, prints one-time banner.
# Safe to re-run: existing values are never overwritten.
#
# Usage:
#   cp deployments/engine/.env.example .env
#   # Fill DB_PASSWORD, REDIS_PASSWORD, PROXY_SECRET_KEY, VAULT_TOKEN, etc.
#   bash scripts/init-engine.sh
#   docker compose -f compose.engine.yml up -d

set -euo pipefail

ENV_FILE="${ENV_FILE:-.env}"

if [[ ! -f "$ENV_FILE" ]]; then
  echo "[init-engine] ERROR: $ENV_FILE not found. Copy deployments/engine/.env.example to .env first." >&2
  exit 1
fi

if grep -qE "^ADMIN_PASSWORD=.+" "$ENV_FILE" 2>/dev/null; then
  echo "[init-engine] ADMIN_PASSWORD already set in $ENV_FILE — skipping generation."
else
  ADMIN_PASSWORD=$(LC_ALL=C tr -dc 'A-Za-z0-9!@#%^&*_+=' </dev/urandom 2>/dev/null | head -c20 || true)
  echo "ADMIN_PASSWORD=${ADMIN_PASSWORD}" >> "$ENV_FILE"
  echo ""
  echo "╔══════════════════════════════════════════════════════════════╗"
  echo "║  MCP Security Platform — Engine Tier — First Run            ║"
  echo "║                                                              ║"
  printf "║  Admin password: %-44s ║\n" "${ADMIN_PASSWORD}"
  echo "║                                                              ║"
  echo "║  Admin panel:  https://localhost/admin  (LAN only)           ║"
  echo "║  Portal:       https://localhost/portal (LAN only)           ║"
  echo "║                                                              ║"
  echo "║  Save this password — it will not be shown again.           ║"
  echo "╚══════════════════════════════════════════════════════════════╝"
  echo ""
fi

echo "[init-engine] Done. Start the stack with:"
echo "  docker compose -f compose.engine.yml up -d"
echo ""
echo "[init-engine] Then generate the DB bootstrap API key:"
echo "  PGHOST=localhost PGPORT=5432 PGDATABASE=\${DB_NAME:-mcp_security} \\"
echo "  PGUSER=\${DB_USER:-mcp_app} PGPASSWORD=<your-db-password> \\"
echo "  bash infra/scripts/create-bootstrap-key.sh"
