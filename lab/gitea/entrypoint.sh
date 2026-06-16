#!/bin/sh
# Lab entrypoint: starts Gitea then creates the admin user + a demo repo.
# Wraps the official image entrypoint so all normal Gitea startup logic runs.
set -e

GITEA_ADMIN_USER="${GITEA_ADMIN_USER:-gitadmin}"
GITEA_ADMIN_PASSWORD="${GITEA_ADMIN_PASSWORD:-labpassword}"
GITEA_ADMIN_EMAIL="${GITEA_ADMIN_EMAIL:-admin@lab.local}"

# Start official Gitea entrypoint in background
/usr/bin/entrypoint &
GITEA_PID=$!

# Wait for Gitea HTTP to be ready (up to 300s — first run SQLite init is slow)
echo "[lab-gitea] Waiting for Gitea to be ready..."
i=0
until wget -T 30 -qO- http://localhost:3000/api/healthz 2>/dev/null | grep -q '"status":"pass"'; do
  i=$((i+1))
  if [ $i -ge 150 ]; then
    echo "[lab-gitea] Timeout waiting for Gitea after 300s" >&2
    exit 1
  fi
  sleep 2
done
echo "[lab-gitea] Gitea is up."

# Create admin user (idempotent — fails silently if already exists)
gitea admin user create \
  --username "${GITEA_ADMIN_USER}" \
  --password "${GITEA_ADMIN_PASSWORD}" \
  --email "${GITEA_ADMIN_EMAIL}" \
  --admin \
  --must-change-password=false 2>/dev/null && \
  echo "[lab-gitea] Admin user '${GITEA_ADMIN_USER}' created." || \
  echo "[lab-gitea] Admin user already exists."

# Create a demo repository so the MCP server has something to work with
wget -qO- \
  --header="Content-Type: application/json" \
  --post-data="{\"name\":\"lab-demo\",\"description\":\"Lab demo repository\",\"private\":false,\"auto_init\":true,\"default_branch\":\"main\"}" \
  "http://${GITEA_ADMIN_USER}:${GITEA_ADMIN_PASSWORD}@localhost:3000/api/v1/user/repos" \
  2>/dev/null && echo "[lab-gitea] Demo repo created." || echo "[lab-gitea] Demo repo already exists."

wait $GITEA_PID
