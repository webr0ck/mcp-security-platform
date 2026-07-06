#!/usr/bin/env bash
# teardown_gitea_fixtures.sh — remove the lab-gitea-tls sidecar, revert the
# proxy container to its normal (non-GIT_SSL_CAINFO-pinned) config, and
# disable the temporary gitea-lab git_providers row. Safe to run even if
# setup was never applied.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
cd "$ROOT"

export DOCKER_HOST="${DOCKER_HOST:-unix://$(podman machine inspect --format '{{.ConnectionInfo.PodmanSocket.Path}}')}"
LAB_COMPOSE="podman-compose --env-file .env.lab -f docker-compose.yml -f docker-compose.dev.yml -f podman-compose.lab.yml -f compose.wazuh.yml"

echo "== AT3 fixture teardown =="
podman rm -f lab-gitea-tls >/dev/null 2>&1 && echo "  lab-gitea-tls sidecar removed" || echo "  lab-gitea-tls already gone"

$LAB_COMPOSE up -d --no-deps proxy >/dev/null 2>&1
echo "  proxy recreated without the GIT_SSL_CAINFO override"

$LAB_COMPOSE up -d --no-deps scanner-worker >/dev/null 2>&1
echo "  scanner-worker recreated without the GIT_SSL_CAINFO override (CR-14 / WP-B1)"

podman exec -i mcp-db psql -U mcp_app -d mcp_security -c \
  "UPDATE git_providers SET enabled=false WHERE provider='gitea-lab';" >/dev/null 2>&1 || true
echo "  git_providers 'gitea-lab' row disabled"
echo "== done =="
