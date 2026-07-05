#!/usr/bin/env bash
# setup_gitea_fixtures.sh — AT3 prerequisite: give the submission scanner a
# real, HTTPS-reachable git host it can clone from, with our own fixture repos
# pushed to it.
#
# Why this is needed: proxy/app/services/git_providers.py's URL regex requires
# a literal "https://<host>/..." (no port suffix, i.e. the default 443), and
# submission.py's DraftCreate validator forces https too. lab-gitea normally
# only serves plain HTTP on :3000 (see podman-compose.lab.yml).
#
# Tried-and-reverted approach: switching lab-gitea itself to native HTTPS on
# :443 (PROTOCOL=https, HTTP_PORT=443). This FAILS in this rootless-Podman lab:
# the gitea/gitea:1.22 binary refuses to bind :443 unless it can either run as
# root (it explicitly refuses: "Gitea is not supposed to be run as root...
# please use setcap") or hold CAP_NET_BIND_SERVICE as its own non-root user —
# and podman-compose does not apply `cap_add:` from an override file to an
# already-created service in this environment (verified: HostConfig.CapAdd
# stayed empty after `up -d --no-deps`), so the bind permanently fails with
# EACCES either way. lab-gitea is restored to its stock config below.
#
# Working approach instead: a small nginx:alpine TLS-terminating SIDECAR
# container (lab-gitea-tls) on lab-net, listening on :443 with a self-signed
# cert, reverse-proxying to lab-gitea:3000 over plain HTTP internally. nginx's
# master process starts as root (standard image behavior) so binding :443 is
# trivial, and proxy already shares lab-net with lab-gitea so no network
# reattachment is needed. git_providers.host = 'lab-gitea-tls' (matches the
# clone URL exactly, no port suffix -> the scanner's regex is satisfied).
#
# The self-signed cert must be trusted by the proxy container's git client for
# the clone to succeed. The proxy's $HOME is read-only (can't write
# ~/.gitconfig), so trust is injected via GIT_SSL_CAINFO in
# compose.proxy-git-ca-override.yml, which bind-mounts this cert into the
# proxy container and recreates it with that env var set. NOTE: this pins the
# proxy's *entire* git-over-https trust store to this one CA for as long as
# the override is applied — fine for this suite (AT3 clones only from
# lab-gitea-tls, never a real public host), but must be reverted afterward
# (teardown_gitea_fixtures.sh does this) or a later real github.com clone
# would break.
#
# Usage: bash lab/tests/acceptance/fixtures/setup_gitea_fixtures.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
FIXTURES="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

export DOCKER_HOST="${DOCKER_HOST:-unix://$(podman machine inspect --format '{{.ConnectionInfo.PodmanSocket.Path}}')}"

LAB_COMPOSE="podman-compose --env-file .env.lab -f docker-compose.yml -f docker-compose.dev.yml -f podman-compose.lab.yml -f compose.wazuh.yml"
GITEA_ADMIN_USER="$(grep '^GITEA_ADMIN_USER=' .env.lab | cut -d= -f2-)"
GITEA_ADMIN_PASSWORD="$(grep '^GITEA_ADMIN_PASSWORD=' .env.lab | cut -d= -f2-)"

echo "== AT3 fixture setup: gitea-tls sidecar + repo push =="

# 1. Self-signed cert for lab-gitea-tls (idempotent — regenerate every run so
#    a stale/expired cert never blocks a rerun).
mkdir -p "$FIXTURES/certs"
openssl req -x509 -newkey rsa:2048 \
  -keyout "$FIXTURES/certs/lab-gitea-tls-key.pem" \
  -out "$FIXTURES/certs/lab-gitea-tls-ca.pem" \
  -days 3650 -nodes -subj "/CN=lab-gitea-tls" \
  -addext "subjectAltName=DNS:lab-gitea-tls" 2>/dev/null
echo "  self-signed cert generated (CN=lab-gitea-tls)"

# 2. nginx TLS-terminating sidecar -> lab-gitea:3000 (plain http internally).
cat > "$FIXTURES/certs/nginx.conf" <<'EOF'
events {}
http {
  server {
    listen 443 ssl;
    ssl_certificate     /certs/lab-gitea-tls-ca.pem;
    ssl_certificate_key /certs/lab-gitea-tls-key.pem;
    client_max_body_size 50m;
    location / {
      proxy_pass http://lab-gitea:3000;
      proxy_set_header Host $host;
      proxy_set_header X-Real-IP $remote_addr;
      proxy_read_timeout 120s;
    }
  }
}
EOF
podman rm -f lab-gitea-tls >/dev/null 2>&1 || true
podman run -d --name lab-gitea-tls \
  --network mcp-security-platform_lab-net \
  -v "$FIXTURES/certs/nginx.conf:/etc/nginx/nginx.conf:ro,Z" \
  -v "$FIXTURES/certs:/certs:ro,Z" \
  docker.io/library/nginx:alpine >/dev/null
echo "  lab-gitea-tls sidecar started on lab-net"

# 3. Trust that self-signed CA from inside the proxy container (GIT_SSL_CAINFO
#    override — see rationale above). Recreating with --no-deps only touches
#    this one service.
mkdir -p "$FIXTURES/certs_for_proxy"
cp "$FIXTURES/certs/lab-gitea-tls-ca.pem" "$FIXTURES/certs_for_proxy/lab-gitea-tls-ca.pem"
$LAB_COMPOSE -f "$FIXTURES/compose.proxy-git-ca-override.yml" up -d --no-deps proxy
echo "  proxy recreated trusting the lab-gitea-tls CA (GIT_SSL_CAINFO)"

for _ in $(seq 1 15); do
  podman ps --filter name=mcp-proxy --filter status=running --format '{{.Names}}' | grep -q mcp-proxy && break
  sleep 2
done
sleep 3

# 4. Confirm the proxy can actually reach + trust lab-gitea-tls before going further.
podman exec mcp-proxy curl -sk -o /dev/null -w 'lab-gitea-tls reachable: HTTP %{http_code}\n' https://lab-gitea-tls/ --max-time 10

# 5. Create the two fixture repos under the Gitea admin user (idempotent —
#    409 on rerun is fine, ignored).
for repo in malicious-mcp clean-mcp; do
  code=$(curl -s -o /dev/null -w '%{http_code}' -u "${GITEA_ADMIN_USER}:${GITEA_ADMIN_PASSWORD}" \
    -X POST "http://localhost:3002/api/v1/user/repos" \
    -H 'Content-Type: application/json' \
    -d "{\"name\":\"${repo}\",\"private\":false,\"auto_init\":true}")
  echo "  repo ${repo}: HTTP ${code} (201=created, 409=already exists)"
done

# 6. Push fixture content (from the host — localhost:3002 is lab-gitea's normal
#    published HTTP port, untouched by any of the above).
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
for repo in malicious-mcp clean-mcp; do
  rm -rf "$WORK/$repo"
  git clone -q "http://${GITEA_ADMIN_USER}:${GITEA_ADMIN_PASSWORD}@localhost:3002/${GITEA_ADMIN_USER}/${repo}.git" "$WORK/$repo"
  # Glob each extension separately (nullglob) so an optional file that
  # doesn't exist (e.g. clean-mcp has no requirements.txt) doesn't abort the
  # whole copy under `set -e` — a single multi-pattern `cp` fails outright if
  # even one pattern has zero matches.
  shopt -s nullglob
  for f in "$FIXTURES/$repo"/*.py "$FIXTURES/$repo"/*.txt "$FIXTURES/$repo"/*.md; do
    cp "$f" "$WORK/$repo/"
  done
  shopt -u nullglob
  ( cd "$WORK/$repo" \
    && git -c user.name=qa -c user.email=qa@lab.local add -A \
    && git -c user.name=qa -c user.email=qa@lab.local commit -q -m "AT3 fixture: $repo" --allow-empty \
    && git push -q origin HEAD )
  echo "  pushed $repo"
done

# 7. Register lab-gitea-tls as an enabled, allow-private git provider so the
#    scanner's SSRF host check (private podman-bridge IP) passes.
podman exec -i mcp-db psql -U mcp_app -d mcp_security <<SQL
INSERT INTO git_providers (provider, enabled, host, clone_account, allow_private, updated_by)
VALUES ('gitea-lab', true, 'lab-gitea-tls', NULL, true, 'qa-acceptance-setup')
ON CONFLICT (provider) DO UPDATE SET enabled=true, host='lab-gitea-tls', allow_private=true;
SQL
echo "  git_providers row seeded (provider=gitea-lab host=lab-gitea-tls allow_private=true)"

# 8. Prove the clone actually works end-to-end before handing off to pytest.
podman exec mcp-proxy sh -c 'rm -rf /tmp/_at_clone_check && git clone --depth=1 https://lab-gitea-tls/gitadmin/clean-mcp.git /tmp/_at_clone_check >/dev/null 2>&1 && echo "  clone-through-proxy OK" && rm -rf /tmp/_at_clone_check' \
  || { echo "  FATAL: proxy cannot clone from lab-gitea-tls — see setup_gitea_fixtures.sh rationale" >&2; exit 1; }

echo "MALICIOUS_URL=https://lab-gitea-tls/${GITEA_ADMIN_USER}/malicious-mcp.git"
echo "CLEAN_URL=https://lab-gitea-tls/${GITEA_ADMIN_USER}/clean-mcp.git"
echo "== gitea fixture setup complete =="
