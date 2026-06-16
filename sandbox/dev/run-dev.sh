#!/usr/bin/env bash
# =============================================================================
# run-dev.sh — Start the MCP development sandbox container
# =============================================================================
# Builds (if needed) and starts a long-running dev container with:
#   - Film Advisor REST API on host port 8080
#   - MCP server (HTTP streamable) on host port 8081
#   - Interactive shell via: podman exec -it mcp-dev-sandbox bash
#   - Workspace mounted at /workspace (code persists on host)
#
# Security profile:
#   - --cap-drop=ALL  (no capabilities)
#   - --security-opt no-new-privileges
#   - NOT --read-only (dev environment needs writable /workspace)
#   - NOT --internal network (dev may need pip/curl; use with caution)
#   - pids-limit=256 (raised from 32 for multi-process dev)
#   - memory=512m
#
# Usage:
#   ./sandbox/dev/run-dev.sh           # build + start
#   ./sandbox/dev/run-dev.sh --rebuild # force rebuild
#   ./sandbox/dev/run-dev.sh --stop    # stop and remove container
#   ./sandbox/dev/run-dev.sh --shell   # open interactive shell in running container

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONTAINER_NAME="mcp-dev-sandbox"
IMAGE_NAME="localhost/mcp-dev:latest"
WORKSPACE="${SCRIPT_DIR}/film-advisor"
# SB-001: isolated network — internal:true blocks internet egress from the dev
# container. The Film Advisor app communicates only with itself (loopback inside
# the container), so no external connectivity is required at runtime.
DEV_NETWORK="mcp-dev-net"
# SB-002: seccomp profile — same profile used by the red-team sandbox runner.
# Deny-by-default: blocks ptrace, mount, kexec, setns, bpf, and kernel module ops.
SECCOMP_PROFILE="${SECCOMP_PROFILE:-${HOME}/.config/containers/seccomp/mcp-sandbox.json}"

REBUILD=false
STOP=false
SHELL_ONLY=false

for arg in "$@"; do
    case "${arg}" in
        --rebuild) REBUILD=true ;;
        --stop)    STOP=true ;;
        --shell)   SHELL_ONLY=true ;;
    esac
done

# ─── Stop ─────────────────────────────────────────────────────────────────────
if ${STOP}; then
    echo "[dev] Stopping ${CONTAINER_NAME}..."
    podman stop "${CONTAINER_NAME}" 2>/dev/null || true
    podman rm   "${CONTAINER_NAME}" 2>/dev/null || true
    echo "[dev] Stopped."
    exit 0
fi

# ─── Shell into existing container ────────────────────────────────────────────
if ${SHELL_ONLY}; then
    if ! podman ps --format "{{.Names}}" | grep -q "^${CONTAINER_NAME}$"; then
        echo "[dev] Container not running. Start it first: ./run-dev.sh"
        exit 1
    fi
    exec podman exec -it "${CONTAINER_NAME}" bash
fi

# ─── Build image ──────────────────────────────────────────────────────────────
if ${REBUILD} || ! podman image exists "${IMAGE_NAME}" 2>/dev/null; then
    echo "[dev] Building ${IMAGE_NAME}..."
    podman build -t "${IMAGE_NAME}" -f "${SCRIPT_DIR}/Dockerfile.dev" "${SCRIPT_DIR}"
    echo "[dev] Build complete."
else
    echo "[dev] Image ${IMAGE_NAME} exists (use --rebuild to force)."
fi

# ─── Remove stale container ───────────────────────────────────────────────────
if podman ps -a --format "{{.Names}}" | grep -q "^${CONTAINER_NAME}$"; then
    echo "[dev] Removing stale container ${CONTAINER_NAME}..."
    podman stop "${CONTAINER_NAME}" 2>/dev/null || true
    podman rm   "${CONTAINER_NAME}" 2>/dev/null || true
fi

# ─── Create isolated network ──────────────────────────────────────────────────
# SB-001: internal=true prevents any internet egress from the dev container.
# Host port mapping (-p) still works: Podman bridges via the host namespace.
if ! podman network exists "${DEV_NETWORK}" 2>/dev/null; then
    echo "[dev] Creating isolated network ${DEV_NETWORK} (internal, no internet egress)..."
    podman network create --internal "${DEV_NETWORK}"
fi

# ─── Start container ──────────────────────────────────────────────────────────
echo "[dev] Starting ${CONTAINER_NAME}..."

# SB-002: seccomp flag — applied only when profile file exists (graceful degradation).
SECCOMP_OPT=()
if [[ -f "${SECCOMP_PROFILE}" ]]; then
    SECCOMP_OPT=("--security-opt" "seccomp=${SECCOMP_PROFILE}")
    echo "[dev] Applying seccomp profile: ${SECCOMP_PROFILE}"
else
    echo "[dev] WARNING: seccomp profile not found at ${SECCOMP_PROFILE}. Run playbook 01-prepare-environment.yml to deploy it."
fi

podman run -d \
    --name "${CONTAINER_NAME}" \
    --network "${DEV_NETWORK}" \
    --cap-drop=ALL \
    --security-opt no-new-privileges \
    "${SECCOMP_OPT[@]}" \
    --read-only \
    --tmpfs /tmp:rw,noexec,nosuid,size=128m \
    -p 8080:8080 \
    -p 8081:8081 \
    -v "${WORKSPACE}:/workspace:z" \
    --memory=512m \
    --pids-limit=256 \
    --env DATABASE_URL=sqlite+aiosqlite:////workspace/films.db \
    --env FILM_API_URL=http://localhost:8080 \
    "${IMAGE_NAME}" \
    bash /workspace/start.sh

echo "[dev] Container started: ${CONTAINER_NAME}"
echo ""
echo "  Film Advisor REST API : http://localhost:8080"
echo "  MCP Server (HTTP)     : http://localhost:8081/mcp"
echo "  Interactive shell     : podman exec -it ${CONTAINER_NAME} bash"
echo "  Logs                  : podman logs -f ${CONTAINER_NAME}"
echo "  Stop                  : ./run-dev.sh --stop"
echo ""

# ─── Wait for services to be ready ───────────────────────────────────────────
echo "[dev] Waiting for Film Advisor API..."
for i in $(seq 1 30); do
    if curl -sf http://localhost:8080/health >/dev/null 2>&1; then
        echo "[dev] REST API ready at http://localhost:8080"
        break
    fi
    if [[ ${i} -eq 30 ]]; then
        echo "[dev] WARNING: REST API not ready after 15s. Check: podman logs ${CONTAINER_NAME}"
    fi
    sleep 0.5
done

echo "[dev] Waiting for MCP server..."
for i in $(seq 1 30); do
    if curl -sf http://localhost:8081/health >/dev/null 2>&1; then
        echo "[dev] MCP server ready at http://localhost:8081"
        break
    fi
    if [[ ${i} -eq 30 ]]; then
        echo "[dev] INFO: MCP server may still be starting. Check: podman logs ${CONTAINER_NAME}"
    fi
    sleep 0.5
done

echo "[dev] Done. Run: ./run-dev.sh --shell  to enter the container."
