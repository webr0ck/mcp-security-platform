#!/usr/bin/env bash
# lab/scripts/lab-recreate.sh — safely recreate ONE lab service (image bump,
# config/env change) without the manual container surgery this needed before
# 2026-07-11 (Keycloak 24->26 upgrade hit this: `podman-compose ... up -d
# --force-recreate --no-deps lab-keycloak` failed with "has dependent
# containers" / "cannot remove container ... running" because
# lab-keycloak-seeder — a one-shot container with restart:"no" — holds a
# depends_on reference to lab-keycloak even after it has already exited).
#
# Usage: bash lab/scripts/lab-recreate.sh <compose-service-name> [--pull]
#   <compose-service-name>  the SERVICE key in podman-compose.lab.yml (e.g.
#                            `gateway`, not its container_name `mcp-gateway`)
#   --pull                  podman pull the image before recreating (use
#                            after bumping an image tag in the compose file)
#
# Examples:
#   bash lab/scripts/lab-recreate.sh lab-keycloak --pull
#   bash lab/scripts/lab-recreate.sh gateway

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
cd "${PROJECT_ROOT}"

SERVICE="${1:-}"
[[ -z "${SERVICE}" ]] && { echo "Usage: $0 <service> [--pull]" >&2; exit 1; }
DO_PULL=false
[[ "${2:-}" == "--pull" ]] && DO_PULL=true

LAB_COMPOSE="podman-compose --env-file .env.lab -f docker-compose.yml -f docker-compose.dev.yml -f podman-compose.lab.yml"

log() { echo "[lab-recreate] $*"; }

# ── One-shot containers (restart: "no") that hold a depends_on reference to
# a given service and must be removed before that service can be recreated,
# plus the command to re-run each after the service is healthy again.
# (plain case statements, not `declare -A` — macOS ships bash 3.2, no assoc arrays)
dependents_for() {
    case "$1" in
        lab-keycloak) echo "lab-keycloak-seeder" ;;
        lab-vault|lab-grafana|lab-netbox|lab-gitea) echo "lab-seeder" ;;
        *) echo "" ;;
    esac
}
reseed_command_for() {
    case "$1" in
        lab-keycloak-seeder) echo "${LAB_COMPOSE} run --rm lab-keycloak-seeder" ;;
        lab-seeder) echo "${LAB_COMPOSE} run --rm lab-seeder" ;;
        *) echo "" ;;
    esac
}

# CONTAINER_NAME can differ from the compose SERVICE key (e.g. service
# `gateway` -> container_name `mcp-gateway`) — resolve it from compose config
# rather than assuming they match, since podman rm/inspect need the real name.
CONTAINER_NAME="$(${LAB_COMPOSE} config 2>/dev/null | awk -v svc="  ${SERVICE}:" '
    $0==svc{f=1; next} f && /container_name:/{print $2; exit} f && /^  [a-zA-Z]/{exit}')"
CONTAINER_NAME="${CONTAINER_NAME:-${SERVICE}}"

DEPENDENTS="$(dependents_for "${SERVICE}")"
if [[ -n "${DEPENDENTS}" ]]; then
    for dep in ${DEPENDENTS}; do
        if podman ps -a --format '{{.Names}}' | grep -qx "${dep}"; then
            log "Removing one-shot dependent container: ${dep}"
            podman rm -f "${dep}" >/dev/null
        fi
    done
fi

if ${DO_PULL}; then
    IMAGE="$(${LAB_COMPOSE} config 2>/dev/null | awk -v svc="  ${SERVICE}:" '$0==svc{f=1; next} f && /image:/{print $2; exit} f && /^  [a-zA-Z]/{exit}')"
    if [[ -n "${IMAGE}" ]]; then
        log "Pulling ${IMAGE}"
        podman pull "${IMAGE}"
    else
        log "⚠ Could not resolve image for ${SERVICE} from compose config — skipping pull, relying on cache"
    fi
fi

# force-recreate can still fail the same way --no-deps did if the container
# is mid-crash-loop ("running or paused containers cannot be removed without
# force") — fall back to an explicit rm -f + up rather than trusting
# force-recreate's own removal step.
log "Removing ${CONTAINER_NAME} (if present) and recreating"
podman rm -f "${CONTAINER_NAME}" >/dev/null 2>&1 || true
${LAB_COMPOSE} up -d --no-deps "${SERVICE}"

log "Waiting for ${CONTAINER_NAME} to become healthy..."
ELAPSED=0
while true; do
    STATUS="$(podman inspect "${CONTAINER_NAME}" --format '{{.State.Health.Status}}' 2>/dev/null || echo "no-healthcheck")"
    if [[ "${STATUS}" == "healthy" ]]; then
        log "${CONTAINER_NAME} is healthy (${ELAPSED}s)"
        break
    fi
    if [[ "${STATUS}" == "no-healthcheck" ]]; then
        log "${CONTAINER_NAME} has no healthcheck — assuming ready"
        break
    fi
    if [[ ${ELAPSED} -ge 180 ]]; then
        echo "[lab-recreate] ✗ ${CONTAINER_NAME} did not become healthy within 180s (status: ${STATUS})" >&2
        echo "[lab-recreate] Check: podman logs ${CONTAINER_NAME}" >&2
        exit 1
    fi
    sleep 5; ELAPSED=$((ELAPSED + 5))
done

if [[ -n "${DEPENDENTS}" ]]; then
    for dep in ${DEPENDENTS}; do
        cmd="$(reseed_command_for "${dep}")"
        if [[ -n "${cmd}" ]]; then
            log "Re-running ${dep}"
            eval "${cmd}"
        fi
    done
fi

log "Done."
