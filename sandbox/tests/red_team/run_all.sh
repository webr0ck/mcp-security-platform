#!/usr/bin/env bash
# =============================================================================
# run_all.sh — MCP Sandbox Red Team Test Runner
# =============================================================================
# Runs all containment tests, aggregates results, exits 1 if any test fails.
#
# Usage:
#   ./sandbox/tests/red_team/run_all.sh
#   ./sandbox/tests/red_team/run_all.sh --verbose    # show container output
#   ./sandbox/tests/red_team/run_all.sh --no-cleanup  # leave containers on failure
#
# Requirements: podman in PATH, sandbox network must exist (run 01-prepare-environment.yml first)
#
# Exit code: 0 = all tests pass, 1 = one or more tests failed

set -euo pipefail

# ─── Configuration ────────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SANDBOX_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

SANDBOX_NETWORK="${SANDBOX_NETWORK:-mcp-sandbox-net}"
TEST_IMAGE="${TEST_IMAGE:-docker.io/busybox:1.36}"
PYTHON_IMAGE="${PYTHON_IMAGE:-docker.io/python:3.12-slim}"
SECCOMP_PROFILE="${SECCOMP_PROFILE:-${HOME}/.config/containers/seccomp/mcp-sandbox.json}"

VERBOSE=false
NO_CLEANUP=false

# Parse flags
for arg in "$@"; do
    case "${arg}" in
        --verbose|-v) VERBOSE=true ;;
        --no-cleanup) NO_CLEANUP=true ;;
        --help|-h)
            grep '^#' "${BASH_SOURCE[0]}" | head -20 | sed 's/^# \?//'
            exit 0
            ;;
    esac
done

# ─── Colours ──────────────────────────────────────────────────────────────────

RESET='\033[0m'
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
BOLD='\033[1m'

ts() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }

pass()  { printf "${GREEN}[PASS]${RESET} %s — %s\n" "$(ts)" "$*"; }
fail()  { printf "${RED}[FAIL]${RESET} %s — %s\n" "$(ts)" "$*"; }
info()  { printf "${BOLD}[INFO]${RESET} %s — %s\n" "$(ts)" "$*"; }
warn()  { printf "${YELLOW}[WARN]${RESET} %s — %s\n" "$(ts)" "$*"; }

# ─── Preflight ────────────────────────────────────────────────────────────────

info "MCP Sandbox Red Team Test Runner"
info "Network: ${SANDBOX_NETWORK} | Test image: ${TEST_IMAGE}"
info "Seccomp: ${SECCOMP_PROFILE}"
echo ""

# Verify podman is available
if ! command -v podman &>/dev/null; then
    fail "podman not found in PATH. Run 01-prepare-environment.yml first."
    exit 1
fi

# Verify sandbox network exists
if ! podman network inspect "${SANDBOX_NETWORK}" &>/dev/null; then
    fail "Sandbox network '${SANDBOX_NETWORK}' does not exist."
    fail "Run: ansible-playbook -i inventory/sandbox-hosts.yml playbooks/01-prepare-environment.yml"
    exit 1
fi

# Verify seccomp profile exists
if [[ ! -f "${SECCOMP_PROFILE}" ]]; then
    warn "Seccomp profile not found at ${SECCOMP_PROFILE}. Tests will run without it (less restrictive)."
    SECCOMP_FLAGS=""
else
    SECCOMP_FLAGS="--security-opt seccomp=${SECCOMP_PROFILE}"
fi

# Pull images (idempotent)
info "Pulling test images..."
podman pull "${TEST_IMAGE}" --quiet
podman pull "${PYTHON_IMAGE}" --quiet
info "Images ready."
echo ""

# ─── Common container flags ───────────────────────────────────────────────────

HARDENED=(
    --network "${SANDBOX_NETWORK}"
    --cap-drop=ALL
    --security-opt no-new-privileges
    ${SECCOMP_FLAGS}
    --read-only
    --tmpfs /tmp:rw,noexec,nosuid,size=32m
    --memory=128m
    --pids-limit=32
)

# ─── Test registry ────────────────────────────────────────────────────────────

declare -a TEST_SCRIPTS=(
    "test_network_isolation.sh"
    "test_filesystem_isolation.sh"
    "test_privilege_escalation.sh"
    "test_resource_limits.sh"
    "test_seccomp.sh"
    "test_credential_exfil.sh"
    # Apr–May 2026 CVE coverage
    "test_symlink_escape.sh"
    "test_stdio_injection.sh"
    "test_supply_chain.sh"
    "test_tool_poisoning.sh"
)

# ─── POC lab integration tests (require full POC stack) ──────────────────────
# These tests require the POC lab to be running:
#   podman compose -f compose.poc.yml up -d  (plus seed + TAINT_FLOOR_ENABLED=true)
# They are NOT part of the containment suite above, which uses ephemeral containers.
# Run standalone: bash sandbox/tests/red_team/test_prompt_injection_wazuh.sh [--skip-wazuh]
declare -a POC_TEST_SCRIPTS=(
    "test_prompt_injection_wazuh.sh"
)

declare -i PASS_COUNT=0
declare -i FAIL_COUNT=0
declare -a FAILED_TESTS=()

# ─── Run tests ────────────────────────────────────────────────────────────────

for test_script in "${TEST_SCRIPTS[@]}"; do
    test_path="${SCRIPT_DIR}/${test_script}"
    test_name="${test_script%.sh}"

    if [[ ! -f "${test_path}" ]]; then
        warn "Test script not found: ${test_path} — skipping"
        continue
    fi

    info "Running ${test_name}..."
    set +e
    if ${VERBOSE}; then
        env \
            SANDBOX_NETWORK="${SANDBOX_NETWORK}" \
            TEST_IMAGE="${TEST_IMAGE}" \
            PYTHON_IMAGE="${PYTHON_IMAGE}" \
            SECCOMP_PROFILE="${SECCOMP_PROFILE}" \
            SECCOMP_FLAGS="${SECCOMP_FLAGS}" \
            NO_CLEANUP="${NO_CLEANUP}" \
            bash "${test_path}"
        result=$?
    else
        output=$(
            env \
                SANDBOX_NETWORK="${SANDBOX_NETWORK}" \
                TEST_IMAGE="${TEST_IMAGE}" \
                PYTHON_IMAGE="${PYTHON_IMAGE}" \
                SECCOMP_PROFILE="${SECCOMP_PROFILE}" \
                SECCOMP_FLAGS="${SECCOMP_FLAGS}" \
                NO_CLEANUP="${NO_CLEANUP}" \
                bash "${test_path}" 2>&1
        )
        result=$?
        if [[ ${result} -ne 0 ]]; then
            echo "${output}"
        fi
    fi
    set -e

    if [[ ${result} -eq 0 ]]; then
        pass "${test_name}"
        (( PASS_COUNT++ )) || true
    else
        fail "${test_name}"
        (( FAIL_COUNT++ )) || true
        FAILED_TESTS+=("${test_name}")
    fi
done

# ─── Summary ──────────────────────────────────────────────────────────────────

echo ""
echo "================================================================="
printf "${BOLD}Red Team Test Results — %s${RESET}\n" "$(ts)"
echo "================================================================="
printf "  Passed: ${GREEN}%d${RESET}\n" "${PASS_COUNT}"
printf "  Failed: ${RED}%d${RESET}\n" "${FAIL_COUNT}"
echo ""

if [[ ${FAIL_COUNT} -gt 0 ]]; then
    printf "${RED}FAILED TESTS:${RESET}\n"
    for t in "${FAILED_TESTS[@]}"; do
        printf "  - %s\n" "${t}"
    done
    echo ""
    fail "Sandbox containment validation FAILED. Do NOT use this sandbox for real MCP evaluation."
    exit 1
else
    pass "All ${PASS_COUNT} containment tests passed. Sandbox is verified."
    exit 0
fi
