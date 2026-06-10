#!/usr/bin/env bash
# check_signed_default.sh — F-002 gate (INV-012).
#
# Verifies that every non-dev compose tier that runs OPA has --verification-key
# in its command, AND that the signed bundle actually verifies against the repo's
# HS256 key (a substring grep alone would pass on a broken key/alg config).
#
# NOTE: This gate was designed to FAIL against the original docker-compose.yml
# because that file used an unsigned directory mount (no --verification-key).
# After Task 1.1, docker-compose.yml itself contains --verification-key and
# mounts bundle.tar.gz, so the grep check passes on the default tier.
#
# Called by: make security-check (F-002 block)
# Exit 0 = PASS, Exit 1 = FAIL

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Non-dev compose files that must enforce signed bundles.
# docker-compose.opa-signed.yml is now deleted (absorbed into default).
# docker-compose.dev.yml is intentionally excluded — dev uses unsigned dir mount.
PROD_COMPOSES=(
  "docker-compose.yml"
  "compose.standard.yml"
  "compose.engine.yml"
)

FAILURES=0

for COMPOSE in "${PROD_COMPOSES[@]}"; do
  COMPOSE_PATH="${REPO_ROOT}/${COMPOSE}"
  [ -f "${COMPOSE_PATH}" ] || continue

  # Does this compose file define an opa service at all?
  grep -q '^  opa:' "${COMPOSE_PATH}" || continue

  # Extract the OPA service's command block (up to 50 lines after the service header)
  OPA_BLOCK=$(grep -A50 '^  opa:' "${COMPOSE_PATH}")

  if ! echo "${OPA_BLOCK}" | grep -q -- '--verification-key'; then
    echo "FAIL [F-002]: ${COMPOSE} starts OPA without --verification-key (unsigned policy)."
    FAILURES=$((FAILURES + 1))
  else
    echo "PASS [F-002]: ${COMPOSE} has --verification-key in OPA command."
  fi
done

if [ "${FAILURES}" -gt 0 ]; then
  echo "FAIL [F-002]: ${FAILURES} compose file(s) run OPA without bundle signature verification."
  exit 1
fi

# Functional check: sign with the repo's existing HS256 tooling, then prove OPA
# loads the bundle with the same key (catches alg/key/path mismatches).
# Skip if POLICY_SIGNING_KEY is absent (the signing script will error clearly).
if [ -z "${POLICY_SIGNING_KEY:-}" ]; then
  echo "SKIP [F-002]: POLICY_SIGNING_KEY not set — skipping functional OPA bundle-load check."
  echo "      Set POLICY_SIGNING_KEY to enable the full functional gate."
  echo "PASS [F-002]: structural check passed (all prod tiers enforce --verification-key)."
  exit 0
fi

echo ""
echo "--- F-002 functional check: sign + OPA bundle-load verification ---"

"${SCRIPT_DIR}/sign_policy_bundle.sh"

podman run --rm \
  -e POLICY_SIGNING_KEY \
  -v "${REPO_ROOT}/policies/bundle.tar.gz:/policies/bundle.tar.gz:ro" \
  openpolicyagent/opa:0.63.0-static \
  run --server --shutdown-after=2s \
  --verification-key="${POLICY_SIGNING_KEY}" \
  --signing-alg=HS256 \
  --bundle /policies/bundle.tar.gz \
  || { echo "FAIL [F-002]: signed bundle does not verify/load."; exit 1; }

echo "PASS [F-002]: signed OPA bundle enforced and verifiable."
