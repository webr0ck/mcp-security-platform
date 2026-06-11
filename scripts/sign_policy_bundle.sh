#!/usr/bin/env bash
# sign_policy_bundle.sh — F-002 / INV-012.
#
# Builds a SIGNED OPA bundle (policies/bundle.tar.gz) from policies/rego/ so
# that OPA in staging/production (docker-compose.opa-signed.yml) will only
# load a bundle whose .signatures.json verifies against POLICY_SIGNING_KEY.
#
# OPA 1.17 flags (different from older docs):
#   Sign:   opa build -b <rego-dir> --signing-alg HS256 --signing-key <keyfile> -o <out>
#   Verify: opa build --bundle <bundle> --verification-key <keyfile> --signing-alg HS256 -o /dev/null
#   Note:   --signing-key-id does not exist in OPA 1.17. --scope is not needed.
#
# Usage:  POLICY_SIGNING_KEY=<hmac-secret> scripts/sign_policy_bundle.sh
#         make sign-policy-bundle
#
# Exits non-zero if the key is missing/placeholder, opa is absent, or the
# sign→verify round trip fails. Never echoes the key.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REGO_DIR="${REPO_ROOT}/policies/rego"
OUT="${REPO_ROOT}/policies/bundle.tar.gz"

if ! command -v opa >/dev/null 2>&1; then
  echo "FAIL: 'opa' binary not found on PATH — cannot build a signed bundle." >&2
  exit 1
fi

: "${POLICY_SIGNING_KEY:?FAIL: POLICY_SIGNING_KEY is not set}"
case "${POLICY_SIGNING_KEY}" in
  ""|"change-me-in-production"|"your-"*|"placeholder"*)
    echo "FAIL: POLICY_SIGNING_KEY is empty or a known placeholder." >&2
    exit 1 ;;
esac

KEYFILE="$(mktemp)"
trap 'rm -f "${KEYFILE}"' EXIT
printf '%s' "${POLICY_SIGNING_KEY}" > "${KEYFILE}"

# Task 4.4b (SELF-F6): The policies/rego/.manifest file specifies:
#   "roots": ["mcp"]
# This means the bundle claims ownership of the "mcp" data/policy tree only.
# The "mcp_grants" path is NOT owned by the bundle, allowing the proxy to push
# grants via OPA data API (PUT /v1/data/mcp_grants) without bundle conflict.
# The .manifest file is automatically included by opa build -b <dir>.
echo "Building signed bundle from ${REGO_DIR} (roots: [\"mcp\"], grants at mcp_grants) ..."
opa build -b "${REGO_DIR}" \
  --signing-alg HS256 \
  --signing-key "${KEYFILE}" \
  -o "${OUT}"

echo "Verifying signature round trip ..."
opa build --bundle "${OUT}" \
  --verification-key "${KEYFILE}" \
  --signing-alg HS256 \
  -o /dev/null

echo "OK: signed bundle written to ${OUT} (HS256)"
