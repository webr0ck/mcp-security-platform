#!/usr/bin/env bash
# sign_policy_bundle.sh — F-002 / INV-012.
#
# Builds a SIGNED OPA bundle (policies/bundle.tar.gz) from policies/rego/ so
# that OPA in staging/production (docker-compose.opa-signed.yml) will only
# load a bundle whose .signatures.json verifies against POLICY_SIGNING_KEY.
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
KEY_ID="mcp-policy-signing-key-v1"

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

echo "Building signed bundle from ${REGO_DIR} ..."
opa build -b "${REGO_DIR}" \
  --signing-alg HS256 \
  --signing-key "${KEYFILE}" \
  --signing-key-id "${KEY_ID}" \
  -o "${OUT}"

echo "Verifying signature round trip ..."
opa build -b "${OUT}" \
  --verification-key "${KEYFILE}" \
  --verification-key-id "${KEY_ID}" \
  --signing-alg HS256 \
  -o /dev/null

echo "OK: signed bundle written to ${OUT} (keyid=${KEY_ID}, HS256, scope=write)"
