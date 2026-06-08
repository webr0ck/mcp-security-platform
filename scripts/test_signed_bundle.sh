#!/usr/bin/env bash
# test_signed_bundle.sh — F-002 / INV-012 runtime proof.
#
# Proves that OPA's bundle verification actually works end-to-end:
#   1. Signs the current policies with a test key (OPA 1.17 flags)
#   2. Verifies OPA accepts the signed bundle (correct key, round-trip)
#   3. Verifies OPA rejects a bundle with NO signature (unsigned)
#   4. Verifies OPA rejects a bundle signed with a DIFFERENT key
#   5. Cleans up all temp files
#
# OPA 1.17 flags (older docs are wrong):
#   Sign:   opa build -b <dir> --signing-alg HS256 --signing-key <file> -o <out>
#   Verify: opa build --bundle <bundle> --verification-key <file> --signing-alg HS256 -o /dev/null
#   Reject: exit 1 with "bundle missing .signatures.json file" (unsigned)
#           exit 1 with "JWT signature verification failed" (wrong key)
#   NOT supported: --signing-key-id, --scope (these flags don't exist in 1.17)
#
# Exit 0 only if all steps pass.
# Does NOT require a running stack — uses `opa build` locally.
#
# Usage:  scripts/test_signed_bundle.sh
#         make test-signed-bundle
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REGO_DIR="${REPO_ROOT}/policies/rego"
TMPDIR_OWN="$(mktemp -d)"
SIGNED_BUNDLE="${TMPDIR_OWN}/bundle-signed.tar.gz"
UNSIGNED_BUNDLE="${TMPDIR_OWN}/bundle-unsigned.tar.gz"
KEYFILE="${TMPDIR_OWN}/signing.key"
WRONGKEY="${TMPDIR_OWN}/wrong.key"

cleanup() {
  rm -rf "${TMPDIR_OWN}"
}
trap cleanup EXIT

if ! command -v opa >/dev/null 2>&1; then
  echo "FAIL: 'opa' binary not found on PATH — cannot run signed-bundle test." >&2
  exit 1
fi

# Two distinct test keys (neither is ever used in production).
printf '%s' "test-signing-key-aaaaaaaaaaaaaaaaaaaaaaaaaaaa" > "${KEYFILE}"
printf '%s' "test-signing-key-bbbbbbbbbbbbbbbbbbbbbbbbbbbb" > "${WRONGKEY}"

echo "--- Step 1: Build UNSIGNED bundle (baseline) ---"
opa build -b "${REGO_DIR}" -o "${UNSIGNED_BUNDLE}"
echo "OK: unsigned bundle at ${UNSIGNED_BUNDLE}"

echo ""
echo "--- Step 2: Build SIGNED bundle with test key ---"
opa build -b "${REGO_DIR}" \
  --signing-alg HS256 \
  --signing-key "${KEYFILE}" \
  -o "${SIGNED_BUNDLE}"
echo "OK: signed bundle at ${SIGNED_BUNDLE}"

echo ""
echo "--- Step 3: OPA accepts the correctly signed bundle ---"
if ! opa build --bundle "${SIGNED_BUNDLE}" \
       --verification-key "${KEYFILE}" \
       --signing-alg HS256 \
       -o /dev/null 2>/dev/null; then
  echo "FAIL: OPA rejected a validly signed bundle." >&2
  exit 1
fi
echo "OK: OPA accepted the signed bundle."

echo ""
echo "--- Step 4: OPA rejects an UNSIGNED bundle ---"
if opa build --bundle "${UNSIGNED_BUNDLE}" \
     --verification-key "${KEYFILE}" \
     --signing-alg HS256 \
     -o /dev/null 2>/dev/null; then
  echo "FAIL: OPA accepted an unsigned bundle — signature verification is broken." >&2
  exit 1
fi
echo "OK: OPA correctly rejected the unsigned bundle."

echo ""
echo "--- Step 5: OPA rejects a bundle signed with a DIFFERENT key ---"
if opa build --bundle "${SIGNED_BUNDLE}" \
     --verification-key "${WRONGKEY}" \
     --signing-alg HS256 \
     -o /dev/null 2>/dev/null; then
  echo "FAIL: OPA accepted a bundle verified with the wrong key." >&2
  exit 1
fi
echo "OK: OPA correctly rejected the wrong-key bundle."

echo ""
echo "PASS: F-002 signed-bundle runtime proof complete."
echo "  - Unsigned bundle:    rejected"
echo "  - Wrong-key bundle:   rejected"
echo "  - Correct-key bundle: accepted"
echo ""
echo "To enforce in a running stack:"
echo "  make sign-policy-bundle"
echo "  POLICY_SIGNING_KEY=<key> podman-compose -f docker-compose.yml -f docker-compose.opa-signed.yml up -d"
