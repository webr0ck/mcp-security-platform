#!/usr/bin/env bash
# Generate the self-signed demo certificates the Wazuh lab overlay
# (compose.wazuh.yml) mounts. These are NOT committed — private keys must never
# live in the repo. Run this once before bringing up the Wazuh overlay.
#
#   ./scripts/gen-wazuh-certs.sh
#
# Uses Wazuh's official wazuh-certs-tool.sh, which emits exactly the filenames
# compose.wazuh.yml expects (root-ca.pem/key, wazuh-{indexer,manager,dashboard}
# .pem/-key.pem, admin.pem/-key.pem). Idempotent: refuses to clobber unless -f.
set -euo pipefail

WAZUH_VERSION="${WAZUH_VERSION:-4.9}"
CERTS_DIR="$(cd "$(dirname "$0")/.." && pwd)/lab/wazuh/certs"
CONFIG="${CERTS_DIR}/config.yml"
FORCE="${1:-}"

command -v openssl >/dev/null || { echo "openssl is required" >&2; exit 1; }
[ -f "$CONFIG" ] || { echo "missing $CONFIG" >&2; exit 1; }

if [ -f "${CERTS_DIR}/root-ca.pem" ] && [ "$FORCE" != "-f" ]; then
  echo "Certs already present in ${CERTS_DIR}. Re-run with -f to regenerate." >&2
  exit 0
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
echo "Downloading Wazuh ${WAZUH_VERSION} cert tool…"
curl -fsSL "https://packages.wazuh.com/${WAZUH_VERSION}/wazuh-certs-tool.sh" -o "$tmp/wazuh-certs-tool.sh"
cp "$CONFIG" "$tmp/config.yml"
( cd "$tmp" && bash wazuh-certs-tool.sh -A )

# Place the generated set where compose.wazuh.yml mounts it.
mkdir -p "$CERTS_DIR"
cp "$tmp/wazuh-certificates/"* "$CERTS_DIR/"
chmod 640 "$CERTS_DIR"/*-key.pem "$CERTS_DIR"/root-ca.key 2>/dev/null || true
echo "Wrote demo certs to ${CERTS_DIR} (git-ignored). Now: podman compose -f compose.wazuh.yml up -d"
