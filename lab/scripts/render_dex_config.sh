#!/usr/bin/env bash
# lab/scripts/render_dex_config.sh
#
# Keeps lab/dex/config.lab.yaml's mcp-dex-generic OAuth client's redirectURIs
# in sync with the CURRENT PROXY_BASE_URL (.env.lab) — a LAN/Tailscale IP
# that drifts across lab sessions on this machine. Dex's own static config
# has no env-var expansion (confirmed empirically: the pinned ghcr.io/dexidp/
# dex:v2.38.0 alpine image ships no envsubst, and dex just yaml.Unmarshal's
# the file verbatim, no templating engine) — so the "durable" fix is to
# render the file on the HOST before Dex reads it, not to lean on the
# container to expand anything itself.
#
# Root cause this closes: PROXY_BASE_URL drives the redirect_uri the proxy
# sends to Dex during /auth/enroll/dex-external (app.core.public_url::
# derive_public_base_url always prefers PROXY_BASE_URL). If that redirect_uri
# isn't in Dex's static client allowlist, Dex 400s "Unregistered redirect_uri"
# instead of showing the login form (test_at1_dex_external_oauth.py's
# test_external_oauth_dex_user_token_generic_path).
#
# Idempotent + non-destructive:
#   - The two static fallback entries (127.0.0.1, localhost) — for a
#     developer running the lab with no Tailscale IP configured — are NEVER
#     touched.
#   - The dynamic entry this script manages is marked with a trailing
#     `# dynamic:PROXY_BASE_URL` comment so re-running (PROXY_BASE_URL
#     changed, or unchanged) always replaces exactly that one line, never
#     accumulates duplicates/stale IPs.
#   - If PROXY_BASE_URL is unset/empty, any previously-injected dynamic line
#     is stripped and nothing is added — config.lab.yaml stays valid with
#     just the two static entries, and the lab still boots.
#
# Writes lab/dex/config.rendered.yaml (GITIGNORED) from the tracked template
# lab/dex/config.lab.yaml. The real PROXY_BASE_URL is a LAN/Tailscale address and
# must never land in git, so the template holds only loopback fallbacks and the
# host-specific entry exists solely in the rendered, ignored copy.
#
# Usage: bash lab/scripts/render_dex_config.sh
#   (then `podman restart lab-dex` — bind-mounted, no recreate needed)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
TEMPLATE="${PROJECT_ROOT}/lab/dex/config.lab.yaml"
# Rendered output is GITIGNORED: PROXY_BASE_URL is a real LAN/Tailscale address and
# must never be committed. The tracked template carries only the loopback fallbacks.
CONFIG="${PROJECT_ROOT}/lab/dex/config.rendered.yaml"
cp "${TEMPLATE}" "${CONFIG}"

ENV_LAB="${PROJECT_ROOT}/.env.lab"
PROXY_BASE_URL="${PROXY_BASE_URL:-}"
if [[ -z "${PROXY_BASE_URL}" && -f "${ENV_LAB}" ]]; then
    PROXY_BASE_URL="$(grep -E '^PROXY_BASE_URL=' "${ENV_LAB}" | tail -1 | cut -d= -f2-)"
fi
PROXY_BASE_URL="${PROXY_BASE_URL%/}"

TMP="$(mktemp "${CONFIG}.XXXXXX")"
trap 'rm -f "${TMP}"' EXIT

if [[ -n "${PROXY_BASE_URL}" ]]; then
    REDIRECT_URI="${PROXY_BASE_URL}/auth/callback/dex-external"
    echo "render_dex_config.sh: setting mcp-dex-generic dynamic redirect_uri = ${REDIRECT_URI}"
else
    REDIRECT_URI=""
    echo "render_dex_config.sh: PROXY_BASE_URL unset/empty — stripping any dynamic redirect_uri entry"
fi

awk -v uri="${REDIRECT_URI}" '
    /^  - id: mcp-dex-generic$/ { in_block=1 }
    in_block && / # dynamic:PROXY_BASE_URL/ { next }
    in_block && /^    name: MCP Generic External-OAuth/ && !inserted {
        if (uri != "") {
            print "      - " uri "  # dynamic:PROXY_BASE_URL (managed by lab/scripts/render_dex_config.sh)"
        }
        inserted = 1
    }
    { print }
' "${CONFIG}" > "${TMP}"

if ! diff -q "${CONFIG}" "${TMP}" >/dev/null 2>&1; then
    mv "${TMP}" "${CONFIG}"
    echo "render_dex_config.sh: ${CONFIG} updated"
else
    echo "render_dex_config.sh: ${CONFIG} already up to date"
fi
