#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# lab/scripts/entra-check.sh
# Validates Microsoft Entra (Azure AD) tenant connectivity for Graph API access.
#
# Usage:
#   bash lab/scripts/entra-check.sh
#
# Required environment variables:
#   ENTRA_TENANT_ID      — Azure AD tenant ID (UUID)
#   ENTRA_CLIENT_ID      — App registration client ID
#   ENTRA_CLIENT_SECRET  — App registration client secret (injected at runtime)
#
# What this script does:
#   1. Verifies required env vars are set
#   2. Requests a client_credentials token from Entra
#   3. Prints token expiry
#   4. Calls GET /v1.0/organization to validate Graph API access
# =============================================================================

# ---------------------------------------------------------------------------
# 1. Check required env vars
# ---------------------------------------------------------------------------
MISSING=()

if [[ -z "${ENTRA_TENANT_ID:-}" ]]; then
    MISSING+=("ENTRA_TENANT_ID")
fi
if [[ -z "${ENTRA_CLIENT_ID:-}" ]]; then
    MISSING+=("ENTRA_CLIENT_ID")
fi
if [[ -z "${ENTRA_CLIENT_SECRET:-}" ]]; then
    MISSING+=("ENTRA_CLIENT_SECRET")
fi

if [[ ${#MISSING[@]} -gt 0 ]]; then
    echo "[entra-check] ERROR: The following required environment variables are not set:" >&2
    for var in "${MISSING[@]}"; do
        echo "  - ${var}" >&2
    done
    echo "" >&2
    echo "[entra-check] Set these variables before running this script." >&2
    echo "[entra-check] ENTRA_CLIENT_SECRET must be injected at runtime — do not hardcode it." >&2
    exit 1
fi

TOKEN_URL="https://login.microsoftonline.com/${ENTRA_TENANT_ID}/oauth2/v2.0/token"
GRAPH_ORG_URL="https://graph.microsoft.com/v1.0/organization"

# ---------------------------------------------------------------------------
# 2. Request client_credentials token
# ---------------------------------------------------------------------------
echo "[entra-check] Requesting token from:"
echo "  ${TOKEN_URL}"

TOKEN_RESPONSE=$(
    curl -s -X POST "${TOKEN_URL}" \
        --data-urlencode "grant_type=client_credentials" \
        --data-urlencode "scope=https://graph.microsoft.com/.default" \
        --data-urlencode "client_id=${ENTRA_CLIENT_ID}" \
        --data-urlencode "client_secret=${ENTRA_CLIENT_SECRET}"
)

# Check for error in response
ERROR_FIELD=$(echo "${TOKEN_RESPONSE}" | jq -r '.error // empty' 2>/dev/null || true)
if [[ -n "${ERROR_FIELD}" ]]; then
    ERROR_DESC=$(echo "${TOKEN_RESPONSE}" | jq -r '.error_description // "no description"' 2>/dev/null || true)
    echo "[entra-check] ERROR: Token request failed." >&2
    echo "  error:             ${ERROR_FIELD}" >&2
    echo "  error_description: ${ERROR_DESC}" >&2
    exit 1
fi

ACCESS_TOKEN=$(echo "${TOKEN_RESPONSE}" | jq -r '.access_token // empty' 2>/dev/null || true)
if [[ -z "${ACCESS_TOKEN}" ]]; then
    echo "[entra-check] ERROR: Token response did not contain access_token." >&2
    echo "  Response: ${TOKEN_RESPONSE}" >&2
    exit 1
fi

# Extract and display token expiry
EXPIRES_IN=$(echo "${TOKEN_RESPONSE}" | jq -r '.expires_in // "unknown"' 2>/dev/null || true)
TOKEN_TYPE=$(echo "${TOKEN_RESPONSE}" | jq -r '.token_type // "Bearer"' 2>/dev/null || true)

echo ""
echo "  Entra client_credentials flow: OK"
echo "  token_type:  ${TOKEN_TYPE}"
echo "  expires_in:  ${EXPIRES_IN}s ($(( EXPIRES_IN / 60 )) minutes)"

# ---------------------------------------------------------------------------
# 3. Test Graph API — GET /v1.0/organization
# ---------------------------------------------------------------------------
echo ""
echo "[entra-check] Testing Graph API: GET ${GRAPH_ORG_URL}"

GRAPH_HTTP_STATUS=$(
    curl -s -o /tmp/entra_graph_response.json -w "%{http_code}" \
        -H "Authorization: Bearer ${ACCESS_TOKEN}" \
        -H "Accept: application/json" \
        "${GRAPH_ORG_URL}"
)

if [[ "${GRAPH_HTTP_STATUS}" == "200" ]]; then
    ORG_DISPLAY_NAME=$(
        jq -r '.value[0].displayName // "unknown"' /tmp/entra_graph_response.json 2>/dev/null || echo "unknown"
    )
    echo ""
    echo "  Graph API access: OK"
    echo "  Organization:     ${ORG_DISPLAY_NAME}"
    echo ""
    echo "[entra-check] All checks passed."
    rm -f /tmp/entra_graph_response.json
    exit 0
else
    GRAPH_ERROR=$(
        jq -r '.error.message // "no error message"' /tmp/entra_graph_response.json 2>/dev/null || echo "unknown"
    )
    echo "" >&2
    echo "[entra-check] ERROR: Graph API returned HTTP ${GRAPH_HTTP_STATUS}." >&2
    echo "  Error: ${GRAPH_ERROR}" >&2
    rm -f /tmp/entra_graph_response.json
    exit 1
fi
