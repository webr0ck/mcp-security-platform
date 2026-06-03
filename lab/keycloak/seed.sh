#!/usr/bin/env bash
# lab/keycloak/seed.sh
# Wait for Keycloak to be ready, then update client secrets from env vars.
# Run inside the keycloak container or from a seeder sidecar.
set -euo pipefail

KC_URL="${KC_URL:-http://lab-keycloak:8080}"
REALM="${KC_REALM:-mcp}"
ADMIN_USER="${KC_ADMIN:-admin}"
ADMIN_PASS="${KC_ADMIN_PASSWORD:-adminpassword}"

echo "Waiting for Keycloak at ${KC_URL}..."
until curl -s "${KC_URL}/realms/${REALM}" > /dev/null 2>&1; do
    sleep 3
done
echo "Keycloak ready."

# Get admin token
TOKEN=$(curl -s -X POST "${KC_URL}/realms/master/protocol/openid-connect/token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "grant_type=password&client_id=admin-cli&username=${ADMIN_USER}&password=${ADMIN_PASS}" \
    | jq -r '.access_token')

echo "Got admin token."

# Update mcp-proxy client secret
CLIENT_ID=$(curl -s -H "Authorization: Bearer ${TOKEN}" \
    "${KC_URL}/admin/realms/${REALM}/clients?clientId=mcp-proxy" \
    | jq -r '.[0].id // empty')

if [ -n "${CLIENT_ID}" ] && [ -n "${KC_PROXY_CLIENT_SECRET:-}" ]; then
    curl -s -X PUT -H "Authorization: Bearer ${TOKEN}" \
        -H "Content-Type: application/json" \
        "${KC_URL}/admin/realms/${REALM}/clients/${CLIENT_ID}" \
        -d "{\"secret\": \"${KC_PROXY_CLIENT_SECRET}\"}"
    echo "Updated mcp-proxy client secret."
fi

# Update grafana client secret
GF_CLIENT_ID=$(curl -s -H "Authorization: Bearer ${TOKEN}" \
    "${KC_URL}/admin/realms/${REALM}/clients?clientId=grafana" \
    | jq -r '.[0].id // empty')

if [ -n "${GF_CLIENT_ID}" ] && [ -n "${KC_GRAFANA_CLIENT_SECRET:-}" ]; then
    curl -s -X PUT -H "Authorization: Bearer ${TOKEN}" \
        -H "Content-Type: application/json" \
        "${KC_URL}/admin/realms/${REALM}/clients/${GF_CLIENT_ID}" \
        -d "{\"secret\": \"${KC_GRAFANA_CLIENT_SECRET}\"}"
    echo "Updated grafana client secret."
fi

# Update Trusted Hosts policy — add LAB_HOST so dynamic client registration
# works from LAN/Tailscale clients (e.g. Claude Code on another device).
POLICY_ID=$(curl -s -H "Authorization: Bearer ${TOKEN}" \
    "${KC_URL}/admin/realms/${REALM}/components?type=org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy" \
    | jq -r '.[] | select(.name=="Trusted Hosts") | .id')

LAB_HOST="${LAB_HOST:-localhost}"
if [ -n "${POLICY_ID}" ]; then
    curl -s -X PUT -H "Authorization: Bearer ${TOKEN}" \
        -H "Content-Type: application/json" \
        "${KC_URL}/admin/realms/${REALM}/components/${POLICY_ID}" \
        -d "{
          \"id\": \"${POLICY_ID}\",
          \"name\": \"Trusted Hosts\",
          \"providerId\": \"trusted-hosts\",
          \"providerType\": \"org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy\",
          \"parentId\": \"${REALM}\",
          \"config\": {
            \"host-sending-registration-request-must-match\": [\"false\"],
            \"client-uris-must-match\": [\"true\"],
            \"trusted-hosts\": [\"${LAB_HOST}\", \"localhost\", \"127.0.0.1\"]
          }
        }"
    echo "Updated Trusted Hosts policy: ${LAB_HOST}, localhost, 127.0.0.1"
fi

# Update Allowed Client Scopes policies — add openid and standard scopes
# so Claude Code and other MCP clients can register dynamically.
for SCOPE_POLICY_ID in $(curl -s -H "Authorization: Bearer ${TOKEN}" \
    "${KC_URL}/admin/realms/${REALM}/components?type=org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy" \
    | jq -r '.[] | select(.name=="Allowed Client Scopes") | "\(.id) \(.subType // "")"'); do
  POLICY_UUID=$(echo $SCOPE_POLICY_ID | awk '{print $1}')
  SUBTYPE=$(echo $SCOPE_POLICY_ID | awk '{print $2}')
  curl -s -X PUT -H "Authorization: Bearer ${TOKEN}" \
    -H "Content-Type: application/json" \
    "${KC_URL}/admin/realms/${REALM}/components/${POLICY_UUID}" \
    -d "{\"id\":\"${POLICY_UUID}\",\"name\":\"Allowed Client Scopes\",\"providerId\":\"allowed-client-templates\",\"providerType\":\"org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy\",\"subType\":\"${SUBTYPE}\",\"parentId\":\"${REALM}\",\"config\":{\"allow-default-scopes\":[\"true\"],\"allowed-client-scopes\":[\"openid\",\"profile\",\"email\",\"roles\",\"web-origins\",\"offline_access\",\"address\",\"phone\",\"microprofile-jwt\"]}}"
  echo "Updated Allowed Client Scopes policy (${SUBTYPE:-unknown}): openid+standard scopes added"
done

# Set lab user emails to corp domain so they match role_assignments/OPA grants.
# The proxy uses email (when present) as client_id for OIDC JWTs.
declare -A LAB_USER_EMAILS
LAB_USER_EMAILS=([alice]="alice@corp" [bob]="bob@corp" [carol]="carol@corp")
for LAB_USER in alice bob carol; do
    LAB_UID=$(curl -s -H "Authorization: Bearer ${TOKEN}" \
        "${KC_URL}/admin/realms/${REALM}/users?username=${LAB_USER}" \
        | jq -r '.[0].id // empty' 2>/dev/null)
    if [ -n "${LAB_UID}" ]; then
        NEW_EMAIL="${LAB_USER}@corp"
        curl -s -X PUT -H "Authorization: Bearer ${TOKEN}" \
            -H "Content-Type: application/json" \
            "${KC_URL}/admin/realms/${REALM}/users/${LAB_UID}" \
            -d "{\"email\":\"${NEW_EMAIL}\",\"emailVerified\":true}" 2>/dev/null || true
    fi
done
echo "Set lab user emails to @corp domain"

# Grant offline_access role to all lab users so MCP clients can get refresh tokens
OA_ROLE_ID=$(curl -s -H "Authorization: Bearer ${TOKEN}" \
    "${KC_URL}/admin/realms/${REALM}/roles/offline_access" \
    | jq -r '.id' 2>/dev/null)

# Also get the agent role id for alice
AGENT_ROLE_ID=$(curl -s -H "Authorization: Bearer ${TOKEN}" \
    "${KC_URL}/admin/realms/${REALM}/roles/agent" \
    | jq -r '.id' 2>/dev/null)

if [ -n "${OA_ROLE_ID}" ]; then
    for LAB_USER in alice bob carol; do
        LAB_UID=$(curl -s -H "Authorization: Bearer ${TOKEN}" \
            "${KC_URL}/admin/realms/${REALM}/users?username=${LAB_USER}" \
            | jq -r '.[0].id // empty' 2>/dev/null)
        if [ -n "${LAB_UID}" ]; then
            curl -s -X POST -H "Authorization: Bearer ${TOKEN}" \
                -H "Content-Type: application/json" \
                "${KC_URL}/admin/realms/${REALM}/users/${LAB_UID}/role-mappings/realm" \
                -d "[{\"id\":\"${OA_ROLE_ID}\",\"name\":\"offline_access\"}]" 2>/dev/null || true
        fi
    done
    echo "Granted offline_access to alice, bob, carol"
fi

# Grant alice the "agent" realm role so proxy OPA check passes
if [ -n "${AGENT_ROLE_ID}" ]; then
    ALICE_UID=$(curl -s -H "Authorization: Bearer ${TOKEN}" \
        "${KC_URL}/admin/realms/${REALM}/users?username=alice" \
        | jq -r '.[0].id // empty' 2>/dev/null)
    if [ -n "${ALICE_UID}" ]; then
        curl -s -X POST -H "Authorization: Bearer ${TOKEN}" \
            -H "Content-Type: application/json" \
            "${KC_URL}/admin/realms/${REALM}/users/${ALICE_UID}/role-mappings/realm" \
            -d "[{\"id\":\"${AGENT_ROLE_ID}\",\"name\":\"agent\"}]" 2>/dev/null || true
        echo "Granted agent role to alice"
    fi
fi

# Add mcp-proxy audience mapper as a default realm scope so all clients
# (including dynamically registered ones like Claude Code) get aud: mcp-proxy
EXISTING_AUD_SCOPE=$(curl -s -H "Authorization: Bearer ${TOKEN}" \
    "${KC_URL}/admin/realms/${REALM}/client-scopes" \
    | jq -r '.[] | select(.name=="mcp-proxy-audience") | .id' 2>/dev/null)

if [ -z "${EXISTING_AUD_SCOPE}" ]; then
    AUD_SCOPE_ID=$(curl -s -X POST "${KC_URL}/admin/realms/${REALM}/client-scopes" \
        -H "Authorization: Bearer ${TOKEN}" -H "Content-Type: application/json" \
        -d '{"name":"mcp-proxy-audience","protocol":"openid-connect","attributes":{"include.in.token.scope":"false","display.on.consent.screen":"false"}}' \
        -D - | grep -i "^location:" | awk -F'/' '{print $NF}' | tr -d '\r')
    curl -s -X POST "${KC_URL}/admin/realms/${REALM}/client-scopes/${AUD_SCOPE_ID}/protocol-mappers/models" \
        -H "Authorization: Bearer ${TOKEN}" -H "Content-Type: application/json" \
        -d '{"name":"mcp-proxy-audience","protocol":"openid-connect","protocolMapper":"oidc-audience-mapper","config":{"included.client.audience":"mcp-proxy","id.token.claim":"false","access.token.claim":"true"}}' 2>/dev/null
    curl -s -X PUT "${KC_URL}/admin/realms/${REALM}/default-default-client-scopes/${AUD_SCOPE_ID}" \
        -H "Authorization: Bearer ${TOKEN}" 2>/dev/null
    echo "Created mcp-proxy-audience scope and set as realm default"
else
    echo "mcp-proxy-audience scope already exists"
fi

echo "Keycloak seeding complete."
