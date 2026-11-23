#!/usr/bin/env bash
# First-run and every-deploy preparation for the Dark Factory tier, run on
# vm-mcp as the `mcp` user from this directory. Idempotent: secrets and keys
# are generated once and never overwritten; the OPA bundle is re-signed every
# run so it always matches the checked-out policies.
#
#   MCP_PUBLIC_HOST=10.77.30.30 bash init.sh
set -euo pipefail
cd "$(dirname "$0")"
umask 077

HOST="${MCP_PUBLIC_HOST:-10.77.30.30}"
DNS_NAME="${MCP_DNS_NAME:-mcp.ai.home.arpa}"
# The OPA image used for signing must be the one that verifies.
OPA_IMAGE="${OPA_IMAGE:-docker.io/openpolicyagent/opa:0.63.0-static}"
STATE=state
ENV_FILE=.env

rand() { openssl rand -hex 32; }
mkdir -p "$STATE"/{tls/gateway,tls/vault,nginx-secrets,opa}

# ── secrets (.env) ────────────────────────────────────────────────────────────
touch "$ENV_FILE"
chmod 600 "$ENV_FILE"
put_once() {   # name value: append only if the name is absent
    grep -q "^$1=" "$ENV_FILE" || printf '%s=%s\n' "$1" "$2" >> "$ENV_FILE"
}
for name in DB_PASSWORD REDIS_PASSWORD PROXY_SECRET_KEY API_KEY_HMAC_KEY \
            SBOM_SIGNING_KEY AUDIT_LOG_HMAC_KEY WEBHOOK_SIGNING_KEY \
            POLICY_SIGNING_KEY OAUTH_STATE_SECRET VAULT_TOKEN \
            GATEWAY_SHARED_SECRET OIDC_CLIENT_SECRET KC_DB_PASSWORD \
            KC_ADMIN_PASSWORD; do
    put_once "$name" "$(rand)"
done
# Unused here (no Dex, no MinIO) but the production validator refuses an
# empty value for both, so they get a random one rather than a placeholder.
put_once DEX_CLIENT_SECRET "$(rand)"
put_once MINIO_ROOT_PASSWORD "$(rand)"
# Temporary: Keycloak forces a change at first login.
put_once KC_OPERATOR_INITIAL_PASSWORD "$(openssl rand -base64 18 | tr -d '/+=')"

# Non-secret settings: rewritten every run so the file follows the code.
sed -i '/^# --- settings ---$/,$d' "$ENV_FILE"
cat >> "$ENV_FILE" <<EOF
# --- settings ---
ENVIRONMENT=production
LOG_LEVEL=INFO
MCP_PUBLIC_HOST=$HOST
PROXY_BASE_URL=https://$HOST
PROXY_ALLOWED_HOSTS=$HOST
PROXY_WORKERS=2
OIDC_TRUST_FORWARDED_HOST=false
SESSION_COOKIE_SECURE=true
DB_HOST=db
DB_PORT=5432
DB_NAME=mcp_security
DB_USER=mcp_app
REDIS_HOST=redis
REDIS_PORT=6379
OPA_HOST=opa
OPA_PORT=8181
VAULT_ADDR=https://vault:8200
VAULT_CA_BUNDLE=/etc/mcp/vault-ca.crt
OIDC_ENABLED=true
OIDC_ISSUER_URL=https://$HOST/realms/mcp
OIDC_INTERNAL_ISSUER_URL=http://keycloak:8080/realms/mcp
OIDC_CLIENT_ID=mcp-proxy
OIDC_AUDIENCE=mcp-proxy
# Registration needs the LLM auditor (production refuses to degrade to
# regex-only). llm-shim is the lease-holding adapter to the factory LLM
# gateway; until it runs, registration answers 503 and invocation works.
REQUIRE_LLM_AUDIT=true
OLLAMA_HOST=llm-shim
OLLAMA_PORT=11434
# Private upstreams a registered server may resolve into: df-control,
# qmd on vm-dev's lab leg, and the in-host pairwise backend networks.
UPSTREAM_PRIVATE_CIDR_ALLOWLIST=10.77.20.10/32,10.77.90.10/32,172.31.240.0/28
# SEC-05: backends share a pairwise net with the proxy so it can dial them;
# this refuses any inbound peer that is not the gateway or loopback.
PROXY_INGRESS_ALLOWLIST_ENABLED=true
PROXY_INGRESS_TRUSTED_HOSTS=gateway
EOF

# ── TLS: one internal CA for the gateway's server cert and Vault's ────────────
# Client certificates for agents come from step-ca, not from this CA.
CA_KEY=$STATE/tls/ca.key CA_CRT=$STATE/tls/ca.crt
if [[ ! -f $CA_KEY ]]; then
    openssl ecparam -name prime256v1 -genkey -noout -out "$CA_KEY"
    openssl req -x509 -new -key "$CA_KEY" -sha256 -days 3650 \
        -subj "/CN=Dark Factory MCP platform CA" -out "$CA_CRT" \
        -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
        -addext "keyUsage=critical,keyCertSign,cRLSign"
fi
chmod 644 "$CA_CRT"

issue() {   # dir name san
    local dir=$1 name=$2 san=$3
    [[ -f $dir/$name.crt ]] && return 0
    openssl ecparam -name prime256v1 -genkey -noout -out "$dir/$name.key"
    local cn=${san%%,*}; cn=${cn#*:}
    openssl req -new -key "$dir/$name.key" -subj "/CN=$cn" -out "$dir/$name.csr" \
        -addext "subjectAltName=$san"
    openssl x509 -req -in "$dir/$name.csr" -CA "$CA_CRT" -CAkey "$CA_KEY" -CAcreateserial \
        -days 825 -sha256 -copy_extensions copyall \
        -extfile <(printf 'basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\n') \
        -out "$dir/$name.crt"
    rm -f "$dir/$name.csr"
    cp "$CA_CRT" "$dir/ca.crt"
}
issue "$STATE/tls/gateway" server "IP:$HOST,DNS:$DNS_NAME"
issue "$STATE/tls/vault" vault "DNS:vault,IP:127.0.0.1"
chmod 644 "$STATE"/tls/*/*.crt

# ── gateway -> proxy shared secret (X-Gateway-Secret, F-001) ──────────────────
GSECRET=$(sed -n 's/^GATEWAY_SHARED_SECRET=//p' "$ENV_FILE")
printf 'proxy_set_header X-Gateway-Secret "%s";\n' "$GSECRET" > "$STATE/nginx-secrets/gateway-secret.conf"

[[ -f $STATE/step-ca-password ]] || rand > "$STATE/step-ca-password"

# ── signed OPA bundle (INV-012) ───────────────────────────────────────────────
sed -n 's/^POLICY_SIGNING_KEY=//p' "$ENV_FILE" | tr -d '\n' > "$STATE/opa/policy-signing.key"
podman run --rm --user 0:0 --network none \
    -v "$PWD/../../policies/rego:/rego:ro" -v "$PWD/$STATE/opa:/out" \
    "$OPA_IMAGE" build -b /rego --signing-alg HS256 \
    --signing-key /out/policy-signing.key -o /out/bundle.tar.gz
podman run --rm --user 0:0 --network none -v "$PWD/$STATE/opa:/out:ro" \
    "$OPA_IMAGE" build --bundle /out/bundle.tar.gz --signing-alg HS256 \
    --verification-key /out/policy-signing.key -o /dev/null
chmod 644 "$STATE/opa/bundle.tar.gz"

echo "[init] ready: $ENV_FILE and $STATE/ (secrets never printed)"
