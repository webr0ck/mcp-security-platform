# Runbook: Registering a New Keycloak Client

## Symptom

- A new MCP server needs its own OAuth client (confidential, service-account,
  or public) in the `mcp` Keycloak realm, e.g. to onboard a new admin tool,
  a new Grafana-style dashboard, or a new service account for
  machine-to-machine calls.
- A new human admin/reviewer needs to log in via PKCE and doesn't yet have a
  realm role assigned.
- Symptom in the wild: `invalid_client` or `unauthorized_client` from
  Keycloak's `/token` endpoint, or the proxy's OIDC callback 400s with
  "client not found" / "redirect_uri mismatch".

## Diagnosis

```bash
# Confirm the realm and existing clients (lab uses realm "mcp")
cat lab/keycloak/realm-mcp.json | python3 -c \
  "import json,sys; d=json.load(sys.stdin); print([c['clientId'] for c in d['clients']])"

# Is Keycloak actually reachable and the realm imported?
curl -sf http://localhost:8080/realms/mcp/.well-known/openid-configuration | python3 -m json.tool

# Check what redirect_uri the failing client is actually requesting vs what's registered
podman logs mcp-keycloak --tail 100 | grep -i redirect
```

## Resolution

This repo's `mcp` realm is defined declaratively in `lab/keycloak/realm-mcp.json`
and seeded via `lab/keycloak/seed.sh` / `lab/keycloak/Dockerfile.seeder` on lab
bring-up. There is no runtime "admin UI onboarding" path documented for new
clients in this repo — you add the client to the realm-import JSON (or via
`kcadm.sh`/Admin Console against a running instance, then reconcile back into
the JSON so the lab stays reproducible).

Ground the new client's config in the real examples already in
`lab/keycloak/realm-mcp.json`:

| Field | `mcp-proxy` (confidential, user-facing) | `svc-mcp-agent` (service account) | `claude-code` (public, PKCE) |
|---|---|---|---|
| `protocol` | `openid-connect` | `openid-connect` | `openid-connect` |
| `publicClient` | `false` | `false` | `true` |
| `standardFlowEnabled` | `true` | `false` | `true` |
| `serviceAccountsEnabled` | `true` | `true` | `false` |
| `directAccessGrantsEnabled` | `false` | `false` | `false` |
| `redirectUris` | `http://localhost:8000/api/v1/auth/oidc/callback`, plus `${LAB_HOST}` variants | (none needed) | `http://localhost/*`, `http://127.0.0.1/*` |
| `webOrigins` | matching localhost origins | (none) | `['+']` |

Decide which shape your new client needs:

1. **New MCP server needing user-delegated OAuth** (like `mcp-proxy`) —
   confidential client, `standardFlowEnabled: true`, `serviceAccountsEnabled:
   true` if it also needs its own machine identity, exact `redirectUris`
   matching its own OIDC callback path (do not use wildcards for
   confidential clients — that's what public clients like `claude-code` do).
2. **New service-to-service credential** (like `svc-mcp-agent`) —
   confidential client, `standardFlowEnabled: false`,
   `serviceAccountsEnabled: true`, `directAccessGrantsEnabled: false`. Assign
   a realm role via the client's service-account user
   (`Service Account Roles` tab in the Admin Console, or
   `kcadm.sh add-roles`).
3. **New human/PKCE client** (like `claude-code`) — public client,
   `standardFlowEnabled: true`, PKCE is enforced by Keycloak automatically
   for public clients in recent Keycloak versions; set explicit
   `redirectUris` scoped to the real callback path (avoid the `claude-code`
   wildcard pattern for anything beyond local dev).

After adding the JSON block, re-seed:
```bash
bash lab/keycloak/seed.sh
# or rebuild the seeder image if you changed Dockerfile.seeder
podman-compose -f podman-compose.lab.yml build keycloak-seeder
make -f Makefile.lab lab-up
```

For a **role assignment** on an existing client's service account or a human
user, use the Admin Console (`http://localhost:8080` in the lab) →
Users/Clients → Role Mapping, or `kcadm.sh add-roles --uusername <user>
--rolename <role>` — this repo's proxy consumes realm roles via
`request.state.client_roles` (see `proxy/app/middleware/rbac.py`), so the
role name must match one of: `admin`, `platform_admin`, `server_owner`,
`manager`, `auditor`, `user`, `agent`, `readonly`, `security_reviewer`.

## Verification

```bash
# Confirm the new client is visible in the realm's OIDC discovery / admin API
curl -sf http://localhost:8080/admin/realms/mcp/clients \
  -H "Authorization: Bearer $ADMIN_TOKEN" | python3 -c \
  "import json,sys; print([c['clientId'] for c in json.load(sys.stdin)])"

# For a user-facing client: drive a real PKCE login through the proxy
# (see the acceptance-test skill's PKCE login flow) and confirm
# /api/v1/auth/oidc/callback returns 200 with a session cookie.

# For a service account: mint a token and confirm the expected realm role appears
curl -s -X POST http://localhost:8080/realms/mcp/protocol/openid-connect/token \
  -d "grant_type=client_credentials&client_id=<new-client>&client_secret=<secret>" \
  | python3 -c "import json,sys,base64; t=json.load(sys.stdin)['access_token']; \
    print(base64.b64decode(t.split('.')[1]+'==').decode())" | python3 -m json.tool
```

## Prevention / Related

- Keep `lab/keycloak/realm-mcp.json` as the single source of truth — manual
  Admin Console changes that aren't reconciled back into the JSON are lost on
  the next `lab-reset`.
- User auth to `/mcp` is OAuth 2.1 PKCE via Keycloak ONLY — never wire a
  static API key/Bearer token as a substitute for a missing client
  registration.
- `docs/runbooks/git-provider-setup.md` and
  `docs/runbooks/private-cidr-allowlisting.md` cover the other two
  "register a new trust boundary" runbooks for onboarding new MCP servers.
