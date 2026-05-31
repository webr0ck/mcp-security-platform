# MCP Server Publishing Guide

How to build, test, register, and publish an MCP server through the MCP Security Platform.
Written for external developers who want their tool available to AI agents behind the platform's identity, policy, and audit stack.

---

## Table of Contents

1. [What the platform does for you](#1-what-the-platform-does-for-you)
2. [Prerequisites](#2-prerequisites)
3. [Step 1 — Build your MCP server](#3-step-1--build-your-mcp-server)
4. [Step 2 — Test locally against the sandbox](#4-step-2--test-locally-against-the-sandbox)
5. [Step 3 — Register with the platform](#5-step-3--register-with-the-platform)
6. [Step 4 — Understand the security review](#6-step-4--understand-the-security-review)
7. [Step 4b — Supply-chain hardening checklist](#supply-chain-hardening-checklist)
7. [Step 5 — Choose a credential injection mode](#7-step-5--choose-a-credential-injection-mode)
8. [Step 6 — Configure OPA access grants](#8-step-6--configure-opa-access-grants)
9. [Step 7 — Maintain and version your server](#9-step-7--maintain-and-version-your-server)
10. [Reference: registration fields](#10-reference-registration-fields)
11. [Reference: risk levels](#11-reference-risk-levels)
12. [Troubleshooting](#12-troubleshooting)

---

## 1. What the platform does for you

When your MCP server is registered, every call to it flows through:

```
AI Agent (Claude Code / Copilot)
  │  Bearer token (user identity)
  ▼
Nginx gateway  — TLS, rate limiting, ModSecurity WAF
  ▼
Security Proxy  — identity verification, session management
  ▼
OPA/Rego  — policy: is this client allowed to call this tool?
  ▼
Credential Broker  — injects the right credential for your backend
  ▼
Your MCP server  — receives a clean request with the correct auth header
```

**You get, for free:**
- Identity propagation — you know exactly which user called you (via the injected credential or a forwarded user token)
- Per-call audit trail — every invocation is logged with SHA-256 hash integrity
- RBAC enforcement — only clients with the right role can reach your tool
- Automatic SBOM generation — CycloneDX bill of materials created at registration
- Prompt injection scanning — your tool's description and parameters are scanned for injection patterns

**Your responsibility:**
- Implement the MCP `streamable-http` transport correctly
- Expose a `/health` endpoint
- Accept and honour the credential the broker injects
- Not store user credentials or tokens beyond the request

---

## 2. Prerequisites

| Item | Details |
|------|---------|
| Platform API key | An `admin`-role key. Ask your platform administrator. |
| Container runtime | Docker or Podman — your server must run in a container |
| Network access | Your server must be reachable from the proxy by container name or FQDN |
| Python ≥ 3.11 or Go/Node.js | The example uses FastMCP (Python). Any MCP SDK that implements HTTP Streamable works. |

**Install the MCP Python SDK:**
```bash
pip install "mcp[server]"   # installs FastMCP + uvicorn
```

---

## 3. Step 1 — Build your MCP server

### Minimal template

```python
# server.py
from __future__ import annotations
import os, httpx, uvicorn
from mcp.server.fastmcp import FastMCP

# Name shown in tool discovery
mcp = FastMCP("my-service-mcp")

@mcp.tool()
async def my_tool(query: str) -> dict:
    """One-line description of what this tool does.

    Parameters:
        query: The search query to run against my-service.
    """
    token = os.environ.get("INJECTED_CREDENTIAL", "")
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.get(
            "https://my-service.example.com/api/search",
            params={"q": query},
            headers={"Authorization": f"Bearer {token}"},
        )
        resp.raise_for_status()
        return resp.json()

if __name__ == "__main__":
    app = mcp.streamable_http_app()
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", "8000")))
```

### Rules for your tool descriptions

The platform's Tool Manifest Auditor (TMA) scans every tool description for:

| Pattern | Risk raised | Example |
|---------|-------------|---------|
| Filesystem path parameters with no scope | High | `path: str` — "absolute file path" |
| Shell/command execution | Critical | "executes a shell command" |
| Prompt injection payloads | Critical | "Ignore previous instructions..." |
| Broad scope language | Medium | "reads any email in the mailbox" |
| Credentials in description | High | "pass your API key in the query field" |

**Do:**
- Be precise: `"Search incidents created in the last 7 days"` not `"Search anything"`
- State scope explicitly: `"Read-only. Returns at most 50 results."`
- Name parameters clearly: `incident_id` not `id`

**Don't:**
- Include example tokens or credentials in descriptions
- Use dynamic parameter names that accept arbitrary keys
- Claim capabilities your tool doesn't have

### Required endpoints

| Path | Method | Purpose |
|------|--------|---------|
| `/mcp` | POST | MCP JSON-RPC 2.0 over HTTP Streamable — required |
| `/health` | GET | Returns `{"status":"ok"}` — used by the platform healthcheck |

### Dockerfile template

```dockerfile
FROM python:3.12-slim

RUN groupadd --gid 1001 appgroup && \
    useradd --uid 1001 --gid appgroup --no-create-home appuser

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY --chown=appuser:appgroup server.py .
USER appuser

ENV PORT=8000 HOST=0.0.0.0 TRANSPORT=http
CMD ["python", "server.py"]
```

---

## 4. Step 2 — Test locally against the sandbox

### 4.1 Run the platform sandbox

```bash
cd ~/Code/mcp-security-platform
podman compose \
  -f docker-compose.yml \
  -f docker-compose.dev.yml \
  -f podman-compose.lab.yml \
  --env-file .env --env-file .env.lab \
  up -d
```

### 4.2 Start your server on the same Docker network

```bash
# Build your server image
docker build -t my-mcp-server:dev .

# Run on the lab internal network so the proxy can reach it
docker run --rm \
  --name my-mcp-server \
  --network mcp-security-platform_internal-net \
  -e INJECTED_CREDENTIAL=test-token \
  my-mcp-server:dev
```

### 4.3 Verify the MCP protocol handshake

```bash
curl -X POST http://localhost:my-port/mcp \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","method":"initialize","id":1,"params":{
    "protocolVersion":"2024-11-05",
    "capabilities":{},
    "clientInfo":{"name":"test","version":"1"}
  }}'
```

Expected response includes `"serverInfo"` with your server name and a `"capabilities"` object.

### 4.4 Verify tool listing

```bash
curl -X POST http://localhost:my-port/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"tools/list","params":{},"id":2}'
```

Your tool names and descriptions must appear in the response before you proceed to registration.

---

## 5. Step 3 — Register with the platform

### 5.1 Get an API key

Ask your platform admin to create an `admin`-role API key for you. It looks like `mcp_<32chars>`.

### 5.2 Call the registration endpoint

> **Security note — SSRF risk**: `upstream_url` is where the proxy forwards all calls to your tool. Do not point it at internal platform services (`postgres`, `keycloak`, `vault`, etc.) or cloud metadata endpoints. Your platform operator should enforce an egress allowlist on the internal Docker network. The TMA checks for localhost/127.0.0.1 by name but does not block all RFC-1918 container addresses.

```bash
PLATFORM_URL=http://localhost:8000   # or your platform's base URL
API_KEY=mcp_your_key_here

curl -X POST "$PLATFORM_URL/api/v1/tools/register" \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "my-service-search",
    "version": "1.0.0",
    "description": "Search incidents in My Service. Read-only. Returns at most 50 results per query.",
    "schema": {
      "type": "object",
      "properties": {
        "query": {
          "type": "string",
          "description": "Keyword or phrase to search for"
        },
        "limit": {
          "type": "integer",
          "description": "Maximum results (1–50)",
          "minimum": 1,
          "maximum": 50
        }
      },
      "required": ["query"]
    },
    "upstream_url": "http://my-mcp-server:8000/mcp",
    "source_repo": "https://github.com/yourorg/my-mcp-server",
    "source_commit": "abc123def456...",
    "tags": ["search", "incidents"]
  }'
```

> **Note**: Credential injection mode (`injection_mode`, `inject_header`, `inject_prefix`) is **not** set at registration — the registration endpoint only accepts the fields shown above. Configure injection mode separately after registration (see Step 5).

### 5.3 Read the response

```json
{
  "tool_id": "550e8400-e29b-41d4-a716-446655440000",
  "name": "my-service-search",
  "version": "1.0.0",
  "status": "active",
  "risk_score": 22,
  "risk_level": "low",
  "risk_reasons": [],
  "sbom_ref": "sbom_01HZ...",
  "registered_at": "2026-05-31T10:00:00Z",
  "registered_by": "you@example.com"
}
```

Save the `tool_id` — you will need it for credential upload and status checks.

**If `status` is `"quarantined"`:** Your tool scored `critical` risk. See [Step 4](#6-step-4--understand-the-security-review) for what to fix, then re-register with a bumped version.

---

## 6. Step 4 — Understand the security review

### What happens automatically at registration

1. **Tool Manifest Auditor (TMA)** runs on your `name`, `description`, `schema`, and `upstream_url`
   - Static pattern matching (prompt injection, credential leakage, path traversal)
   - LLM-based semantic risk scan (via local Ollama / configured model)
   - Produces a `risk_score` (0–100) and `risk_level` (low / medium / high / critical)

2. **SBOM generation** — CycloneDX JSON listing all parameters, tool metadata, and the upstream URL
   - Signed with `SBOM_SIGNING_KEY`; stored in `sbom_records`
   - Available at `GET /api/v1/tools/{tool_id}/sbom`

3. **Status assignment:**
   - `low`, `medium` → `status: active` (callable immediately)
   - `high` → `status: active`, but **requires human review before granting access**. A `high` risk score means the TMA detected patterns that warrant manual security review (broad scope, unbounded parameters, or semantic risk). Ask your platform admin to review the `risk_reasons` before creating an OPA grant. Do not self-approve.
   - `critical` → `status: quarantined` (blocked until an admin manually sets `active` and an SBOM exists)

### How to fix a quarantine

```bash
# 1. Read the risk reasons
curl "$PLATFORM_URL/api/v1/tools/$TOOL_ID/audit" \
  -H "Authorization: Bearer $API_KEY"

# 2. Fix the issues in your server
# 3. Re-register with a new version (bumped semver)
curl -X POST "$PLATFORM_URL/api/v1/tools/register" \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"name":"my-service-search","version":"1.0.1",...}'

# 4. If an admin approves your quarantined tool directly
#    (requires a valid SBOM to exist — re-register if SBOM generation failed):
curl -X PATCH "$PLATFORM_URL/api/v1/tools/$TOOL_ID" \
  -H "Authorization: Bearer $ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{"status":"active"}'
```

### Common risk reasons and fixes

| Risk reason | Fix |
|-------------|-----|
| "Parameter allows filesystem traversal" | Rename `path` → `incident_id`; add `enum` constraint if finite values |
| "Description contains injection pattern" | Remove any "ignore", "pretend", "override" language from descriptions |
| "Tool description too broad" | Specify the scope: "Read-only", "returns at most N results", named resource types only |
| "Upstream URL points to localhost" | Use a container name or FQDN, not `127.0.0.1` or `localhost` |
| "No schema validation on required params" | Add `"required": ["param_name"]` to your schema |

---

## Supply-chain hardening checklist

Before the platform admin grants your tool `active` status or approves an OPA grant, your server image must pass the following supply-chain checks. Run these in your CI pipeline on every build.

### 1. No known CVEs in installed packages

```bash
# Python — pip-audit scans your requirements.txt against the OSV/PyPI advisory database
pip install pip-audit
pip-audit -r requirements.txt --fail-on-vuln

# Node.js — built into npm
npm audit --audit-level=high

# Container image — scan with Trivy (checks OS packages + language runtimes)
trivy image --exit-code 1 --severity HIGH,CRITICAL my-mcp-server:dev
```

Fail the build if any HIGH or CRITICAL CVE is found. The platform operator may re-run Trivy as part of the registration review.

### 2. Packages must come from trusted sources only

**Python** — restrict to PyPI official index and pin all transitive dependencies:
```bash
# Generate a pinned lockfile from your direct requirements
pip-compile requirements.txt --generate-hashes --output-file requirements.lock

# Install only from the lockfile (hash verification, no network fallback)
pip install --require-hashes -r requirements.lock
```

In your Dockerfile, install from the lockfile:
```dockerfile
COPY requirements.lock .
RUN pip install --no-cache-dir --require-hashes -r requirements.lock
```

**Node.js** — use `npm ci` (installs from lockfile only, fails on any mismatch):
```dockerfile
COPY package-lock.json .
RUN npm ci --omit=dev
```

Never use `--index-url` pointing to a private registry unless it mirrors the official index and is controlled by your organisation.

### 3. Packages must not be suspiciously new

Newly published packages (< 7 days on PyPI/npm) are a common supply-chain attack vector (typosquatting, dependency confusion). The platform recommends checking publication age:

```bash
# Python — check when a package version was first published
python3 -c "
import urllib.request, json, datetime, sys
pkg, ver = sys.argv[1], sys.argv[2]
d = json.loads(urllib.request.urlopen(f'https://pypi.org/pypi/{pkg}/{ver}/json').read())
pub = d['urls'][0]['upload_time']
age = (datetime.datetime.now() - datetime.datetime.fromisoformat(pub)).days
print(f'{pkg}=={ver} published {age} days ago')
if age < 7:
    print('WARNING: package is less than 7 days old — verify before use')
    sys.exit(1)
" httpx 0.27.0
```

For automated CI:
```bash
# pip-audit + custom age check can be combined in a single pre-build gate
# Prefer packages with ≥ 6 months of release history and active maintenance
```

### 4. Base image freshness

Pin to a specific digest, not just a tag — tags are mutable:

```dockerfile
# Instead of:
FROM python:3.12-slim

# Use:
FROM python:3.12-slim@sha256:abc123...  # pin to exact digest
```

Rebuild weekly to pick up OS security patches. Your CI pipeline should trigger a nightly or weekly rebuild even without code changes.

### 5. Pre-registration checklist

Before submitting to the platform admin for approval:

- [ ] `pip-audit` / `npm audit` passes with no HIGH/CRITICAL CVEs
- [ ] `trivy image` passes with no HIGH/CRITICAL CVEs
- [ ] All packages installed from `requirements.lock` with hash verification
- [ ] No package version is < 7 days old on its package registry
- [ ] Base image pinned to a specific digest
- [ ] `source_commit` in your registration payload points to the exact commit that built this image
- [ ] `source_repo` is publicly accessible so the platform admin can verify the code

---

## 7. Step 5 — Choose a credential injection mode

Credential injection is a two-step process: (1) set the mode on the tool, then (2) upload the credential.

### Mode summary

| Mode | What the proxy injects | When to use |
|------|----------------------|-------------|
| `none` | Nothing — your server handles auth itself | Public APIs, servers that auth via other means |
| `service` | One shared token/key per tool, stored by an admin | Service-to-service calls; all users share one identity |
| `user` | Per-user credential, stored once by the user | APIs where each user has their own API key/token |
| `service_account` | Keycloak service-account OAuth token | Your backend trusts Keycloak; KC client credentials flow |
| `oauth_user_token` | User's actual OAuth access token (KC token exchange) | Backend validates the user's identity directly |

### Step 5a — Set the injection mode on your registered tool

```bash
# Set injection_mode (and optionally inject_header / inject_prefix)
curl -X PUT "$PLATFORM_URL/admin/credentials/$TOOL_ID/injection-mode" \
  -H "Authorization: Bearer $ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "mode": "service",
    "inject_header": "Authorization",
    "inject_prefix": "Bearer "
  }'
```

For `X-Api-Key` style headers:
```bash
-d '{"mode":"service","inject_header":"X-Api-Key","inject_prefix":""}'
```

### Step 5b — Upload the credential

```bash
# Upload service credential for your tool
# Field name is "secret" (not "credential")
curl -X PUT "$PLATFORM_URL/admin/credentials/$TOOL_ID" \
  -H "Authorization: Bearer $ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "secret": "sk-your-service-api-key",
    "owner_type": "service"
  }'
```

For `user` mode (each user uploads their own key):
```bash
curl -X PUT "$PLATFORM_URL/admin/credentials/$TOOL_ID" \
  -H "Authorization: Bearer $USER_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "secret": "user-personal-api-key",
    "owner_type": "user"
  }'
```

Your server receives the credential in the configured header:
```python
# Default: Authorization: Bearer <secret>
token = request.headers.get("Authorization", "").removeprefix("Bearer ").strip()
```

---

## 8. Step 6 — Configure OPA access grants

After registration, no client can call your tool yet. You must add a grant in the OPA policy data.

### Current policy location

`policies/rego/grants.json` (or the Rego `data.mcp.grants` document, depending on your deployment).

### Add a grant for a client

```json
{
  "client-id-of-caller": {
    "allowed_tools": ["my-service-search"],
    "allowed_tags":  ["search"],
    "max_risk_level": "medium"
  }
}
```

The grant must include your tool's `name` (not `tool_id`) in `allowed_tools`, **or** one of its `tags` in `allowed_tags`.

### Test the grant

```bash
# Evaluate the policy for your tool before going live
# Use tool "name" (not tool_id), client_roles array, and tool_risk_level
curl -X POST "$PLATFORM_URL/api/v1/policy/evaluate" \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "input": {
      "client_id": "alice@corp",
      "client_roles": ["agent"],
      "tool_name": "my-service-search",
      "tool_risk_level": "low",
      "params": {}
    }
  }'
```

Expected when grant is in place:
```json
{"allow": true, "reasons": [], "evaluated_at": "...", "opa_decision_id": "..."}
```

---

## 9. Step 7 — Maintain and version your server

### Updating a tool

Register a new version. The old version remains in the registry in its current state.

```bash
curl -X POST "$PLATFORM_URL/api/v1/tools/register" \
  ... --data '{"name":"my-service-search","version":"1.1.0",...}'
```

Deprecate the old version when clients have migrated:

```bash
curl -X PATCH "$PLATFORM_URL/api/v1/tools/$OLD_TOOL_ID" \
  -H "Authorization: Bearer $ADMIN_KEY" \
  -d '{"status":"deprecated"}'
```

### Health monitoring

The platform checks your server's health via `GET {upstream_url_base}/health`. Return:

```json
{"status": "ok", "version": "1.1.0"}
```

If health checks fail for 3 consecutive minutes, the tool is automatically quarantined.

### Audit log

Every invocation of your tool is logged:

```bash
curl "$PLATFORM_URL/api/v1/audit/events?tool_id=$TOOL_ID&limit=20" \
  -H "Authorization: Bearer $ADMIN_KEY"
```

Fields: `event_id`, `client_id`, `tool_name`, `outcome`, `latency_ms`, `sha256_hash`, `created_at`.

---

## 10. Reference: registration fields

| Field | Type | Required | Notes |
|-------|------|----------|-------|
| `name` | string | Yes | Lowercase, hyphens only, max 64 chars. Unique per version. |
| `version` | string | Yes | Semver: `1.0.0`. Same name+version → 409 conflict. |
| `description` | string | Yes | Scanned by TMA. Be precise and scoped. Max 1000 chars. |
| `schema` | JSON Schema | Yes | Describes tool call parameters. Used for validation and risk assessment. |
| `upstream_url` | string (URL) | Yes | Where the proxy forwards matching tool calls. Must be reachable from the proxy container. |
| `source_repo` | string | No | Git repo URL. Improves SBOM traceability. |
| `source_commit` | string | No | Full 40-char SHA preferred. |
| `tags` | string[] | No | Used for OPA `allowed_tags` grants. |
| `metadata` | object | No | Arbitrary JSONB. Stored; not evaluated. |

> **Credential injection fields** (`injection_mode`, `inject_header`, `inject_prefix`, `service_name`, `kc_client_id`, `kc_token_audience`) are **not accepted** by `POST /tools/register`. Set them after registration using `PUT /admin/credentials/{tool_id}/injection-mode` (see Step 5).

---

## 11. Reference: risk levels

| Level | Score range | Default status | Invocable immediately? |
|-------|------------|----------------|----------------------|
| `low` | 0–24 | `active` | Yes |
| `medium` | 25–49 | `active` | Yes |
| `high` | 50–74 | `active` | Yes — but anomaly detection is more sensitive |
| `critical` | 75–100 | `quarantined` | No — requires admin approval |

---

## 12. Troubleshooting

| Symptom | Likely cause | Fix |
|---------|-------------|-----|
| Registration → 400 validation error | Missing `description` or invalid semver | Add `description`; use `"1.0.0"` not `"v1.0"` |
| `status: quarantined` | `risk_level: critical` | Check `risk_reasons` in the response; fix description or schema |
| 409 on re-register | Same name+version exists | Bump version to `1.0.1` |
| Policy returns `{"allow":false}` | No OPA grant for this client+tool | Add grant to `policies/rego/grants.json` |
| Tool invocation → 502 | Proxy can't reach upstream | Verify container is on `internal-net`; check container name |
| Credential not injected | `injection_mode` is `none` or credential not uploaded | Set mode at registration; upload credential via admin API |
| Health check quarantine | `/health` returns non-200 or is unreachable | Ensure `/health` endpoint exists; check network connectivity |
