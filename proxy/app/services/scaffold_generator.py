"""
Scaffold generator — produces a starter MCP server package tailored to the
selected injection mode and data profile.

Returns a dict of {filename: content} that the submission router zips and
streams to the submitter.
"""
from __future__ import annotations

_SERVER_TEMPLATES: dict[str, str] = {
    "kc_token_exchange": '''\
"""
{name} — MCP server using Keycloak token exchange (same-IdP).

The platform broker exchanges the caller's session token for a short-lived
service-specific token before forwarding the request.  No credential is stored
at rest.  Your server validates the token from X-Authorization.
"""
from mcphub_sdk import PlatformMCPServer, identity, credential

srv = PlatformMCPServer("{name}", require_proxy=True)

@srv.tool()
async def example_tool(query: str) -> dict:
    who = identity()           # sub + role injected by the proxy
    token = credential()       # exchanged token — do NOT log
    # TODO: use token to call your upstream service
    return {{"result": "...", "caller": who.sub}}

if __name__ == "__main__":
    srv.run()
''',

    "entra_client_credentials": '''\
"""
{name} — MCP server using Microsoft Entra client credentials (machine identity).

The platform broker obtains a client-credentials token from Entra and injects it
into X-Authorization.  All calls appear as the app's service principal — no
per-user identity is preserved in the upstream system.
"""
from mcphub_sdk import PlatformMCPServer, identity, credential

srv = PlatformMCPServer("{name}", require_proxy=True)

@srv.tool()
async def example_tool(query: str) -> dict:
    who = identity()           # gateway user (attribution in audit log)
    token = credential()       # Entra access token — do NOT log
    # TODO: use token to call Microsoft Graph or your Azure resource
    return {{"result": "...", "gateway_user": who.sub}}

if __name__ == "__main__":
    srv.run()
''',

    "entra_user_token": '''\
"""
{name} — MCP server using Microsoft Entra delegated (per-user) token.

The platform broker performs delegated OAuth to obtain a per-user Entra token.
Each caller is represented by their own Entra identity in the upstream system.
"""
from mcphub_sdk import PlatformMCPServer, identity, credential

srv = PlatformMCPServer("{name}", require_proxy=True)

@srv.tool()
async def example_tool(query: str) -> dict:
    who = identity()           # sub matches the Entra user
    token = credential()       # per-user delegated Entra token — do NOT log
    # TODO: use token to call Microsoft Graph on behalf of this user
    return {{"result": "...", "entra_user": who.sub}}

if __name__ == "__main__":
    srv.run()
''',

    "service": '''\
"""
{name} — MCP server using a shared service-account token.

The platform broker injects a single shared credential into every request.
All upstream calls use one identity — attribution is at the gateway level only.

Set the token via the platform credential store after your server is approved.
"""
from mcphub_sdk import PlatformMCPServer, identity, credential

# credential_env: fallback for local dev only (never used when proxied)
srv = PlatformMCPServer("{name}", credential_env="SERVICE_TOKEN", require_proxy=True)

@srv.tool()
async def example_tool(query: str) -> dict:
    who = identity()           # gateway user (for audit; upstream sees service account)
    token = credential()       # shared service token — do NOT log
    # TODO: use token to call your upstream API
    return {{"result": "...", "gateway_user": who.sub}}

if __name__ == "__main__":
    srv.run()
''',

    "service_account": '''\
"""
{name} — MCP server using a shared OAuth service-account token.

Similar to "service" mode but the upstream IdP is external OAuth.
The platform broker injects a single shared credential into every request.
"""
from mcphub_sdk import PlatformMCPServer, identity, credential

srv = PlatformMCPServer("{name}", credential_env="OAUTH_SERVICE_TOKEN", require_proxy=True)

@srv.tool()
async def example_tool(query: str) -> dict:
    who = identity()
    token = credential()       # shared OAuth token — do NOT log
    return {{"result": "...", "gateway_user": who.sub}}

if __name__ == "__main__":
    srv.run()
''',

    "user": '''\
"""
{name} — MCP server using per-user stored tokens.

The platform broker looks up and injects the calling user's stored credential.
Each user must enroll their token via the portal before they can call this server.
The upstream system sees individual user identities — full attribution preserved.

Identity comes from X-User-Sub (proxy-injected). NEVER trust a tool parameter
for the user's identity — it is forgeable.
"""
from __future__ import annotations
import contextvars
from mcphub_sdk import PlatformMCPServer, identity, credential
from starlette.middleware.base import BaseHTTPMiddleware

_caller_sub: contextvars.ContextVar[str] = contextvars.ContextVar("_caller_sub", default="anonymous")

srv = PlatformMCPServer("{name}", require_proxy=True)

class _IdentityMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        tok = _caller_sub.set(request.headers.get("x-user-sub", "anonymous"))
        try:
            return await call_next(request)
        finally:
            _caller_sub.reset(tok)

srv.app.add_middleware(_IdentityMiddleware)

@srv.tool()
async def example_tool(query: str) -> dict:
    user_sub = _caller_sub.get()    # from proxy header — not forgeable
    token = credential()            # this user's stored token — do NOT log
    # TODO: use token to call your upstream API as this specific user
    return {{"result": "...", "user": user_sub}}

if __name__ == "__main__":
    srv.run(stateless_http=True)   # required for ContextVar to work
''',

    "oauth_user_token": '''\
"""
{name} — MCP server using per-user external OAuth tokens.

The platform broker handles the OAuth flow with the external IdP and injects
per-user access tokens.  Each caller gets their own token.
"""
from mcphub_sdk import PlatformMCPServer, identity, credential

srv = PlatformMCPServer("{name}", require_proxy=True)

@srv.tool()
async def example_tool(query: str) -> dict:
    who = identity()
    token = credential()    # per-user OAuth token for external IdP — do NOT log
    return {{"result": "...", "user": who.sub}}

if __name__ == "__main__":
    srv.run()
''',

    "none": '''\
"""
{name} — MCP server with no credential injection (public or internally-trusted).

No authentication is injected by the platform.  Your server is responsible for
any access control it needs — or it is intentionally open within the trust boundary.
"""
from mcphub_sdk import PlatformMCPServer, identity

srv = PlatformMCPServer("{name}", require_proxy=False)

@srv.tool()
async def example_tool(query: str) -> dict:
    who = identity()    # will be "anonymous" for unauthenticated callers
    return {{"result": "...", "caller": who.sub}}

if __name__ == "__main__":
    srv.run()
''',
}

_REQUIREMENTS = """\
mcphub-sdk>=0.1.0
fastmcp>=0.1.0
httpx>=0.27.0
"""

_DOCKERFILE = """\
FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY server.py .

# The platform expects your server on port 8000 with stateless HTTP transport
EXPOSE 8000
CMD ["python", "server.py"]
"""

_README_TEMPLATE = """\
# {name}

MCP server registered with the MCP Security Platform.

## Auth mode: `{mode}`

{mode_notes}

## What the platform injects

| Header | Content |
|--------|---------|
| `X-User-Sub` | The authenticated caller's identity (sub from OIDC token) |
| `X-User-Role` | The caller's platform role |
| `X-Authorization` | The injected credential (mode-specific — see `credential()`) |

**Never trust a tool parameter as a user identity.** Always call `identity()` inside
the tool body.  Never log the return value of `credential()`.

## Running locally

```bash
pip install -r requirements.txt
# Set a dev credential for local testing (not used when proxied):
export SERVICE_TOKEN=dev-token
python server.py
```

## Health endpoint

The platform probes `/health` before tool discovery.  `PlatformMCPServer` adds
this automatically — no extra code needed.

## Submitting to the platform

1. Push this code to a GitHub repo
2. Return to the submission wizard and provide your repo URL
3. After approval, deploy your server and provide the running URL
4. The platform will discover your tools automatically
"""

_MODE_NOTES: dict[str, str] = {
    "kc_token_exchange": "The platform exchanges the caller's Keycloak session token for a short-lived token scoped to your service. No secret stored at rest. Full per-user attribution.",
    "entra_client_credentials": "The platform obtains a client-credentials token from Microsoft Entra using a registered app. All calls use the app's service principal — no per-user attribution in the upstream system.",
    "entra_user_token": "The platform obtains a delegated Entra token for each caller. Full per-user attribution in the upstream system.",
    "service": "One shared service-account credential is injected for all callers. Attribution is at the gateway layer only.",
    "service_account": "One shared OAuth token for all callers. Attribution is at the gateway layer only.",
    "user": "Each user's stored credential is injected. Full per-user attribution. Users must enroll their credentials via the portal before calling your server.",
    "oauth_user_token": "Per-user OAuth tokens from an external IdP are injected. Full per-user attribution.",
    "none": "No credential is injected. Your server is public within the platform trust boundary or handles its own auth.",
}


_PROMPTS: dict[str, list[dict]] = {
    "kc_token_exchange": [
        {"id": "tool_list",    "prompt": "List every action a user can perform on this service. For each, write: name (snake_case), one-sentence description, input parameters (name, type, required), and whether it's read-only or mutating."},
        {"id": "auth_flow",    "prompt": "The platform will exchange the caller's Keycloak session token for a short-lived token scoped to your service. Describe what audience value your service expects in the token and any required scopes."},
        {"id": "error_cases",  "prompt": "What should happen if the injected token is expired or the upstream API returns 401? Describe the expected error response your MCP tool should return."},
    ],
    "entra_client_credentials": [
        {"id": "tool_list",    "prompt": "List every action this server exposes. For each: name, description, parameters, read/write, and which Microsoft Graph or Azure API endpoint it calls."},
        {"id": "scopes",       "prompt": "Which Microsoft Graph API permissions (application permissions, not delegated) does this server need? List each permission and why it's required."},
        {"id": "attribution",  "prompt": "This mode uses a shared app identity — all calls appear as the app service principal. How will you distinguish individual users in your logs for audit purposes?"},
    ],
    "entra_user_token": [
        {"id": "tool_list",    "prompt": "List every action this server exposes. For each: name, description, parameters, and which delegated Graph permission it requires."},
        {"id": "scopes",       "prompt": "Which Microsoft Graph delegated permissions does this server need per user? Explain what each permission allows the user to do."},
        {"id": "data_access",  "prompt": "Describe what data each tool can access on behalf of the user. Can tools access other users' data? What prevents cross-user data access?"},
    ],
    "service": [
        {"id": "tool_list",    "prompt": "List every action this server exposes. For each: name, description, parameters, whether it's read-only or mutating, and what upstream API it calls."},
        {"id": "credential",   "prompt": "What type of credential does your upstream service require? Describe the header name, token format (Bearer JWT, API key, Basic auth, etc.), and how your server should validate responses."},
        {"id": "attribution",  "prompt": "This mode uses a shared service account. How will audit trails identify individual users? The platform injects the caller's identity in X-User-Sub — describe how your server should log or propagate this."},
    ],
    "user": [
        {"id": "tool_list",    "prompt": "List every action this server exposes per user. For each: name, description, parameters, and what the user must have set up before they can call it."},
        {"id": "enrollment",   "prompt": "Describe the credential each user needs to enroll. What is the format (API key, OAuth token, username+password)? How does a user obtain their credential for your upstream system?"},
        {"id": "isolation",    "prompt": "How does your server ensure that user A cannot access user B's data? Describe the data isolation mechanism — the platform injects user identity via X-User-Sub, never via tool parameters."},
    ],
    "oauth_user_token": [
        {"id": "tool_list",    "prompt": "List every action this server exposes per user. For each: name, description, parameters, and required OAuth scopes."},
        {"id": "idp_setup",    "prompt": "Describe your external OAuth IdP setup: issuer URL, authorization endpoint, required scopes, and how users authorize access the first time."},
        {"id": "token_use",    "prompt": "How does your server use the injected OAuth access token? Describe the API calls it makes and what happens when the token expires mid-session."},
    ],
    "none": [
        {"id": "tool_list",    "prompt": "List every action this server exposes. For each: name, description, and parameters. Since there is no credential injection, explain how access control works (if at all)."},
        {"id": "trust_model",  "prompt": "This server has no credential injection. Who is allowed to call it and why is that safe? Describe the trust boundary this server operates within."},
    ],
}

_SHARED_PROMPTS = [
    {"id": "health",       "prompt": "The platform probes GET /health before registering your server. Describe what your health endpoint checks (e.g. upstream reachable, DB connected) and what it returns on success vs failure."},
    {"id": "error_format", "prompt": "Describe the error format your MCP tools return when something goes wrong. The platform expects a dict with at least an 'error' key. Include examples for auth failure, upstream timeout, and validation error."},
    {"id": "idempotency",  "prompt": "Which of your tools are idempotent (safe to retry)? Which are not? For non-idempotent tools, what should a caller do if they don't receive a response?"},
]


def generate_prompts(injection_mode: str) -> list[dict]:
    """Return a list of {id, prompt} dicts for the no-code LLM-assisted design flow."""
    mode = injection_mode if injection_mode in _PROMPTS else "none"
    return _PROMPTS[mode] + _SHARED_PROMPTS


def generate_scaffold(server_name: str, injection_mode: str) -> dict[str, str]:
    """
    Returns {filename: content} for the scaffold zip.
    Falls back to 'none' template if mode is unknown.
    """
    # validation LOW: an unrecognised injection_mode was silently downgraded to
    # 'none' (no credential injection) — a dev could ship a scaffold with no auth
    # unknowingly. Detect the downgrade and SURFACE it prominently rather than
    # hide it. (An explicit "none"/empty request is not a downgrade.)
    requested = (injection_mode or "none")
    downgraded = requested not in _SERVER_TEMPLATES and requested != "none"
    mode = injection_mode if injection_mode in _SERVER_TEMPLATES else "none"
    server_code = _SERVER_TEMPLATES[mode].format(name=server_name)
    readme = _README_TEMPLATE.format(
        name=server_name,
        mode=mode,
        mode_notes=_MODE_NOTES.get(mode, ""),
    )
    if downgraded:
        warning = (
            f"# ⚠️  WARNING: requested injection_mode '{requested}' is NOT a recognised mode.\n"
            f"# This scaffold was generated with injection_mode='none' — it performs NO\n"
            f"# credential injection. If you intended an authenticated upstream, pick a valid\n"
            f"# mode (kc_token_exchange / service / user / entra_* / oauth_user_token) and\n"
            f"# regenerate. Do not ship this as-is expecting credentials to be injected.\n\n"
        )
        server_code = warning + server_code
        readme = (f"> ⚠️ **Requested mode `{requested}` was not recognised — scaffolded as `none` "
                  f"(no credential injection).** Regenerate with a valid mode if that's not intended.\n\n"
                  + readme)
    files = {
        "server.py": server_code,
        "requirements.txt": _REQUIREMENTS,
        "Dockerfile": _DOCKERFILE,
        "README.md": readme,
    }
    return files
