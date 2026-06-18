"""
Mock OAuth 2.1 / OIDC Identity Provider for MCP Security Platform lab.

Endpoints
---------
GET  /.well-known/oauth-authorization-server  OAuth 2.1 server metadata (RFC 8414)
GET  /oauth/jwks                              JWKS — RS256 public key
POST /oauth/register                          Dynamic Client Registration (RFC 7591)
GET  /oauth/authorize                         Authorization UI (click-to-login)
POST /oauth/authorize                         Issue authorization code
POST /oauth/token                             Exchange code or device_code for JWT
GET  /oauth/userinfo                          Return claims for current token
POST /oauth/device                            Device Authorization Request (RFC 8628)
GET  /activate                                Device activation — user_code entry
POST /activate                                Validate user_code, show user chooser
POST /activate/confirm                        Apply approval/denial

Users (preconfigured, no passwords — just click)
-------------------------------------------------
alice@corp  roles: [analyst]   → Grafana + NetBox read
bob@corp    roles: [viewer]    → Grafana read only
admin@corp  roles: [admin]     → full access (all MCP servers)
Reject button returns access_denied to the redirect_uri.
"""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import secrets
import time
from typing import Any

import uvicorn
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

# ---------------------------------------------------------------------------
# Runtime configuration
# ---------------------------------------------------------------------------
HOST = os.environ.get("HOST", "0.0.0.0")
PORT = int(os.environ.get("PORT", "8888"))
ISSUER = os.environ.get("MOCK_IDP_ISSUER", f"http://localhost:{PORT}")
TOKEN_TTL = int(os.environ.get("TOKEN_TTL_SECONDS", "3600"))
CODE_TTL = int(os.environ.get("CODE_TTL_SECONDS", "300"))

# ---------------------------------------------------------------------------
# RSA key pair — generated once on startup, held in memory
# The proxy fetches the JWKS and caches it; no persistence needed.
# ---------------------------------------------------------------------------
_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_public_key = _private_key.public_key()

_KID = "mock-idp-key-1"


def _jwks_params() -> dict[str, Any]:
    nums = _public_key.public_numbers()
    def _b64(n: int, length: int) -> str:
        return base64.urlsafe_b64encode(n.to_bytes(length, "big")).rstrip(b"=").decode()
    e_len = (nums.e.bit_length() + 7) // 8
    n_len = (nums.n.bit_length() + 7) // 8
    return {"e": _b64(nums.e, e_len), "n": _b64(nums.n, n_len)}


# ---------------------------------------------------------------------------
# User catalogue
# ---------------------------------------------------------------------------
USERS: dict[str, dict[str, Any]] = {
    "alice@corp": {
        "name": "Alice Analyst",
        "roles": ["analyst"],
        "color": "#2563eb",
        "emoji": "🔵",
        "description": "Grafana + NetBox read",
    },
    "bob@corp": {
        "name": "Bob Viewer",
        "roles": ["viewer"],
        "color": "#16a34a",
        "emoji": "🟢",
        "description": "Grafana read only",
    },
    "admin@corp": {
        "name": "Admin",
        "roles": ["admin"],
        "color": "#dc2626",
        "emoji": "🔴",
        "description": "Full access — all MCP servers",
    },
}

# ---------------------------------------------------------------------------
# In-memory stores (single-instance, lab only)
# ---------------------------------------------------------------------------
_pending_codes: dict[str, dict[str, Any]] = {}      # code → {sub, client_id, pkce_challenge, exp}
_issued_tokens: dict[str, str] = {}                 # jti → sub (for userinfo)
_registered_clients: dict[str, dict[str, Any]] = {} # client_id → metadata (RFC 7591)

# RFC 8628 Device Authorization Grant store
# device_code → {user_code, client_id, client_ip, device_challenge, status, sub, exp, interval}
# status: "pending" | "approved" | "denied" | "consumed"
_device_codes: dict[str, dict[str, Any]] = {}
_user_code_index: dict[str, str] = {}               # user_code → device_code (for activation lookup)

DEVICE_CODE_TTL = int(os.environ.get("DEVICE_CODE_TTL_SECONDS", "300"))
DEVICE_POLL_INTERVAL = 5

# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------
app = FastAPI(title="Mock IdP", docs_url=None, redoc_url=None)


# ---------------------------------------------------------------------------
# OAuth 2.1 server metadata  (RFC 8414 + MCP spec §4.2)
# ---------------------------------------------------------------------------
@app.get("/.well-known/oauth-authorization-server")
async def server_metadata():
    return {
        "issuer": ISSUER,
        "authorization_endpoint": f"{ISSUER}/oauth/authorize",
        "token_endpoint": f"{ISSUER}/oauth/token",
        "device_authorization_endpoint": f"{ISSUER}/oauth/device",
        "registration_endpoint": f"{ISSUER}/oauth/register",
        "jwks_uri": f"{ISSUER}/oauth/jwks",
        "userinfo_endpoint": f"{ISSUER}/oauth/userinfo",
        "response_types_supported": ["code"],
        "grant_types_supported": [
            "authorization_code",
            "urn:ietf:params:oauth:grant-type:device_code",
        ],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none", "client_secret_post"],
        "scopes_supported": ["openid", "profile", "email"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
    }


@app.post("/oauth/register", status_code=201)
async def dynamic_client_registration(request: Request):
    """RFC 7591 Dynamic Client Registration — accepts any client, returns client_id."""
    body = await request.json()
    client_id = f"dyn-{secrets.token_urlsafe(12)}"
    client_secret = secrets.token_urlsafe(24)
    client_record = {
        "client_id": client_id,
        "client_secret": client_secret,
        "client_id_issued_at": int(time.time()),
        "redirect_uris": body.get("redirect_uris", []),
        "client_name": body.get("client_name", "dynamic-client"),
        "grant_types": body.get("grant_types", ["authorization_code"]),
        "response_types": body.get("response_types", ["code"]),
        "token_endpoint_auth_method": body.get("token_endpoint_auth_method", "none"),
        "scope": body.get("scope", "openid profile email"),
    }
    _registered_clients[client_id] = client_record
    logger.info("Dynamic client registered: client_id=%s name=%s", client_id, client_record["client_name"])
    return client_record


@app.get("/oauth/jwks")
async def jwks():
    params = _jwks_params()
    return {
        "keys": [{
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": _KID,
            **params,
        }]
    }


# ---------------------------------------------------------------------------
# Device Authorization Grant  (RFC 8628 + two-layer session attestation)
# ---------------------------------------------------------------------------

def _generate_user_code() -> str:
    """8-char user code in XXXX-XXXX format (RFC 8628 §6.1 character set)."""
    chars = "BCDFGHJKLMNPQRSTVWXZ"  # consonant-only: no vowels → no accidental words
    raw = "".join(secrets.choice(chars) for _ in range(8))
    return f"{raw[:4]}-{raw[4:]}"


def _purge_expired_device_codes() -> None:
    now = time.time()
    expired = [dc for dc, v in _device_codes.items() if v["exp"] < now]
    for dc in expired:
        entry = _device_codes.pop(dc, {})
        _user_code_index.pop(entry.get("user_code", ""), None)


@app.post("/oauth/device")
async def device_authorization(request: Request):
    """
    RFC 8628 §3.1 — Device Authorization Request.

    Two-layer session attestation:
      Layer 1 — IP binding:     client IP captured here, enforced at poll time.
      Layer 2 — PKCE-style:     client sends device_challenge = BASE64URL(SHA256(device_verifier)).
                                 The verifier must be supplied at /oauth/token. An attacker who
                                 captures the device_code cannot redeem it without the verifier.
    """
    _purge_expired_device_codes()

    form = await request.form()
    client_id = str(form.get("client_id", ""))
    # Layer 2: optional device_challenge (SHA256 of device_verifier, base64url, no padding)
    device_challenge = str(form.get("device_challenge", ""))
    client_ip = request.client.host if request.client else "unknown"

    device_code = secrets.token_urlsafe(32)
    user_code = _generate_user_code()
    exp = time.time() + DEVICE_CODE_TTL

    _device_codes[device_code] = {
        "user_code": user_code,
        "client_id": client_id,
        "client_ip": client_ip,
        "device_challenge": device_challenge,
        "status": "pending",
        "sub": None,
        "exp": exp,
        "interval": DEVICE_POLL_INTERVAL,
    }
    _user_code_index[user_code] = device_code

    logger.info(
        "Device code issued: client=%s client_ip=%s challenge_set=%s",
        client_id, client_ip, bool(device_challenge),
    )
    return JSONResponse({
        "device_code": device_code,
        "user_code": user_code,
        "verification_uri": f"{ISSUER}/activate",
        "verification_uri_complete": f"{ISSUER}/activate?user_code={user_code}",
        "expires_in": DEVICE_CODE_TTL,
        "interval": DEVICE_POLL_INTERVAL,
    })


@app.get("/activate", response_class=HTMLResponse)
async def activate_ui(user_code: str = ""):
    """Device activation page — user enters user_code (or it's pre-filled via link)."""
    prefill = f'value="{user_code}"' if user_code else 'placeholder="XXXX-XXXX"'
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Activate Device — Mock IdP</title>
  <style>
    body {{font-family:system-ui,sans-serif;background:#0f172a;color:#e2e8f0;
           display:flex;flex-direction:column;align-items:center;justify-content:center;min-height:100vh;margin:0}}
    .card {{background:#1e293b;border-radius:16px;padding:40px;width:420px;box-shadow:0 8px 32px #0005}}
    h1 {{margin:0 0 4px;font-size:1.4rem}}
    .subtitle {{color:#94a3b8;margin:0 0 28px;font-size:.9rem}}
    input[type=text] {{width:100%;padding:12px;font-size:1.2rem;text-align:center;letter-spacing:.2em;
                        border-radius:8px;border:2px solid #334155;background:#0f172a;color:#e2e8f0;
                        box-sizing:border-box;margin-bottom:16px}}
    input[type=text]:focus {{outline:none;border-color:#3b82f6}}
    .btn {{background:#3b82f6;color:#fff;border:none;padding:14px 32px;font-size:1rem;
           border-radius:8px;cursor:pointer;width:100%}}
    .btn:hover {{background:#2563eb}}
    .error {{background:#450a0a;border:1px solid #dc2626;border-radius:8px;padding:12px 16px;
             color:#fca5a5;margin-bottom:16px;font-size:.9rem}}
  </style>
</head>
<body>
  <div class="card">
    <h1>📱 Activate Device</h1>
    <p class="subtitle">Enter the code shown on your device or CLI.</p>
    <form method="POST" action="/activate">
      <input type="text" name="user_code" {prefill} maxlength="9" autocomplete="off" autocapitalize="characters" spellcheck="false">
      <button class="btn" type="submit">Continue →</button>
    </form>
  </div>
</body>
</html>"""
    return HTMLResponse(html)


@app.post("/activate", response_class=HTMLResponse)
async def activate_submit(request: Request, user_code: str = Form(...)):
    """Validate user_code → show user selection buttons."""
    _purge_expired_device_codes()

    normalized = user_code.strip().upper()
    device_code = _user_code_index.get(normalized)
    entry = _device_codes.get(device_code or "")

    if not entry or time.time() > entry["exp"]:
        error_html = """<div class="error">⚠ Code not found or expired. Check your device and try again.</div>"""
        html = f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>Activate Device</title>
<style>
  body{{font-family:system-ui,sans-serif;background:#0f172a;color:#e2e8f0;display:flex;flex-direction:column;align-items:center;justify-content:center;min-height:100vh;margin:0}}
  .card{{background:#1e293b;border-radius:16px;padding:40px;width:420px;box-shadow:0 8px 32px #0005}}
  h1{{margin:0 0 4px;font-size:1.4rem}} .subtitle{{color:#94a3b8;margin:0 0 28px;font-size:.9rem}}
  input[type=text]{{width:100%;padding:12px;font-size:1.2rem;text-align:center;letter-spacing:.2em;border-radius:8px;border:2px solid #334155;background:#0f172a;color:#e2e8f0;box-sizing:border-box;margin-bottom:16px}}
  input[type=text]:focus{{outline:none;border-color:#3b82f6}}
  .btn{{background:#3b82f6;color:#fff;border:none;padding:14px 32px;font-size:1rem;border-radius:8px;cursor:pointer;width:100%}}
  .btn:hover{{background:#2563eb}}
  .error{{background:#450a0a;border:1px solid #dc2626;border-radius:8px;padding:12px 16px;color:#fca5a5;margin-bottom:16px;font-size:.9rem}}
</style></head>
<body>
  <div class="card">
    <h1>📱 Activate Device</h1>
    <p class="subtitle">Enter the code shown on your device or CLI.</p>
    {error_html}
    <form method="POST" action="/activate">
      <input type="text" name="user_code" placeholder="XXXX-XXXX" maxlength="9" autocomplete="off">
      <button class="btn" type="submit">Try again</button>
    </form>
  </div>
</body></html>"""
        return HTMLResponse(html, status_code=400)

    if entry["status"] != "pending":
        return HTMLResponse(
            "<body style='font-family:system-ui;background:#0f172a;color:#e2e8f0;display:flex;align-items:center;justify-content:center;min-height:100vh'>"
            "<div style='text-align:center'><h2>⚠ This code has already been used.</h2><p>Return to your device.</p></div></body>",
            status_code=400,
        )

    user_buttons = ""
    for email, info in USERS.items():
        user_buttons += f"""
        <button type="submit" name="sub" value="{email}"
                style="background:{info['color']};color:#fff;border:none;
                       padding:16px 32px;font-size:1.1rem;border-radius:8px;
                       cursor:pointer;margin:8px;min-width:280px;text-align:left;">
          {info['emoji']} {info['name']}<br>
          <small style="opacity:.85">{email} · {info['description']}</small>
        </button>
        """

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Approve Device — Mock IdP</title>
  <style>
    body {{font-family:system-ui,sans-serif;background:#0f172a;color:#e2e8f0;
           display:flex;flex-direction:column;align-items:center;justify-content:center;min-height:100vh;margin:0}}
    .card {{background:#1e293b;border-radius:16px;padding:40px;width:420px;box-shadow:0 8px 32px #0005}}
    h1 {{margin:0 0 4px;font-size:1.4rem}}
    .subtitle {{color:#94a3b8;margin:0 0 28px;font-size:.9rem}}
    .code-badge {{background:#0f172a;border-radius:8px;padding:8px 16px;font-size:1.4rem;letter-spacing:.2em;
                  font-weight:bold;color:#60a5fa;margin-bottom:24px;display:inline-block}}
    .divider {{border:none;border-top:1px solid #334155;margin:24px 0}}
    .reject {{background:#334155;color:#94a3b8;border:none;padding:12px 24px;
              font-size:.95rem;border-radius:8px;cursor:pointer;width:100%;margin-top:4px}}
    .reject:hover {{background:#475569}}
  </style>
</head>
<body>
  <div class="card">
    <h1>🔐 Approve Device Access</h1>
    <p class="subtitle">Authorising code: <span class="code-badge">{normalized}</span></p>
    <p style="color:#94a3b8;font-size:.9rem;margin-bottom:20px">Sign in as:</p>
    <form method="POST" action="/activate/confirm">
      <input type="hidden" name="device_code" value="{device_code}">
      {user_buttons}
      <hr class="divider">
      <button class="reject" type="submit" name="sub" value="__deny__">
        ⛔ Deny Access
      </button>
    </form>
  </div>
</body>
</html>"""
    return HTMLResponse(html)


@app.post("/activate/confirm", response_class=HTMLResponse)
async def activate_confirm(
    device_code: str = Form(...),
    sub: str = Form(...),
):
    """Apply user's approval/denial decision to the device code."""
    entry = _device_codes.get(device_code)
    if not entry or time.time() > entry["exp"] or entry["status"] != "pending":
        return HTMLResponse(
            "<body style='font-family:system-ui;background:#0f172a;color:#e2e8f0;display:flex;align-items:center;justify-content:center;min-height:100vh'>"
            "<div style='text-align:center'><h2>⚠ Session expired or already used.</h2></div></body>",
            status_code=400,
        )

    if sub == "__deny__":
        entry["status"] = "denied"
        logger.info("Device code denied by user: client=%s", entry["client_id"])
        return HTMLResponse(
            "<body style='font-family:system-ui;background:#0f172a;color:#e2e8f0;display:flex;align-items:center;justify-content:center;min-height:100vh'>"
            "<div style='text-align:center'><h2>⛔ Access denied.</h2><p style=\"color:#94a3b8\">You can close this window.</p></div></body>"
        )

    if sub not in USERS:
        return HTMLResponse(
            "<body style='font-family:system-ui;background:#0f172a;color:#e2e8f0;display:flex;align-items:center;justify-content:center;min-height:100vh'>"
            "<div style='text-align:center'><h2>⚠ Unknown user.</h2></div></body>",
            status_code=400,
        )

    entry["status"] = "approved"
    entry["sub"] = sub
    logger.info("Device code approved: sub=%s client=%s", sub, entry["client_id"])

    user = USERS[sub]
    return HTMLResponse(
        f"<body style='font-family:system-ui;background:#0f172a;color:#e2e8f0;display:flex;align-items:center;justify-content:center;min-height:100vh'>"
        f"<div style='text-align:center'>"
        f"<div style='font-size:4rem'>{user['emoji']}</div>"
        f"<h2 style='color:#4ade80'>✓ Authorised as {user['name']}</h2>"
        f"<p style='color:#94a3b8'>Return to your device — it will complete automatically.</p>"
        f"</div></body>"
    )


# ---------------------------------------------------------------------------
# Authorization endpoint — GET shows the UI, POST issues the code
# ---------------------------------------------------------------------------
@app.get("/oauth/authorize", response_class=HTMLResponse)
async def authorize_ui(
    response_type: str = "code",
    client_id: str = "",
    redirect_uri: str = "",
    state: str = "",
    code_challenge: str = "",
    code_challenge_method: str = "S256",
    scope: str = "",
):
    if response_type != "code":
        return HTMLResponse("<h2>Unsupported response_type</h2>", status_code=400)

    user_buttons = ""
    for email, info in USERS.items():
        user_buttons += f"""
        <button type="submit" name="sub" value="{email}"
                style="background:{info['color']};color:#fff;border:none;
                       padding:16px 32px;font-size:1.1rem;border-radius:8px;
                       cursor:pointer;margin:8px;min-width:280px;text-align:left;">
          {info['emoji']} {info['name']}<br>
          <small style="opacity:.85">{email} · {info['description']}</small>
        </button>
        """

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Mock IdP — Sign In</title>
  <style>
    body {{font-family:system-ui,sans-serif;background:#0f172a;color:#e2e8f0;
           display:flex;flex-direction:column;align-items:center;justify-content:center;min-height:100vh;margin:0}}
    .card {{background:#1e293b;border-radius:16px;padding:40px;width:420px;box-shadow:0 8px 32px #0005}}
    h1 {{margin:0 0 4px;font-size:1.4rem}}
    .subtitle {{color:#94a3b8;margin:0 0 28px;font-size:.9rem}}
    .divider {{border:none;border-top:1px solid #334155;margin:24px 0}}
    .reject {{background:#334155;color:#94a3b8;border:none;padding:12px 24px;
              font-size:.95rem;border-radius:8px;cursor:pointer;width:100%;margin-top:4px}}
    .reject:hover {{background:#475569}}
    input[type=hidden] {{display:none}}
    .client-badge {{background:#0f172a;border-radius:6px;padding:4px 10px;
                    font-size:.8rem;color:#64748b;margin-bottom:20px;display:inline-block}}
  </style>
</head>
<body>
  <div class="card">
    <h1>🔐 Mock Identity Provider</h1>
    <p class="subtitle">MCP Security Platform Lab</p>
    <span class="client-badge">client: {client_id or 'unknown'}</span>
    <form method="POST">
      <input type="hidden" name="client_id" value="{client_id}">
      <input type="hidden" name="redirect_uri" value="{redirect_uri}">
      <input type="hidden" name="state" value="{state}">
      <input type="hidden" name="code_challenge" value="{code_challenge}">
      <input type="hidden" name="code_challenge_method" value="{code_challenge_method}">
      <input type="hidden" name="scope" value="{scope}">
      {user_buttons}
      <hr class="divider">
      <button class="reject" type="submit" name="sub" value="__reject__">
        ⛔ Deny Access
      </button>
    </form>
  </div>
</body>
</html>"""
    return HTMLResponse(html)


@app.post("/oauth/authorize")
async def authorize_submit(
    sub: str = Form(...),
    client_id: str = Form(""),
    redirect_uri: str = Form(""),
    state: str = Form(""),
    code_challenge: str = Form(""),
    code_challenge_method: str = Form("S256"),
    scope: str = Form(""),
):
    if not redirect_uri:
        return JSONResponse({"error": "missing redirect_uri"}, status_code=400)

    sep = "&" if "?" in redirect_uri else "?"

    # Deny path
    if sub == "__reject__":
        return RedirectResponse(
            f"{redirect_uri}{sep}error=access_denied&error_description=User+denied+access"
            + (f"&state={state}" if state else ""),
            status_code=302,
        )

    if sub not in USERS:
        return RedirectResponse(
            f"{redirect_uri}{sep}error=invalid_request&error_description=Unknown+user"
            + (f"&state={state}" if state else ""),
            status_code=302,
        )

    code = secrets.token_urlsafe(32)
    _pending_codes[code] = {
        "sub": sub,
        "client_id": client_id,
        "code_challenge": code_challenge,
        "code_challenge_method": code_challenge_method,
        "scope": scope,
        "exp": time.time() + CODE_TTL,
    }
    logger.info("Authorization code issued: sub=%s client=%s", sub, client_id)

    location = f"{redirect_uri}{sep}code={code}" + (f"&state={state}" if state else "")
    return RedirectResponse(location, status_code=302)


# ---------------------------------------------------------------------------
# Token endpoint
# ---------------------------------------------------------------------------
def _mint_token(sub: str, client_id: str, scope: str) -> dict[str, Any]:
    """Build and sign a JWT access token; return the full token response dict."""
    user = USERS[sub]
    now = int(time.time())
    jti = secrets.token_urlsafe(16)

    from jose import jwt as jose_jwt

    private_pem = _private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    claims = {
        "iss": ISSUER,
        "sub": sub,
        "aud": client_id or "mcp-proxy",
        "iat": now,
        "exp": now + TOKEN_TTL,
        "jti": jti,
        "email": sub,
        "name": user["name"],
        "roles": user["roles"],
    }
    access_token = jose_jwt.encode(claims, private_pem, algorithm="RS256", headers={"kid": _KID})
    _issued_tokens[jti] = sub
    logger.info("Token issued: sub=%s roles=%s", sub, user["roles"])
    return {
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": TOKEN_TTL,
        "scope": scope,
    }


@app.post("/oauth/token")
async def token(request: Request):
    form = await request.form()
    grant_type = form.get("grant_type", "")
    client_id = str(form.get("client_id", ""))

    # ── Device Authorization Grant (RFC 8628) ─────────────────────────────
    if grant_type == "urn:ietf:params:oauth:grant-type:device_code":
        return await _handle_device_token(request, form, client_id)

    # ── Client Credentials Grant (RFC 6749 §4.4) — app-only token for M365 mock ─
    if grant_type == "client_credentials":
        scope = str(form.get("scope", "https://graph.microsoft.com/.default"))
        client_secret = str(form.get("client_secret", ""))
        # Lab: accept any non-empty client_secret (no real validation needed)
        if not client_id:
            return JSONResponse({"error": "invalid_client", "error_description": "client_id required"}, status_code=400)
        now = int(time.time())
        jti = secrets.token_urlsafe(16)
        from jose import jwt as jose_jwt
        private_pem = _private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        claims = {
            "iss": ISSUER,
            "sub": client_id,
            "aud": "https://graph.microsoft.com",
            "iat": now,
            "exp": now + TOKEN_TTL,
            "jti": jti,
            "appid": client_id,
            "roles": ["Application"],
        }
        access_token = jose_jwt.encode(claims, private_pem, algorithm="RS256", headers={"kid": _KID})
        _issued_tokens[jti] = client_id
        logger.info("client_credentials token issued: client_id=%s scope=%s", client_id, scope)
        return JSONResponse({
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": TOKEN_TTL,
            "scope": scope,
        })

    if grant_type != "authorization_code":
        return JSONResponse({"error": "unsupported_grant_type"}, status_code=400)

    code = str(form.get("code", ""))
    redirect_uri = str(form.get("redirect_uri", ""))
    code_verifier = str(form.get("code_verifier", ""))

    entry = _pending_codes.pop(code, None)
    if not entry:
        return JSONResponse({"error": "invalid_grant", "error_description": "code not found or expired"}, status_code=400)

    if time.time() > entry["exp"]:
        return JSONResponse({"error": "invalid_grant", "error_description": "code expired"}, status_code=400)

    # PKCE S256 verification
    if entry.get("code_challenge"):
        if not code_verifier:
            return JSONResponse({"error": "invalid_grant", "error_description": "code_verifier required"}, status_code=400)
        digest = base64.urlsafe_b64encode(
            hashlib.sha256(code_verifier.encode()).digest()
        ).rstrip(b"=").decode()
        if not secrets.compare_digest(digest, entry["code_challenge"]):
            return JSONResponse({"error": "invalid_grant", "error_description": "PKCE verification failed"}, status_code=400)

    return JSONResponse(_mint_token(entry["sub"], client_id, entry.get("scope", "openid profile email")))


async def _handle_device_token(request: Request, form: Any, client_id: str) -> JSONResponse:
    """
    RFC 8628 §3.4 — Device Access Token Request.

    Enforces two-layer session attestation:
      Layer 1 — IP binding:     poll IP must match the IP that called /oauth/device.
      Layer 2 — PKCE verifier:  if device_challenge was set, device_verifier must match.
    Any violation immediately invalidates the device code (cannot be retried).
    """
    device_code = str(form.get("device_code", ""))
    device_verifier = str(form.get("device_verifier", ""))
    poll_ip = request.client.host if request.client else "unknown"

    entry = _device_codes.get(device_code)

    if not entry:
        return JSONResponse({"error": "invalid_grant", "error_description": "device_code not found or expired"}, status_code=400)

    if time.time() > entry["exp"]:
        _device_codes.pop(device_code, None)
        _user_code_index.pop(entry.get("user_code", ""), None)
        return JSONResponse({"error": "expired_token", "error_description": "device_code has expired"}, status_code=400)

    # ── Layer 1: IP binding ───────────────────────────────────────────────
    if poll_ip != entry["client_ip"]:
        logger.warning(
            "SECURITY: Device code IP mismatch — issued_ip=%s poll_ip=%s client=%s — INVALIDATING",
            entry["client_ip"], poll_ip, client_id,
        )
        entry["status"] = "consumed"  # poison the entry so it can't be retried
        _device_codes.pop(device_code, None)
        _user_code_index.pop(entry.get("user_code", ""), None)
        return JSONResponse(
            {"error": "invalid_grant", "error_description": "IP binding violation — device code invalidated"},
            status_code=400,
        )

    # ── Layer 2: PKCE-style device_verifier ──────────────────────────────
    if entry.get("device_challenge"):
        if not device_verifier:
            logger.warning(
                "SECURITY: Device code missing verifier — challenge was set — client=%s poll_ip=%s",
                client_id, poll_ip,
            )
            _device_codes.pop(device_code, None)
            _user_code_index.pop(entry.get("user_code", ""), None)
            return JSONResponse(
                {"error": "invalid_grant", "error_description": "device_verifier required — device code invalidated"},
                status_code=400,
            )
        digest = base64.urlsafe_b64encode(
            hashlib.sha256(device_verifier.encode()).digest()
        ).rstrip(b"=").decode()
        if not secrets.compare_digest(digest, entry["device_challenge"]):
            logger.warning(
                "SECURITY: Device code verifier mismatch — client=%s poll_ip=%s — INVALIDATING",
                client_id, poll_ip,
            )
            _device_codes.pop(device_code, None)
            _user_code_index.pop(entry.get("user_code", ""), None)
            return JSONResponse(
                {"error": "invalid_grant", "error_description": "device_verifier mismatch — device code invalidated"},
                status_code=400,
            )

    # ── RFC 8628 polling state machine ────────────────────────────────────
    status = entry["status"]
    if status == "pending":
        return JSONResponse({"error": "authorization_pending"}, status_code=400)
    if status == "denied":
        _device_codes.pop(device_code, None)
        _user_code_index.pop(entry.get("user_code", ""), None)
        return JSONResponse({"error": "access_denied"}, status_code=400)
    if status != "approved":
        return JSONResponse({"error": "invalid_grant"}, status_code=400)

    # Consume the code (one-time use)
    _device_codes.pop(device_code, None)
    _user_code_index.pop(entry.get("user_code", ""), None)

    return JSONResponse(_mint_token(entry["sub"], client_id, "openid profile email"))


# ---------------------------------------------------------------------------
# Userinfo endpoint
# ---------------------------------------------------------------------------
@app.get("/oauth/userinfo")
async def userinfo(request: Request):
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    token_str = auth[7:]
    try:
        from jose import jwt as jose_jwt
        pub_pem = _public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        claims = jose_jwt.decode(token_str, pub_pem, algorithms=["RS256"], options={"verify_aud": False})
        sub = claims["sub"]
        user = USERS.get(sub, {})
        return {"sub": sub, "email": sub, "name": user.get("name", sub), "roles": user.get("roles", [])}
    except Exception as exc:
        logger.warning("Userinfo token invalid: %s", exc)
        return JSONResponse({"error": "invalid_token"}, status_code=401)


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------
@app.get("/health")
async def health():
    return {"status": "ok", "issuer": ISSUER}


if __name__ == "__main__":
    logger.info("Mock IdP starting — issuer=%s", ISSUER)
    uvicorn.run(app, host=HOST, port=PORT, log_level="info")
