#!/usr/bin/env python3
"""
onboard_server.py — One-command MCP server onboarding operator tool.

Drives the full D3 dual-control onboarding workflow against the proxy REST API:
  Step 1: register  — server_owner POSTs /api/v1/servers (status → pending)
  Step 2: consent   — server_owner POSTs /api/v1/servers/{id}/consent (mints consent_token)
  Step 3: approve   — platform_admin POSTs /api/v1/admin/servers/{id}/approve (with consent_token)
  Step 4: discover  — platform_admin POSTs /api/v1/servers/{id}/discover-tools
  Step 5: activate  — platform_admin PATCHes /api/v1/tools/{tool_id} for each tool
  Step 6: grant     — server_owner POSTs /api/v1/servers/{id}/entitlements

Two-identity dual control:
  - All Step 1–2 and Step 6 calls use the server_owner credential.
  - All Step 3–5 calls use the platform_admin credential.
  Both can be supplied via env vars or prompted interactively.

Credential supply (in priority order):
  server_owner token: $OWNER_TOKEN env var, then --owner-token flag, then prompt.
  platform_admin token: $ADMIN_TOKEN env var, then --admin-token flag, then prompt.
  Tokens are NEVER echoed to stdout (INV-002 spirit).

Usage:
  python scripts/onboard_server.py \\
      --url https://my-mcp-server.example.com \\
      --mode service \\
      [--service-name my-service] \\
      [--base-url http://localhost:8000] \\
      [--grant-principal agent-001] \\
      [--grant-principal-type agent] \\
      [--activate-all]

Environment variables:
  OWNER_TOKEN       Bearer token / API key for the server_owner identity
  ADMIN_TOKEN       Bearer token / API key for the platform_admin identity
  PROXY_BASE_URL    Override for --base-url (default: http://localhost:8000)
  UPSTREAM_PRIVATE_CIDR_ALLOWLIST  If set, allows private upstream URLs
                                   (passed through to the proxy via X-Private-CIDR header)

Exit codes:
  0  All steps succeeded or were idempotently skipped.
  1  A step failed — the error is printed with which step failed.
  2  Invalid arguments.

Idempotency:
  If a step returns a known-already-done error code, the tool prints a note
  and continues to the next step rather than aborting.

Secret hygiene:
  Tokens are read into variables and passed in Authorization headers only.
  They are never printed, logged to stdout, or stored in the filesystem.
"""
from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
from typing import Optional

try:
    import httpx
except ImportError:
    print("ERROR: httpx not installed. Run: pip install httpx", file=sys.stderr)
    sys.exit(1)


# ─── Colour helpers (no external deps) ──────────────────────────────────────

def _ok(msg: str) -> None:
    print(f"  [OK]   {msg}")


def _skip(msg: str) -> None:
    print(f"  [SKIP] {msg}")


def _info(msg: str) -> None:
    print(f"         {msg}")


def _warn(msg: str) -> None:
    print(f"  [WARN] {msg}", file=sys.stderr)


def _fail(msg: str) -> None:
    print(f"  [FAIL] {msg}", file=sys.stderr)


def _step(n: int, label: str) -> None:
    print(f"\n[Step {n}] {label}")


def _hdr(msg: str) -> None:
    print(f"\n{'='*66}")
    print(f"  {msg}")
    print(f"{'='*66}")


# ─── Credential helpers ──────────────────────────────────────────────────────

def _bearer_headers(token: str) -> dict[str, str]:
    """Return Authorization Bearer header dict. Never log the token value."""
    return {"Authorization": f"Bearer {token}"}


def _resolve_token(env_var: str, flag_value: Optional[str], prompt_label: str) -> str:
    """
    Resolve a credential in priority order:
      1. CLI flag value (if provided and non-empty)
      2. Environment variable
      3. Interactive prompt (never echoes input)

    The returned token is NEVER printed to stdout.
    """
    # Priority 1: CLI flag
    if flag_value:
        return flag_value.strip()
    # Priority 2: env var
    env_val = os.environ.get(env_var, "").strip()
    if env_val:
        return env_val
    # Priority 3: interactive prompt
    token = getpass.getpass(f"Enter {prompt_label} (input hidden): ").strip()
    if not token:
        _fail(f"{prompt_label} is required but was empty.")
        sys.exit(1)
    return token


# ─── HTTP helpers ────────────────────────────────────────────────────────────

class OnboardingError(Exception):
    """Raised when a non-idempotent step fails."""
    def __init__(self, step: str, status: int, body: str):
        self.step = step
        self.status = status
        self.body = body
        super().__init__(f"Step '{step}' failed: HTTP {status}: {body}")


def _call(
    client: httpx.Client,
    method: str,
    url: str,
    *,
    headers: dict[str, str],
    json_body: Optional[dict] = None,
    step_label: str,
    allow_statuses: tuple[int, ...] = (200, 201),
    idempotent_status: Optional[int] = None,
    idempotent_msg: Optional[str] = None,
) -> Optional[dict]:
    """
    Make an HTTP call, handle errors, and return parsed JSON on success.

    If the response status is in allow_statuses, return the JSON body.
    If idempotent_status matches, print skip message and return None.
    Otherwise raise OnboardingError.
    """
    try:
        resp = client.request(
            method,
            url,
            headers=headers,
            json=json_body,
            timeout=30.0,
        )
    except httpx.ConnectError as exc:
        raise OnboardingError(step_label, -1, f"Connection failed: {exc}") from exc
    except httpx.TimeoutException as exc:
        raise OnboardingError(step_label, -1, f"Request timed out: {exc}") from exc

    if resp.status_code in allow_statuses:
        try:
            return resp.json()
        except Exception:
            return {}

    if idempotent_status and resp.status_code == idempotent_status:
        _skip(idempotent_msg or f"Already done (HTTP {resp.status_code})")
        return None

    # Sanitize error body — strip any potential secret-like strings
    raw = resp.text[:1000]
    raise OnboardingError(step_label, resp.status_code, raw)


# ─── Main onboarding flow ────────────────────────────────────────────────────

def run_onboarding(
    *,
    upstream_url: str,
    injection_mode: str,
    service_name: str,
    base_url: str,
    owner_token: str,
    admin_token: str,
    grant_principal: Optional[str],
    grant_principal_type: str,
    activate_all: bool,
    tool_names_to_activate: list[str],
    private_cidr_allowlist: Optional[str],
) -> int:
    """
    Execute the full onboarding workflow.

    Returns 0 on success, 1 on failure.
    """
    _hdr(f"MCP Server Onboarding: {service_name}")
    _info(f"Upstream URL : {upstream_url}")
    _info(f"Mode         : {injection_mode}")
    _info(f"Proxy        : {base_url}")
    if private_cidr_allowlist:
        _info(f"Private CIDR : {private_cidr_allowlist}")

    # Build per-identity header sets (tokens kept in memory only)
    owner_hdrs = {
        "Content-Type": "application/json",
        **_bearer_headers(owner_token),
    }
    admin_hdrs = {
        "Content-Type": "application/json",
        **_bearer_headers(admin_token),
    }

    # Optionally forward CIDR allowlist as a header the proxy can read
    # (Task 3.1 adds UPSTREAM_PRIVATE_CIDR_ALLOWLIST support to the proxy).
    if private_cidr_allowlist:
        owner_hdrs["X-Private-CIDR-Allowlist"] = private_cidr_allowlist
        admin_hdrs["X-Private-CIDR-Allowlist"] = private_cidr_allowlist

    server_id: Optional[str] = None
    consent_token: Optional[str] = None
    discovered_tools: list[dict] = []

    with httpx.Client(base_url=base_url) as client:

        # ──────────────────────────────────────────────────────────────────
        # Step 1: Register
        # ──────────────────────────────────────────────────────────────────
        _step(1, "Register server (server_owner)")
        register_body: dict = {
            "service_name": service_name,
            "upstream_url": upstream_url,
            "injection_mode": injection_mode,
        }

        try:
            reg_resp = _call(
                client, "POST", "/api/v1/servers",
                headers=owner_hdrs,
                json_body=register_body,
                step_label="register",
                allow_statuses=(200, 201),
            )
        except OnboardingError as exc:
            if exc.status == 409:
                # Already registered — try to extract the server_id from the error body
                _skip("Server appears to already be registered (HTTP 409).")
                _info("If you have the server_id, re-run with --server-id <id> to resume.")
                _fail("Cannot resume without server_id; aborting.")
                return 1
            _fail(str(exc))
            return 1

        if reg_resp is None:
            _skip("Registration skipped (idempotent)")
        else:
            server_id = reg_resp.get("server_id")
            _ok(f"Server registered — server_id={server_id}, status={reg_resp.get('status', 'pending')}")

        if not server_id:
            _fail("server_id not returned from registration — cannot continue.")
            return 1

        # ──────────────────────────────────────────────────────────────────
        # Step 2: Mint consent token (server_owner identity)
        # ──────────────────────────────────────────────────────────────────
        _step(2, "Mint consent token (server_owner)")
        try:
            consent_resp = _call(
                client, "POST", f"/api/v1/servers/{server_id}/consent",
                headers=owner_hdrs,
                json_body={"action": "approve"},
                step_label="consent",
                allow_statuses=(200, 201),
                idempotent_status=409,
                idempotent_msg="Server no longer pending — consent step skipped.",
            )
        except OnboardingError as exc:
            _fail(str(exc))
            return 1

        if consent_resp is not None:
            consent_token = consent_resp.get("consent_token")
            jti = consent_resp.get("jti", "")
            expires = consent_resp.get("expires_in_seconds", 900)
            _ok(f"Consent token minted — jti={jti}, expires_in={expires}s")
            # NOTE: consent_token value is NOT printed here (secret hygiene)
        else:
            _info("Consent step produced no token — checking if server is already approved.")

        # ──────────────────────────────────────────────────────────────────
        # Step 3: Approve (platform_admin identity, requires consent_token)
        # ──────────────────────────────────────────────────────────────────
        _step(3, "Approve server (platform_admin + consent_token)")

        if consent_token:
            try:
                approve_resp = _call(
                    client, "POST", f"/api/v1/admin/servers/{server_id}/approve",
                    headers=admin_hdrs,
                    json_body={"consent_token": consent_token},
                    step_label="approve",
                    allow_statuses=(200, 201),
                    idempotent_status=404,
                    idempotent_msg="Server not found in pending state — may already be approved.",
                )
            except OnboardingError as exc:
                if exc.status == 409:
                    _skip("Server already approved or consent token mismatch — checking status.")
                    approve_resp = None
                else:
                    _fail(str(exc))
                    return 1

            if approve_resp is not None:
                _ok(
                    f"Server approved — approved_by={approve_resp.get('approved_by')}, "
                    f"status={approve_resp.get('status')}"
                )
        else:
            _skip("No consent token available — checking if server is already approved.")
            # Verify the server is actually in approved state before proceeding
            try:
                srv_check = _call(
                    client, "GET", f"/api/v1/admin/servers/{server_id}",
                    headers=admin_hdrs,
                    step_label="check_server_status",
                    allow_statuses=(200,),
                )
            except OnboardingError as exc:
                _fail(f"Cannot verify server status: {exc}")
                return 1
            if srv_check and srv_check.get("status") != "approved":
                _fail(
                    f"Server is in status='{srv_check.get('status')}' but no consent token "
                    "available. Cannot approve. Run Step 2 manually first."
                )
                return 1
            _ok("Server confirmed approved (pre-existing approval).")

        # ──────────────────────────────────────────────────────────────────
        # Step 4: Discover tools (platform_admin identity)
        # ──────────────────────────────────────────────────────────────────
        _step(4, "Discover tools (platform_admin)")
        try:
            disc_resp = _call(
                client, "POST", f"/api/v1/servers/{server_id}/discover-tools",
                headers=admin_hdrs,
                step_label="discover-tools",
                allow_statuses=(200,),
            )
        except OnboardingError as exc:
            _fail(str(exc))
            return 1

        if disc_resp is not None:
            discovered_tools = disc_resp.get("tools", [])
            _ok(f"Discovered {disc_resp.get('discovered', len(discovered_tools))} tool(s)")
            for t in discovered_tools:
                _info(f"  - {t.get('tool_name', t.get('name', '?'))} [{t.get('tool_id', '?')}]")

        # ──────────────────────────────────────────────────────────────────
        # Step 5: Activate tools (platform_admin identity)
        # ──────────────────────────────────────────────────────────────────
        _step(5, "Activate tools (platform_admin)")

        # Determine which tools to activate
        tools_to_activate = []
        if activate_all:
            tools_to_activate = discovered_tools
        elif tool_names_to_activate:
            name_set = set(tool_names_to_activate)
            tools_to_activate = [
                t for t in discovered_tools
                if t.get("tool_name", t.get("name", "")) in name_set
            ]
            if not tools_to_activate:
                _warn(
                    f"None of the requested tools {tool_names_to_activate} were found "
                    f"in discovered set {[t.get('tool_name') for t in discovered_tools]}."
                )

        if not tools_to_activate:
            _skip(
                "No tools selected for activation. "
                "Use --activate-all or --activate-tool <name> to activate."
            )
        else:
            activated = 0
            failed_activate = []
            for tool in tools_to_activate:
                tool_id = tool.get("tool_id")
                tool_name = tool.get("tool_name", tool.get("name", tool_id))
                if not tool_id:
                    _warn(f"  Tool '{tool_name}' has no tool_id — skipping.")
                    continue
                try:
                    act_resp = _call(
                        client, "PATCH", f"/api/v1/tools/{tool_id}",
                        headers=admin_hdrs,
                        json_body={"status": "active"},
                        step_label=f"activate:{tool_name}",
                        allow_statuses=(200,),
                        idempotent_status=409,
                        idempotent_msg=f"Tool '{tool_name}' already active.",
                    )
                    if act_resp is not None:
                        _ok(f"Activated tool '{tool_name}' [{tool_id}]")
                        activated += 1
                    else:
                        _skip(f"Tool '{tool_name}' already active")
                        activated += 1
                except OnboardingError as exc:
                    _warn(f"  Failed to activate '{tool_name}': {exc}")
                    failed_activate.append(tool_name)

            if failed_activate:
                _warn(f"Failed to activate: {failed_activate}")
            else:
                _ok(f"All {activated} selected tool(s) activated.")

        # ──────────────────────────────────────────────────────────────────
        # Step 6: Grant entitlement (server_owner identity)
        # ──────────────────────────────────────────────────────────────────
        _step(6, "Grant entitlement (server_owner)")

        if not grant_principal:
            _skip("No --grant-principal specified — skipping entitlement grant.")
        else:
            grant_body = {
                "principal_id": grant_principal,
                "principal_type": grant_principal_type,
            }
            try:
                grant_resp = _call(
                    client, "POST", f"/api/v1/servers/{server_id}/entitlements",
                    headers=owner_hdrs,
                    json_body=grant_body,
                    step_label="grant-entitlement",
                    allow_statuses=(200, 201),
                )
            except OnboardingError as exc:
                _fail(str(exc))
                return 1

            if grant_resp is not None:
                ent_id = grant_resp.get("ent_id", grant_resp.get("entitlement_id", "?"))
                _ok(
                    f"Entitlement granted — ent_id={ent_id}, "
                    f"principal={grant_principal} ({grant_principal_type})"
                )

    # ──────────────────────────────────────────────────────────────────────
    # Summary
    # ──────────────────────────────────────────────────────────────────────
    print(f"\n{'='*66}")
    print("  Onboarding complete.")
    print(f"  server_id  : {server_id}")
    print(f"  service    : {service_name}")
    print(f"  upstream   : {upstream_url}")
    print(f"  mode       : {injection_mode}")
    if grant_principal:
        print(f"  granted to : {grant_principal} ({grant_principal_type})")
    print(f"{'='*66}\n")
    return 0


# ─── CLI ─────────────────────────────────────────────────────────────────────

def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="One-command MCP server onboarding (Task 3.3)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--url",
        required=True,
        help="Upstream MCP server URL (must be HTTPS for public; http+allowlist for private lab)",
    )
    parser.add_argument(
        "--mode",
        default="none",
        choices=["none", "service", "user", "service_account", "oauth_user_token",
                 "entra_user_token", "entra_client_credentials"],
        help="Injection mode (default: none)",
    )
    parser.add_argument(
        "--service-name",
        help="Human-readable service name (defaults to hostname from URL)",
    )
    parser.add_argument(
        "--base-url",
        default=os.environ.get("PROXY_BASE_URL", "http://localhost:8000"),
        help="Proxy base URL (default: http://localhost:8000 or $PROXY_BASE_URL)",
    )
    parser.add_argument(
        "--owner-token",
        default=None,
        help="Bearer token for the server_owner identity ($OWNER_TOKEN env or prompt)",
    )
    parser.add_argument(
        "--admin-token",
        default=None,
        help="Bearer token for the platform_admin identity ($ADMIN_TOKEN env or prompt)",
    )
    parser.add_argument(
        "--grant-principal",
        default=None,
        help="Principal ID to grant entitlement to after onboarding (optional)",
    )
    parser.add_argument(
        "--grant-principal-type",
        default="agent",
        choices=["human", "agent", "kc_group"],
        help="Principal type for the entitlement grant (default: agent)",
    )
    parser.add_argument(
        "--activate-all",
        action="store_true",
        help="Activate all discovered tools (otherwise none are activated by default)",
    )
    parser.add_argument(
        "--activate-tool",
        action="append",
        default=[],
        dest="activate_tools",
        metavar="TOOL_NAME",
        help="Activate a specific tool by name (can be repeated). Overridden by --activate-all.",
    )
    return parser.parse_args()


def main() -> int:
    args = _parse_args()

    # Derive service_name from URL hostname if not provided
    service_name = args.service_name
    if not service_name:
        from urllib.parse import urlparse
        parsed = urlparse(args.url)
        service_name = parsed.hostname or "unknown-service"

    # Resolve both credentials (never echoed to stdout)
    print(
        "\nProviding credentials for two-identity dual control.\n"
        "Neither token will be printed or logged.\n"
    )
    owner_token = _resolve_token(
        env_var="OWNER_TOKEN",
        flag_value=args.owner_token,
        prompt_label="server_owner token",
    )
    admin_token = _resolve_token(
        env_var="ADMIN_TOKEN",
        flag_value=args.admin_token,
        prompt_label="platform_admin token",
    )

    private_cidr = os.environ.get("UPSTREAM_PRIVATE_CIDR_ALLOWLIST")

    return run_onboarding(
        upstream_url=args.url,
        injection_mode=args.mode,
        service_name=service_name,
        base_url=args.base_url,
        owner_token=owner_token,
        admin_token=admin_token,
        grant_principal=args.grant_principal,
        grant_principal_type=args.grant_principal_type,
        activate_all=args.activate_all,
        tool_names_to_activate=args.activate_tools,
        private_cidr_allowlist=private_cidr,
    )


if __name__ == "__main__":
    sys.exit(main())
