#!/usr/bin/env python3
"""
Runtime IDP configuration — the OTHER half of the "both ways" requirement
in rs/ARCHITECTURE.md ("Multi-IDP architecture"). Configures an IDP against
an ALREADY RUNNING platform via the admin API described in
deploy/idp-examples/API_CONTRACT.md.

*** THAT API DOES NOT EXIST YET. *** Confirmed against
rs/crates/mcphub-ui/src/router.rs: the only /admin/idps route is a
CSRF-protected HTML form, not a JSON API, and there is no dedicated_port
route at all. This script is written against the proposed contract so it's
ready the moment that API lands, and — per explicit instruction — it FAILS
LOUDLY rather than pretending success against a 404/wrong-shaped response.
Do not run this against a live environment expecting it to work today; use
deploy/configure-idp.sh (install-time path) instead, which works now.

Body shape matches the REAL rs/crates/mcphub-identity/src/config.rs
IdpConfig struct (see deploy/idp-examples/SCHEMA.md), not a guessed one.
client_secret is never sent over the API — IdpConfig has no such field, so
this script writes it to Vault (same path convention as
deploy/configure-idp.sh) and sends only vault_secret_name.

Usage:
    export VAULT_ADDR=https://vault.internal:8200
    export VAULT_ROLE_ID=... VAULT_SECRET_ID=...
    export MCPHUB_ADMIN_TOKEN=...
    python3 configure_idp_runtime.py \\
        --base-url https://gateway.internal:8443 \\
        --env prod \\
        --vault-secret-name mcp-entra \\
        --issuer https://sts.windows.net/<tenant>/ \\
        --issuer-alias https://login.microsoftonline.com/<tenant>/v2.0 \\
        --discovery-url https://login.microsoftonline.com/<tenant>/v2.0/.well-known/openid-configuration \\
        --client-id <app-client-id> \\
        --audience <app-client-id> \\
        --auth-mode DedicatedPort \\
        --role-mapping-file entra-role-mapping.json \\
        --redirect-uri https://gateway.internal:9000/oauth/callback
"""
from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
import urllib.error
import urllib.request

VALID_AUTH_MODES = {"SharedPassthrough", "SharedExchange", "DedicatedPort"}

DEFAULT_ROLE_MAPPING = {
    "rules": [
        {
            "extract": {"kind": "top_level_array", "claim": "roles"},
            "role_values": {
                "mcphub-super-admin": "SuperAdmin",
                "mcphub-server-owner": "ServerOwner",
                "mcphub-security-analyst": "SecurityAnalyst",
                "mcphub-employee": "Employee",
            },
        }
    ]
}


def read_vault_secret(vault_addr: str, role_id: str, secret_id: str, path: str, field: str) -> str:
    login_req = urllib.request.Request(
        f"{vault_addr}/v1/auth/approle/login",
        data=json.dumps({"role_id": role_id, "secret_id": secret_id}).encode(),
        method="POST",
    )
    with urllib.request.urlopen(login_req, timeout=10) as resp:  # noqa: S310 -- internal Vault addr, operator-controlled
        token = json.load(resp)["auth"]["client_token"]

    mount, _, kv_path = path.partition("/")
    get_req = urllib.request.Request(
        f"{vault_addr}/v1/{mount}/data/{kv_path}",
        headers={"X-Vault-Token": token},
    )
    with urllib.request.urlopen(get_req, timeout=10) as resp:  # noqa: S310
        data = json.load(resp)
    return data["data"]["data"][field]


def write_vault_secret(vault_addr: str, role_id: str, secret_id: str, path: str, field: str, value: str) -> None:
    login_req = urllib.request.Request(
        f"{vault_addr}/v1/auth/approle/login",
        data=json.dumps({"role_id": role_id, "secret_id": secret_id}).encode(),
        method="POST",
    )
    with urllib.request.urlopen(login_req, timeout=10) as resp:  # noqa: S310
        token = json.load(resp)["auth"]["client_token"]

    mount, _, kv_path = path.partition("/")
    put_req = urllib.request.Request(
        f"{vault_addr}/v1/{mount}/data/{kv_path}",
        data=json.dumps({"data": {field: value}}).encode(),
        method="POST",
        headers={"X-Vault-Token": token, "Content-Type": "application/json"},
    )
    with urllib.request.urlopen(put_req, timeout=10):  # noqa: S310
        pass


def call_admin_api(url: str, admin_token: str, method: str, body: dict) -> tuple[int, str]:
    """
    Returns (status_code, body_text). Raises on transport failure (DNS,
    connection refused, timeout). A non-2xx HTTP response is NOT an
    exception here -- the caller decides how to report it -- but it is
    NEVER treated as success. There is no code path in this function that
    returns success for a non-2xx response.
    """
    req = urllib.request.Request(
        url,
        data=json.dumps(body).encode(),
        method=method,
        headers={"Authorization": f"Bearer {admin_token}", "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:  # noqa: S310 -- operator-supplied base_url
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as e:
        # This is the path a 404 (endpoint doesn't exist -- the current
        # reality) takes. Body/status are returned, not swallowed.
        return e.code, e.read().decode()


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--base-url", required=True)
    p.add_argument("--env", required=True)
    p.add_argument("--vault-secret-name", required=True, help="deploy-only identifier; also the Vault KV path suffix")
    p.add_argument("--issuer", required=True)
    p.add_argument("--issuer-alias", action="append", default=[], dest="issuer_aliases")
    p.add_argument("--discovery-url")
    p.add_argument("--client-id", required=True)
    p.add_argument("--audience", action="append", required=True, dest="audiences", help="repeatable; must not be empty")
    p.add_argument("--allowed-alg", action="append", default=["RS256"], dest="allowed_algs")
    p.add_argument("--clock-skew-seconds", type=int, default=60)
    p.add_argument("--auth-mode", required=True, choices=sorted(VALID_AUTH_MODES))
    p.add_argument("--token-exchange", dest="token_exchange", action="store_true")
    p.add_argument("--no-token-exchange", dest="token_exchange", action="store_false")
    p.set_defaults(token_exchange=False)
    p.add_argument("--redirect-uri", action="append", default=[], dest="redirect_uris")
    p.add_argument(
        "--role-mapping-file",
        help="JSON file with the {rules: [...]} shape (see SCHEMA.md); defaults to the generic top-level `roles` mapping if omitted",
    )
    p.add_argument("--client-secret-stdin", action="store_true", help="write the client secret to Vault (piped via stdin, never a CLI arg)")
    p.add_argument("--dry-run", action="store_true")
    args = p.parse_args()

    if args.auth_mode == "SharedExchange" and not args.token_exchange:
        p.error("--auth-mode SharedExchange requires --token-exchange")
    if not args.audiences:
        p.error("--audience is required at least once — an empty audiences list accepts a token minted for ANY relying party")
    if args.client_id and not args.redirect_uris:
        p.error("--redirect-uri is required at least once when --client-id is set — an empty allowlist is an open-redirect risk")

    role_mapping = DEFAULT_ROLE_MAPPING
    if args.role_mapping_file:
        with open(args.role_mapping_file) as f:
            role_mapping = json.load(f)

    vault_addr = os.environ.get("VAULT_ADDR")
    role_id = os.environ.get("VAULT_ROLE_ID")
    secret_id = os.environ.get("VAULT_SECRET_ID")

    if args.client_secret_stdin:
        if not all([vault_addr, role_id, secret_id]):
            print("VAULT_ADDR, VAULT_ROLE_ID, VAULT_SECRET_ID must be set to write the client secret", file=sys.stderr)
            return 1
        client_secret = sys.stdin.readline().rstrip("\n") if not sys.stdin.isatty() else getpass.getpass("Client secret: ")
        vault_path = f"secret/mcphub/{args.env}/idp/{args.vault_secret_name}"
        if not args.dry_run:
            write_vault_secret(vault_addr, role_id, secret_id, vault_path, "client_secret", client_secret)
            print(f"Wrote client_secret to Vault at {vault_path}")
        else:
            print(f"[dry-run] would write client_secret to Vault at {vault_path}")

    body = {
        "vault_secret_name": args.vault_secret_name,
        "issuer": args.issuer,
        "discovery_url": args.discovery_url,
        "issuer_aliases": args.issuer_aliases,
        "audiences": args.audiences,
        "allowed_algs": args.allowed_algs,
        "clock_skew_seconds": args.clock_skew_seconds,
        "auth_mode": args.auth_mode,
        "dedicated_port": None,
        "supports_token_exchange": args.token_exchange,
        "client_id": args.client_id,
        "redirect_uri_allowlist": args.redirect_uris,
        "role_mapping": role_mapping,
    }

    if args.dry_run:
        print(json.dumps(body, indent=2))
        return 0

    admin_token = os.environ.get("MCPHUB_ADMIN_TOKEN")
    if not admin_token:
        print("MCPHUB_ADMIN_TOKEN (super-admin service credential) must be set", file=sys.stderr)
        return 1

    url = f"{args.base_url.rstrip('/')}/api/v1/admin/idps"
    try:
        status, text = call_admin_api(url, admin_token, "POST", body)
    except urllib.error.URLError as e:
        print(f"FAILED: could not reach {url}: {e}", file=sys.stderr)
        return 1

    if status not in (200, 201):
        print(f"FAILED: {url} returned HTTP {status} (this endpoint does not exist as of this writing — see API_CONTRACT.md): {text}", file=sys.stderr)
        return 1

    print(f"OK: {status} {text}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
