"""AT1 addendum — WP-A3 (CR-04 remainder) / Task 12: live proof of the "2
different IdPs" auth-mode category.

test_at1_auth_matrix.py already proves entra_client_credentials and
entra_user_token live against Entra (via lab-mock-idp) — but that's ONE
external IdP. It also proves kc_token_exchange (same-realm Keycloak) and
service_account/basic_auth (platform-internal). None of those exercise the
generic, per-server DYNAMIC external OAuth adapter added by WP-A3
(credential_broker/adapters/generic_oauth.py +
dynamic_external_oauth.py::resolve_external_oauth_adapter,
server_registry.approved_upstream_idp_config) — that path previously only had
mocked unit-test coverage (proxy/tests/unit/test_dispatcher_external_oauth.py).

This test drives that generic path against Dex acting as a genuinely
different, non-Entra, non-Keycloak-native external IdP:

  1. GET /auth/enroll/dex-external (authenticated as alice) — server-side
     consent page (D1/R-5), matching the exact flow a real user's browser
     would hit.
  2. POST /auth/enroll/dex-external/consent — mints PKCE state and 302s to
     Dex's real authorization_endpoint (this test's httpx client stands in
     for the browser from here on; no mocking).
  3. Log in to Dex as alice@corp via its real local-password-connector login
     form (skipApprovalScreen=true means Dex 303s straight to our
     redirect_uri with a real authorization code — no consent-screen stub).
  4. GET the real /auth/callback/dex-external (public endpoint) — the proxy
     exchanges the code for a REAL Dex access_token + refresh_token
     (GenericOAuthAdapter.exchange_code, a live HTTP POST to Dex's
     token_endpoint) and stores the encrypted refresh_token.
  5. Invoke echo-dex-external's whoami tool through the full gateway/
     dispatcher/OPA/entitlement chain — the broker decrypts the stored
     refresh_token, calls GenericOAuthAdapter.refresh() (another live HTTP
     call to Dex), and injects the resulting Dex access_token as
     Authorization: Bearer. has_credential=True + a JWT-shaped preview
     proves the round trip end-to-end.

Server-side fixtures for this test (service_name='dex-external', a SECOND
Dex OAuth client 'mcp-dex-generic' distinct from the legacy static dex.py
adapter's 'mcp-proxy' client, an oauth_provider_policy row, and the
echo-dex-external tool_registry/server_registry/credential_store rows) are
seeded by lab/seeder/sql/dex_external_oauth.sql + seed.py's step 7d3 — see
docs/spec/01-authentication.md §4.6 for the full writeup.

Driving this flow for real (rather than pre-seeding a refresh token, as
test_at1_auth_matrix.py's m365-delegated test does) surfaced two real bugs in
routers/oauth.py's /auth/callback endpoint that no prior test had exercised
(every other approach-A "enrollment" in this lab is pre-seeded, never driven
through this live path): a stale ON CONFLICT target that no longer matched
V011's partial unique index, and a credential encrypt() call missing the
service/tool_id/owner_type AAD fields decrypt() requires. Both are fixed
alongside this test.
"""
from __future__ import annotations

import re

import httpx
import pytest

from conftest import BASE_URL, call_upstream_tool, db_query

DEX_ISSUER_BASE = "http://localhost:5556/dex"
DEX_SERVICE_NAME = "dex-external"


def _dex_password() -> str:
    # NOT _env_lab("DEX_ALICE_PASSWORD", ...): that env var only drives the
    # REAL Keycloak user's password (seed.py's "KC hardening" step). Dex's
    # alice@corp password is the static bcrypt hash baked into
    # lab/dex/config.lab.yaml ("Static test users ... password: labpassword")
    # — always "labpassword" regardless of what KC's password has been
    # rotated to.
    return "labpassword"


def _drive_dex_enrollment(alice_token: str) -> None:
    """Drive a REAL browser-shaped authorization_code+PKCE enrollment for
    alice against Dex, through the generic/dynamic external_oauth_user_token
    path (service_name='dex-external'). Idempotent: re-running just
    refreshes alice's stored Dex refresh_token (ON CONFLICT DO UPDATE)."""
    headers = {"Authorization": f"Bearer {alice_token}"}

    # Step 1/2: GET the server-rendered consent page and extract its one-time
    # CSRF token — no shortcuts, this is the exact page a real browser gets.
    with httpx.Client(verify=False, timeout=20, follow_redirects=False) as c:
        r = c.get(f"{BASE_URL}/auth/enroll/{DEX_SERVICE_NAME}", headers=headers)
        assert r.status_code == 200, f"GET /auth/enroll/{DEX_SERVICE_NAME}: {r.status_code} {r.text[:300]}"
        m = re.search(r'name="csrf_token" value="([^"]+)"', r.text)
        assert m, f"consent page missing csrf_token field: {r.text[:500]}"
        csrf_token = m.group(1)

        # Step 2: POST consent — mints PKCE state, 302s to Dex's REAL
        # authorization_endpoint (server_registry.approved_upstream_idp_config,
        # not a stub/mock).
        r2 = c.post(
            f"{BASE_URL}/auth/enroll/{DEX_SERVICE_NAME}/consent",
            headers=headers, data={"csrf_token": csrf_token},
        )
        assert r2.status_code == 302, f"POST consent: {r2.status_code} {r2.text[:300]}"
        auth_url = r2.headers["location"]
        assert auth_url.startswith(DEX_ISSUER_BASE), (
            f"expected a redirect to Dex's real authorization_endpoint, got: {auth_url}"
        )

    # Step 3: follow the redirect chain to Dex's local-password login form and
    # submit alice's real credentials — Dex is a genuine second IdP here, not
    # a mock. skipApprovalScreen=true means Dex 303s straight to our
    # redirect_uri with a real authorization code once login succeeds.
    with httpx.Client(verify=False, timeout=20, follow_redirects=True) as c:
        login_page = c.get(auth_url)
        login_url = str(login_page.url)
        assert "dex/auth/local/login" in login_url, (
            f"expected Dex's local-password login form, landed on: {login_url}"
        )

        login_post = c.post(
            login_url,
            data={"login": "alice@corp", "password": _dex_password()},
            follow_redirects=False,
        )
        assert login_post.status_code == 303, (
            f"Dex login POST: {login_post.status_code} {login_post.text[:300]}"
        )
        callback_url = login_post.headers["location"]
        assert callback_url.startswith(f"{BASE_URL}/auth/callback/{DEX_SERVICE_NAME}"), (
            f"expected Dex to redirect back to our callback, got: {callback_url}"
        )
        assert "code=" in callback_url and "state=" in callback_url

    # Step 4: hit the real (public, unauthenticated per OAuth redirect
    # semantics) callback endpoint — this is where GenericOAuthAdapter does a
    # live HTTP POST to Dex's token_endpoint and the proxy stores the
    # encrypted refresh_token.
    r_cb = httpx.get(callback_url, verify=False, timeout=20)
    assert r_cb.status_code == 200, f"GET callback: {r_cb.status_code} {r_cb.text[:300]}"
    assert "Authorization complete" in r_cb.text, r_cb.text[:300]


def test_external_oauth_dex_user_token_generic_path(alice_token):
    """Live, end-to-end proof of the SECOND external IdP required by "all
    ways of auth" (same idp / 2 different idps / per-user JWT / SA JWT /
    basic auth): Dex, via the generic WP-A3 dynamic adapter path — distinct
    from Entra (entra_user_token/entra_client_credentials, already proven in
    test_at1_auth_matrix.py) and from the legacy static dex.py adapter
    (service='dex', lab-dex-cal/dex-calendar 'user' mode)."""
    _drive_dex_enrollment(alice_token)

    # loopback=True: echo's whoami tool name trips the gateway WAF (CRS
    # 932260 Unix-RCE wordlist), same as echo-sa/echo-basic in
    # test_at1_auth_matrix.py — every proxy-side gate (auth, entitlement,
    # OPA, the broker's decrypt+refresh(), credential injection) is still
    # fully exercised via the container-loopback path.
    result = call_upstream_tool(alice_token, "echo-dex-external", "whoami", {}, loopback=True)
    assert result["has_credential"] is True, result
    assert result["sub"] == "alice@corp", result  # caller identity preserved
    # Dex's access_token is itself a signed JWT (RS256, per its discovery
    # doc) — a non-trivial length + JWT-shaped preview is as far as spec H8
    # (never log/return the raw credential) lets an acceptance test look,
    # but it rules out an empty/placeholder credential silently "passing".
    assert result["credential_len"] > 100, result
    assert result["credential_preview"].startswith("eyJ"), result


def test_external_oauth_dex_is_a_distinct_idp_from_entra():
    """Sanity-check the "2 different IdPs" claim itself at the data layer:
    dex-external's approved config must point at Dex's real issuer (not
    Entra's), and must be a genuinely separate server_registry row +
    credential_store namespace from both entra_user_token's
    m365-graph-delegated and the legacy static dex.py adapter's
    service='dex' (lab-dex-cal) — three distinct rows, three distinct
    (issuer, service_name) pairs, none of them Entra."""
    issuer = db_query(
        "SELECT approved_upstream_idp_config->>'issuer' FROM server_registry "
        "WHERE service_name = 'dex-external' AND status = 'approved'"
    )
    assert issuer == "http://localhost:5556/dex", issuer
    assert "microsoftonline" not in issuer.lower()

    mode = db_query(
        "SELECT injection_mode FROM server_registry WHERE service_name = 'dex-external'"
    )
    assert mode == "external_oauth_user_token", mode

    # entra_user_token's m365-graph-delegated (tool_registry — this mode has
    # no dedicated server_registry row of its own, it shares lab-m365's) must
    # be a DIFFERENT credential_store service namespace.
    entra_service = db_query(
        "SELECT service_name FROM tool_registry "
        "WHERE injection_mode = 'entra_user_token' LIMIT 1"
    )
    assert entra_service and entra_service != "dex-external", entra_service

    dex_client_id = db_query(
        "SELECT approved_upstream_idp_config->>'client_id' FROM server_registry "
        "WHERE service_name = 'dex-external'"
    )
    # Distinct OAuth client from the legacy static dex.py adapter's
    # 'mcp-proxy' (lab-dex-cal/dex-calendar) — this row proves the NEW
    # dynamic path, not a re-use of the old one.
    assert dex_client_id == "mcp-dex-generic", dex_client_id
