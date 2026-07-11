"""AT1 addendum — T3: live proof of injection_mode=external_oauth_client_credentials,
the one mode confirmed (grep across lab/ and proxy/tests/) to have zero live
coverage anywhere before this file — only mocked unit tests exercised
dispatcher._inject_external_oauth_client_credentials
(proxy/tests/unit/test_dispatcher_external_oauth.py).

This is the GENERIC (non-Entra) app-only OAuth 2.0 client_credentials grant
path: server_registry.approved_upstream_idp_config carries a reviewer-approved
token_endpoint (not hardcoded to Microsoft's, unlike entra_client_credentials,
which test_at1_auth_matrix.py already proves live against lab-mock-idp).
lab-mock-idp's /oauth/token accepts grant_type=client_credentials for ANY
client_id+secret (see lab/mock-idp/server.py), so it doubles as a generic
external IdP here without needing a new container — this test proves the
DISPATCHER'S generic-config-driven code path end to end (a real HTTP POST to
a token_endpoint read from server_registry, not the Entra-specific branch),
which is what had zero live coverage; it deliberately does not claim to prove
a "second distinct IdP" the way test_at1_dex_external_oauth.py's Dex test
does for external_oauth_user_token.

Fixture (server_id=lab-echo-external-cc, tool=echo-external-cc, credential_id
in credential_store keyed owner_type='service') is seeded once, idempotently,
by seed_external_oauth_client_credentials_fixture() below — mirrors
lab/seeder/seed.py's seed_m365_client_credentials encrypt/store pattern
exactly, just off the generic dispatcher branch instead of the Entra one.
Not wired into lab/seeder/seed.py itself (out of scope for a single AT1 test
fixture) but written the same way so it stays byte-compatible with the
proxy's decrypt().
"""
from __future__ import annotations

import json
import os

import httpx
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from conftest import call_upstream_tool, db_query, podman_exec

SERVER_NAME = "lab-echo-external-cc"
SERVICE_NAME = "echo-external-cc"
TOOL_NAME = "echo-external-cc"
TOKEN_ENDPOINT = "http://lab-mock-idp:8888/oauth/token"
VAULT_ADDR = "http://127.0.0.1:8200"


def _encrypt_credential(plaintext: str, user_sub: str, master_bytes: bytes, *,
                        service: str, tool_id: str, owner_type: str) -> bytes:
    """Byte-for-byte replica of lab/seeder/seed.py:_encrypt_credential."""
    salt = os.urandom(32)
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt,
               info=b"mcp-credential-broker-kek-v2:" + user_sub.encode())
    kek = hkdf.derive(master_bytes)
    nonce = os.urandom(12)
    aad = f"mcp-cred-v2|{user_sub}|{service}|{tool_id}|{owner_type}".encode()
    ct = AESGCM(kek).encrypt(nonce, plaintext.encode(), aad)
    return salt + nonce + ct


@pytest.fixture(scope="module", autouse=True)
def _seed_external_oauth_client_credentials_fixture():
    """Idempotent: registers lab-echo-external-cc (reuses lab-mcp-echo as the
    upstream, exactly like echo-dex-external does for external_oauth_user_token)
    with injection_mode=external_oauth_client_credentials and a real
    token_endpoint, if not already present from a prior run."""
    existing = db_query(f"SELECT server_id::text FROM server_registry WHERE name='{SERVER_NAME}'")
    if existing:
        return

    vault_token = None
    env_lab = os.path.join(os.path.dirname(__file__), "..", "..", "..", ".env.lab")
    for line in open(env_lab):
        if line.startswith("VAULT_TOKEN="):
            vault_token = line.strip().split("=", 1)[1]
        if line.startswith("DB_PASSWORD="):
            db_password = line.strip().split("=", 1)[1]
    master_hex = httpx.get(f"{VAULT_ADDR}/v1/secret/data/mcp/broker-master",
                           headers={"X-Vault-Token": vault_token}, timeout=10
                           ).json()["data"]["data"]["value"]
    master_bytes = bytes.fromhex(master_hex)

    approved_config = json.dumps({
        "token_endpoint": TOKEN_ENDPOINT,
        "scopes": ["https://graph.microsoft.com/.default"],
        "client_auth_method": "client_secret_post",
    })
    server_id = db_query(
        "INSERT INTO server_registry (name, service_name, upstream_url, status, trust_tier, "
        "injection_mode, approved_upstream_idp_config, owner_sub, submission_status, "
        "approved_at, approved_by, upstream_allowlist_entry, last_rescanned_at) "
        f"VALUES ('{SERVER_NAME}', '{SERVICE_NAME}', 'http://lab-mcp-echo:8000/mcp', 'approved', 2, "
        f"'external_oauth_client_credentials', '{approved_config}'::jsonb, 'seeder', 'active', "
        "now(), 'seeder', '10.89.0.0/16', now()) RETURNING server_id::text"
    )
    tool_id = db_query(
        f"INSERT INTO tool_registry (name, version, description, schema, upstream_url, status, "
        f"risk_level, registered_by, service_name, injection_mode, server_id) "
        f"VALUES ('{TOOL_NAME}', '1.0.0', "
        f"'AT1/T3 external_oauth_client_credentials live fixture -- proxies lab-mcp-echo whoami', "
        f"'{{}}'::jsonb, 'http://lab-mcp-echo:8000/mcp', 'active', 'low', 'seeder', "
        f"'{SERVICE_NAME}', 'external_oauth_client_credentials', '{server_id}') RETURNING tool_id::text"
    )

    secret = json.dumps({"client_id": "echo-external-cc-lab-app", "client_secret": "echo-external-cc-lab-secret"})
    blob = _encrypt_credential(secret, "__service__", master_bytes,
                               service=SERVICE_NAME, tool_id=tool_id, owner_type="service")
    blob_hex = blob.hex()
    cred_id = db_query(
        "INSERT INTO credential_store (user_sub, service, tool_id, owner_type, credential_type, encrypted_blob) "
        f"VALUES ('__service__', '{SERVICE_NAME}', '{tool_id}', 'service', "
        f"'external_oauth_client_secret', decode('{blob_hex}', 'hex')) RETURNING id::text"
    )
    db_query(f"UPDATE tool_registry SET credential_id='{cred_id}' WHERE tool_id='{tool_id}'")
    db_query(
        f"INSERT INTO entitlement (server_id, principal_id, principal_type, granted_by) "
        f"VALUES ('{server_id}', 'human:keycloak:alice@corp', 'human', 'seeder')"
    )


def test_external_oauth_client_credentials_live_injection(alice_token):
    """Real end-to-end invocation through the gateway: the broker resolves
    server_registry.approved_upstream_idp_config.token_endpoint, decrypts the
    client_id/client_secret from credential_store, POSTs a real
    grant_type=client_credentials request to lab-mock-idp, and injects the
    resulting access_token as Authorization on the upstream call -- proving
    the generic (non-Entra) dispatcher branch actually works, not just a
    mocked unit test of it."""
    # loopback=True: whoami trips the gateway WAF's Unix-RCE wordlist (same
    # reason test_at1_auth_matrix.py's echo-sa/echo-basic use it) -- every
    # proxy-side gate is still fully exercised via the container loopback.
    result = call_upstream_tool(alice_token, "echo-external-cc", "whoami", {}, loopback=True)
    assert result["has_credential"] is True, result
    # A real client_credentials grant from lab-mock-idp returns a signed
    # RS256 JWT (see lab/mock-idp/server.py's /oauth/token handler) --
    # non-trivial length + JWT-shaped preview rules out an
    # empty/placeholder credential silently "passing" (spec H8: never
    # log/return the raw credential, so this is as far as an acceptance
    # test can look).
    assert result["credential_len"] > 100, result
    assert result["credential_preview"].startswith("eyJ"), result


def test_external_oauth_client_credentials_uses_approved_config_not_entra():
    """Sanity-check at the data layer: this server's approved token_endpoint
    is the generic one from server_registry.approved_upstream_idp_config
    (reviewer-approved), and its injection_mode is the generic mode, not
    entra_client_credentials -- proving this exercised the dispatcher's
    generic branch (_inject_external_oauth_client_credentials), not the
    already-covered Entra-specific one."""
    mode = db_query(f"SELECT injection_mode FROM server_registry WHERE name='{SERVER_NAME}'")
    assert mode == "external_oauth_client_credentials", mode
    endpoint = db_query(
        f"SELECT approved_upstream_idp_config->>'token_endpoint' FROM server_registry WHERE name='{SERVER_NAME}'"
    )
    assert endpoint == TOKEN_ENDPOINT, endpoint
