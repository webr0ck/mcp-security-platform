"""
lab/seeder/seed.py
==================
Lab environment seeder. Idempotent: safe to re-run.

Order of operations:
  1. Wait for PostgreSQL (max 60s)
  2. Wait for Vault (max 60s)
  3. Write broker master secret to Vault KV v2
  4. Insert tool_registry rows (tools.sql — ON CONFLICT upsert)
  5. Insert RBAC seed rows (roles.sql — ON CONFLICT DO NOTHING)
  6. Create Grafana service account + API token, print token
  7. Create/retrieve NetBox API token, print token
  8. Print summary

Environment variables (all have safe defaults except DB_PASSWORD):
  DB_HOST, DB_PORT, DB_NAME, DB_USER, DB_PASSWORD (required)
  VAULT_ADDR, VAULT_TOKEN, BROKER_MASTER_SECRET_PATH
  LAB_GRAFANA_URL, LAB_GRAFANA_ADMIN_PASSWORD
  LAB_NETBOX_URL, LAB_NETBOX_ADMIN_TOKEN (optional — skip if absent)
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from pathlib import Path
from typing import Optional

import asyncpg
import httpx
import hvac

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)
log = logging.getLogger("lab.seeder")

# ---------------------------------------------------------------------------
# Configuration (no secrets hardcoded — all come from env)
# ---------------------------------------------------------------------------
DB_HOST = os.environ.get("DB_HOST", "mcp-db")
DB_PORT = int(os.environ.get("DB_PORT", "5432"))
DB_NAME = os.environ.get("DB_NAME", "mcp_security")
DB_USER = os.environ.get("DB_USER", "mcp_app")
DB_PASSWORD = os.environ.get("DB_PASSWORD", "")  # required; empty string fails at connect

VAULT_ADDR = os.environ.get("VAULT_ADDR", "http://mcp-vault:8200")
VAULT_TOKEN = os.environ.get("VAULT_TOKEN", "lab-root-token")
BROKER_MASTER_SECRET_PATH = os.environ.get(
    "BROKER_MASTER_SECRET_PATH", "secret/data/mcp/broker-master"
)

LAB_GRAFANA_URL = os.environ.get("LAB_GRAFANA_URL", "http://lab-grafana:3000")
LAB_GRAFANA_ADMIN_PASSWORD = os.environ.get("LAB_GRAFANA_ADMIN_PASSWORD", "labpassword")

LAB_NETBOX_URL = os.environ.get("LAB_NETBOX_URL", "http://lab-netbox:8080")
# NetBox token seeding requires an existing admin API token.
# If absent, the NetBox step is skipped with a warning.
LAB_NETBOX_ADMIN_TOKEN: Optional[str] = os.environ.get("LAB_NETBOX_ADMIN_TOKEN")

LAB_GITEA_URL = os.environ.get("LAB_GITEA_URL", "http://lab-gitea:3000")
LAB_GITEA_ADMIN_USER = os.environ.get("LAB_GITEA_ADMIN_USER", "admin")
LAB_GITEA_ADMIN_PASSWORD = os.environ.get("LAB_GITEA_ADMIN_PASSWORD", "labpassword")

KC_ADMIN_URL = os.environ.get("KC_ADMIN_URL", "http://lab-keycloak:8080")
KC_ADMIN_PASSWORD = os.environ.get("KC_ADMIN_PASSWORD", "adminpassword")

# OIDC issuer URL used to replace __OIDC_ISSUER_PLACEHOLDER__ in oidc_role_mappings.
# Uses OIDC_INTERNAL_ISSUER_URL (container-network URL) so role lookups work
# inside the proxy container; falls back to OIDC_ISSUER_URL if not set.
OIDC_ISSUER_URL = (
    os.environ.get("OIDC_INTERNAL_ISSUER_URL", "").strip()
    or os.environ.get("OIDC_ISSUER_URL", "").strip()
    or "http://lab-keycloak:8080/realms/mcp"
)
# Expected usernames in the mcp realm; any others are treated as attacker artifacts.
KC_EXPECTED_USERS = {"alice", "bob", "carol"}
# Passwords that should be set for each expected user on every seeder run.
KC_USER_PASSWORDS: dict[str, str] = {
    "alice": os.environ.get("DEX_ALICE_PASSWORD", "labpassword"),
    "bob": os.environ.get("DEX_BOB_PASSWORD", "labpassword"),
    "carol": os.environ.get("DEX_ALICE_PASSWORD", "labpassword"),
}

SQL_DIR = Path(__file__).parent / "sql"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

async def wait_for_postgres(max_wait: int = 60) -> asyncpg.Connection:
    """Retry connecting to Postgres until ready or timeout."""
    dsn = (
        f"postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
    )
    deadline = time.monotonic() + max_wait
    last_exc: Optional[Exception] = None
    while time.monotonic() < deadline:
        try:
            conn = await asyncpg.connect(dsn)
            log.info("PostgreSQL ready at %s:%s/%s", DB_HOST, DB_PORT, DB_NAME)
            return conn
        except Exception as exc:  # noqa: BLE001
            last_exc = exc
            log.debug("Postgres not ready: %s — retrying in 2s", exc)
            await asyncio.sleep(2)
    raise RuntimeError(
        f"PostgreSQL did not become ready within {max_wait}s. "
        f"Last error: {last_exc}"
    )


async def wait_for_vault(max_wait: int = 60) -> None:
    """Poll Vault health endpoint until sealed=false or timeout."""
    health_url = f"{VAULT_ADDR}/v1/sys/health"
    deadline = time.monotonic() + max_wait
    async with httpx.AsyncClient(timeout=5) as client:
        while time.monotonic() < deadline:
            try:
                resp = await client.get(health_url)
                # 200 = initialized, unsealed, active
                # 429 = standby (also healthy for our purposes)
                if resp.status_code in (200, 429):
                    log.info("Vault ready at %s (status %s)", VAULT_ADDR, resp.status_code)
                    return
                log.debug("Vault health status %s — retrying in 2s", resp.status_code)
            except httpx.TransportError as exc:
                log.debug("Vault not reachable: %s — retrying in 2s", exc)
            await asyncio.sleep(2)
    raise RuntimeError(f"Vault did not become ready within {max_wait}s.")


def setup_vault_secret() -> str:
    """
    Enable KV v2 at 'secret/' if needed. Read existing master secret if present,
    only generate a new one on first run. Returning the same secret across runs
    ensures credential_store blobs remain decryptable.

    Returns the hex master secret value.
    """
    client = hvac.Client(url=VAULT_ADDR, token=VAULT_TOKEN)

    if not client.is_authenticated():
        raise RuntimeError(
            "Vault authentication failed. Check VAULT_ADDR and VAULT_TOKEN."
        )

    # Enable KV v2 at 'secret/' — ignore MountInUseError if already mounted.
    try:
        client.sys.enable_secrets_engine(
            backend_type="kv",
            path="secret",
            options={"version": "2"},
        )
        log.info("Vault KV v2 enabled at 'secret/'")
    except hvac.exceptions.InvalidRequest as exc:
        if "path is already in use" in str(exc).lower():
            log.info("Vault KV v2 already enabled at 'secret/' — skipping enable")
        else:
            raise

    kv_path = BROKER_MASTER_SECRET_PATH.removeprefix("secret/data/")

    # Read existing secret first — only write a new one if the path is empty.
    # Overwriting on every seeder run would invalidate all credential_store blobs
    # that were encrypted against the previous master secret.
    try:
        existing = client.secrets.kv.v2.read_secret_version(
            path=kv_path,
            mount_point="secret",
            raise_on_deleted_version=True,
        )
        master_value = existing["data"]["data"].get("master_secret", "")
        if master_value:
            log.info("Broker master secret already exists in Vault — reusing")
            return master_value
    except Exception:
        pass  # Not found or deleted — fall through to generate a new one

    master_value = os.urandom(32).hex()
    client.secrets.kv.v2.create_or_update_secret(
        path=kv_path,
        secret={"master_secret": master_value},
        mount_point="secret",
    )
    log.info("Broker master secret written to Vault at %s", BROKER_MASTER_SECRET_PATH)
    return master_value


async def run_sql_file(conn: asyncpg.Connection, sql_file: Path) -> None:
    """Execute a SQL file, wrapping errors for graceful handling."""
    sql = sql_file.read_text()
    try:
        await conn.execute(sql)
        log.info("Executed SQL file: %s", sql_file.name)
    except asyncpg.UniqueViolationError as exc:
        log.warning(
            "Unique constraint violation in %s (rows may already exist): %s",
            sql_file.name, exc
        )
    except Exception as exc:
        log.error("Error executing %s: %s", sql_file.name, exc)
        raise


def _encrypt_credential(
    plaintext: str,
    user_sub: str,
    master_bytes: bytes,
    *,
    service: str,
    tool_id: str,
    owner_type: str,
) -> bytes:
    """
    Inline replica of proxy/app/credential_broker/approaches/approach_a.encrypt().
    Must stay byte-for-byte compatible with the proxy's decrypt() function.
    Format: salt(32B) || nonce(12B) || AES-256-GCM ciphertext+tag
    """
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    _HKDF_INFO_PREFIX = b"mcp-credential-broker-kek-v2:"
    _AAD_PREFIX = "mcp-cred-v2"

    salt = os.urandom(32)
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=_HKDF_INFO_PREFIX + user_sub.encode(),
    )
    kek = bytearray(hkdf.derive(master_bytes))
    try:
        nonce = os.urandom(12)
        aad = f"{_AAD_PREFIX}|{user_sub}|{service}|{tool_id}|{owner_type}".encode()
        ct = AESGCM(bytes(kek)).encrypt(nonce, plaintext.encode(), aad)
        return salt + nonce + ct
    finally:
        for i in range(len(kek)):
            kek[i] = 0


async def store_service_credential(
    conn: asyncpg.Connection,
    master_hex: str,
    service_name: str,
    tool_name: str,
    token: str,
) -> None:
    """
    Encrypt `token` and upsert it into credential_store as a service-mode row.
    The proxy's _inject_service_credential() will decrypt it at call time.
    """
    row = await conn.fetchrow(
        "SELECT tool_id FROM tool_registry WHERE name=$1 AND deleted_at IS NULL",
        tool_name,
    )
    if not row:
        log.error("Tool '%s' not found in registry — cannot store credential", tool_name)
        return

    tool_id = str(row["tool_id"])
    master_bytes = bytes.fromhex(master_hex)
    blob = _encrypt_credential(
        token,
        "__service__",
        master_bytes,
        service=service_name,
        tool_id=tool_id,
        owner_type="service",
    )

    await conn.execute(
        """
        INSERT INTO credential_store
            (user_sub, service, tool_id, owner_type, credential_type, encrypted_blob)
        VALUES ('__service__', $1, $2::uuid, 'service', 'api_key', $3)
        ON CONFLICT (tool_id, service) WHERE owner_type = 'service' AND tool_id IS NOT NULL
        DO UPDATE SET
            encrypted_blob = EXCLUDED.encrypted_blob,
            updated_at = now()
        """,
        service_name,
        tool_id,
        blob,
    )
    log.info(
        "Service credential stored: tool=%s service=%s tool_id=%s",
        tool_name, service_name, tool_id,
    )


def _write_env_var(env_file: str, key: str, value: str) -> None:
    """
    Upsert KEY=value in env_file. If the key exists (even empty), replace its line.
    If absent, append. Only updates when the value is non-empty.
    """
    if not value:
        return
    try:
        lines = open(env_file).readlines() if os.path.exists(env_file) else []
    except OSError:
        lines = []

    prefix = f"{key}="
    replaced = False
    new_lines = []
    for line in lines:
        if line.startswith(prefix):
            new_lines.append(f"{key}={value}\n")
            replaced = True
        else:
            new_lines.append(line)
    if not replaced:
        new_lines.append(f"{key}={value}\n")

    with open(env_file, "w") as f:
        f.writelines(new_lines)
    log.info("Updated %s: %s=<token>", env_file, key)


async def fix_oidc_issuer_placeholder(conn: asyncpg.Connection) -> int:
    """
    Replace __OIDC_ISSUER_PLACEHOLDER__ in oidc_role_mappings with the real
    OIDC issuer URL.  Returns the number of rows updated.

    The migration (V002) inserts placeholder rows because the issuer URL is
    environment-specific and cannot be hardcoded in a portable migration file.
    The seeder runs after migrations and substitutes the real value on every
    run (idempotent — a second run finds 0 rows to update).
    """
    result = await conn.execute(
        """
        UPDATE oidc_role_mappings
        SET oidc_issuer = $1
        WHERE oidc_issuer = '__OIDC_ISSUER_PLACEHOLDER__'
        """,
        OIDC_ISSUER_URL,
    )
    # asyncpg returns "UPDATE N" as a status string
    updated = int(result.split()[-1]) if result else 0
    if updated:
        log.info(
            "oidc_role_mappings: replaced %d placeholder rows with issuer=%s",
            updated, OIDC_ISSUER_URL,
        )
    else:
        log.info(
            "oidc_role_mappings: no placeholder rows found (already substituted or empty)"
        )
    return updated


async def revoke_placeholder_api_keys(conn: asyncpg.Connection) -> int:
    """
    Revoke API key rows whose key_hash is a known placeholder pattern.
    These keys were inserted by V002 migration and lab/seeder/sql/roles.sql
    and can never authenticate (no real HMAC was computed). Revoking them
    removes the hygiene risk of unrevokable zero-hash entries.
    Returns the number of rows revoked.
    """
    placeholder_hashes = [
        "0000000000000000000000000000000000000000000000000000000000000000",
        "a1ce0000000000000000000000000000000000000000000000000000000000a1",
        "b0b00000000000000000000000000000000000000000000000000000000000b0",
    ]
    result = await conn.execute(
        """
        UPDATE api_keys
        SET revoked_at = NOW()
        WHERE key_hash = ANY($1::text[])
          AND revoked_at IS NULL
        """,
        placeholder_hashes,
    )
    revoked = int(result.split()[-1]) if result else 0
    if revoked:
        log.warning(
            "api_keys: revoked %d placeholder-hash row(s) — generate real keys via "
            "infra/scripts/create-bootstrap-key.sh",
            revoked,
        )
    else:
        log.info("api_keys: no unrevoked placeholder-hash rows found")
    return revoked


async def create_grafana_token() -> Optional[str]:
    """
    Create a Grafana service account 'mcp-broker' (Viewer role) and generate
    an API token for it. Returns the token key, or None on failure.
    Prints: GRAFANA_ADMIN_TOKEN=<key>

    The credential broker only needs to query dashboards/datasources on behalf
    of users — Viewer is sufficient. If a future tool needs to create alerts or
    edit dashboards, define a separate SA with the narrower role rather than
    elevating this one.
    """
    auth = ("admin", LAB_GRAFANA_ADMIN_PASSWORD)
    headers = {"Content-Type": "application/json"}

    async with httpx.AsyncClient(timeout=15, base_url=LAB_GRAFANA_URL) as client:
        # Step 1: Create service account (idempotent — if name exists, Grafana
        # returns the existing account in some versions; handle 409 gracefully).
        sa_payload = {"name": "mcp-broker", "role": "Viewer"}
        try:
            resp = await client.post(
                "/api/serviceaccounts",
                json=sa_payload,
                auth=auth,
                headers=headers,
            )
        except httpx.TransportError as exc:
            log.error("Cannot reach Grafana at %s: %s", LAB_GRAFANA_URL, exc)
            return None

        already_exists = (
            resp.status_code == 409
            or (resp.status_code == 400 and "already exists" in resp.text)
        )
        if already_exists:
            # Service account already exists — fetch it by name.
            log.info("Grafana service account 'mcp-broker' already exists; fetching ID")
            search_resp = await client.get(
                "/api/serviceaccounts/search",
                params={"query": "mcp-broker"},
                auth=auth,
            )
            if search_resp.status_code != 200:
                log.error(
                    "Grafana service account search failed: %s %s",
                    search_resp.status_code, search_resp.text,
                )
                return None
            accounts = search_resp.json().get("serviceAccounts", [])
            if not accounts:
                log.error("Grafana service account 'mcp-broker' not found after conflict.")
                return None
            sa_id = accounts[0]["id"]
        elif resp.status_code in (200, 201):
            sa_id = resp.json()["id"]
            log.info("Grafana service account 'mcp-broker' created (id=%s)", sa_id)
        else:
            log.error(
                "Grafana service account creation failed: %s %s",
                resp.status_code, resp.text,
            )
            return None

        # Step 2: Generate API token for the service account (unique name avoids conflict).
        import time as _time
        token_name = f"mcp-lab-token-{int(_time.time())}"
        token_resp = await client.post(
            f"/api/serviceaccounts/{sa_id}/tokens",
            json={"name": token_name},
            auth=auth,
            headers=headers,
        )
        if token_resp.status_code not in (200, 201):
            log.error(
                "Grafana token creation failed: %s %s",
                token_resp.status_code, token_resp.text,
            )
            return None

        token_key = token_resp.json().get("key")
        if not token_key:
            log.error("Grafana response did not contain a token key: %s", token_resp.json())
            return None

        log.info("Grafana API token created for service account id=%s", sa_id)
        print(f"GRAFANA_ADMIN_TOKEN={token_key}")
        return token_key


async def create_netbox_token() -> Optional[str]:
    """
    Create a NetBox API token for the lab. Requires LAB_NETBOX_ADMIN_TOKEN to
    be set in the environment. If absent, prints a warning and returns None.
    Prints: NETBOX_ADMIN_TOKEN=<token_key>
    """
    if not LAB_NETBOX_ADMIN_TOKEN:
        log.warning(
            "LAB_NETBOX_ADMIN_TOKEN is not set — skipping NetBox token seeding. "
            "Set this env var to an existing NetBox admin token and re-run the seeder."
        )
        return None

    headers = {
        "Authorization": f"Token {LAB_NETBOX_ADMIN_TOKEN}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }

    async with httpx.AsyncClient(timeout=15, base_url=LAB_NETBOX_URL) as client:
        try:
            # Look up the admin user ID (required by the tokens API)
            user_resp = await client.get(
                "/api/users/users/",
                params={"username": "admin"},
                headers=headers,
            )
            if user_resp.status_code != 200 or not user_resp.json().get("results"):
                log.error("NetBox user lookup failed: %s %s", user_resp.status_code, user_resp.text)
                return None
            user_id = user_resp.json()["results"][0]["id"]

            # Check for existing mcp-lab token to stay idempotent
            existing_resp = await client.get(
                "/api/users/tokens/",
                params={"user_id": user_id, "description": "mcp-lab"},
                headers=headers,
            )
            if existing_resp.status_code == 200 and existing_resp.json().get("results"):
                token_key = existing_resp.json()["results"][0]["key"]
                log.info("NetBox mcp-lab token already exists — reusing")
                print(f"NETBOX_ADMIN_TOKEN={token_key}")
                return token_key

            # Create a new token for the admin user
            resp = await client.post(
                "/api/users/tokens/",
                json={"user": user_id, "description": "mcp-lab"},
                headers=headers,
            )
        except httpx.TransportError as exc:
            log.error("Cannot reach NetBox at %s: %s", LAB_NETBOX_URL, exc)
            return None

        if resp.status_code not in (200, 201):
            log.error(
                "NetBox token creation failed: %s %s",
                resp.status_code, resp.text,
            )
            return None

        token_key = resp.json().get("key")
        if not token_key:
            log.error("NetBox response did not contain a token key: %s", resp.json())
            return None

        log.info("NetBox API token created (description=mcp-lab)")
        print(f"NETBOX_ADMIN_TOKEN={token_key}")
        return token_key


async def create_gitea_token() -> Optional[str]:
    """Create or retrieve a Gitea API token for the admin user."""
    token_name = "mcp-lab"
    auth = (LAB_GITEA_ADMIN_USER, LAB_GITEA_ADMIN_PASSWORD)

    async with httpx.AsyncClient(base_url=LAB_GITEA_URL, timeout=15) as client:
        try:
            # Check if the token already exists
            existing = await client.get(
                f"/api/v1/users/{LAB_GITEA_ADMIN_USER}/tokens",
                auth=auth,
            )
            if existing.status_code == 200:
                for t in existing.json():
                    if t.get("name") == token_name:
                        log.info("Gitea mcp-lab token already exists — re-creating to get the key")
                        # Delete the old token so we can recreate it (Gitea only exposes key on creation)
                        await client.delete(
                            f"/api/v1/users/{LAB_GITEA_ADMIN_USER}/tokens/{t['id']}",
                            auth=auth,
                        )
                        break

            # Create a new token (Gitea 1.19+ requires at least one scope)
            resp = await client.post(
                f"/api/v1/users/{LAB_GITEA_ADMIN_USER}/tokens",
                json={"name": token_name, "scopes": ["write:repository", "write:issue", "read:user"]},
                auth=auth,
                headers={"Content-Type": "application/json"},
            )
        except httpx.TransportError as exc:
            log.error("Cannot reach Gitea at %s: %s", LAB_GITEA_URL, exc)
            return None

    if resp.status_code not in (200, 201):
        log.error("Gitea token creation failed: %s %s", resp.status_code, resp.text)
        return None

    token_sha1 = resp.json().get("sha1")
    if not token_sha1:
        log.error("Gitea response did not contain sha1: %s", resp.json())
        return None

    log.info("Gitea API token created (name=%s)", token_name)
    print(f"GITEA_ADMIN_TOKEN={token_sha1}")
    return token_sha1


async def seed_m365_credential(conn: asyncpg.Connection, master_hex: str) -> bool:
    """
    Seed the AZURE_CLIENT_SECRET from environment into credential_store as an
    entra_client_credentials-mode service credential for the m365 tool.

    Task 2.5: AZURE_CLIENT_SECRET is removed from lab-mcp-m365's compose env;
    it is stored in credential_store and injected by the broker at call time
    via the X-Entra-Client-Secret header.

    Returns True on success, False if the env var is absent (skip).
    """
    azure_secret = os.environ.get("AZURE_CLIENT_SECRET", "").strip()
    if not azure_secret:
        log.info("AZURE_CLIENT_SECRET not set in env — skipping m365 credential seeding")
        return False

    try:
        await store_service_credential(
            conn, master_hex, "entra_client_credentials", "m365-mcp", azure_secret
        )
        log.info("m365 AZURE_CLIENT_SECRET seeded into credential_store as entra_client_credentials")
        return True
    except Exception as exc:
        log.error("m365 credential seeding failed: %s", exc)
        return False


async def seed_self_service_api_key(conn: asyncpg.Connection) -> Optional[str]:
    """
    Generate (or retrieve) a service API key for lab-mcp-self-service.

    The key is stored in the proxy's api_keys table under client_id
    'lab-self-service' with role 'agent'. The seeder generates a random
    hex key, hashes it via the same hash_api_key path used by the proxy,
    and writes the raw key to .env.lab as SELF_SERVICE_API_KEY.

    Idempotent: if a non-revoked key for 'lab-self-service' already exists,
    returns a new one (re-generation is safe — old key is revoked).

    Returns the raw (unhashed) key, or None on failure.
    """
    import hashlib
    import secrets

    raw_key = secrets.token_hex(32)
    # Hash using the same algorithm as proxy/app/core/security.py:hash_api_key
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()

    try:
        # Revoke any existing non-revoked keys for this client_id
        await conn.execute(
            """
            UPDATE api_keys SET revoked_at = NOW()
            WHERE client_id = 'lab-self-service' AND revoked_at IS NULL
            """,
        )
        # Insert new key
        await conn.execute(
            """
            INSERT INTO api_keys (client_id, key_hash, created_at)
            VALUES ('lab-self-service', $1, NOW())
            """,
            key_hash,
        )
        # Ensure role_assignments row exists for 'lab-self-service' with role 'agent'
        await conn.execute(
            """
            INSERT INTO role_assignments (client_id, role, assigned_by)
            VALUES ('lab-self-service', 'agent', 'seeder')
            ON CONFLICT (client_id, role) DO NOTHING
            """,
        )
        log.info("lab-self-service API key seeded (client_id=lab-self-service role=agent)")
        return raw_key
    except Exception as exc:
        log.error("lab-self-service API key seeding failed: %s", exc)
        return None


# ---------------------------------------------------------------------------
# Keycloak hardening — runs on every seeder invocation (idempotent)
# ---------------------------------------------------------------------------

async def harden_keycloak() -> dict[str, str]:
    """
    Enforce expected KC mcp-realm state:
      - Reset all expected user passwords to known-good values
      - Delete any unknown users (attacker artifacts)
      - Disable ROPC (directAccessGrantsEnabled) on mcp-proxy client
    Returns a results dict.
    """
    results: dict[str, str] = {}

    # Obtain master-realm admin token via admin-cli ROPC (admin-cli uses ROPC internally).
    async with httpx.AsyncClient(timeout=15.0) as client:
        try:
            resp = await client.post(
                f"{KC_ADMIN_URL}/realms/master/protocol/openid-connect/token",
                data={
                    "client_id": "admin-cli",
                    "grant_type": "password",
                    "username": "admin",
                    "password": KC_ADMIN_PASSWORD,
                },
            )
            if resp.status_code != 200:
                log.warning("KC admin token failed (%s) — skipping KC hardening", resp.status_code)
                return {"keycloak": f"SKIPPED (token {resp.status_code})"}
            admin_token = resp.json()["access_token"]
        except Exception as exc:
            log.warning("KC not reachable — skipping KC hardening: %s", exc)
            return {"keycloak": f"SKIPPED ({exc})"}

        headers = {"Authorization": f"Bearer {admin_token}", "Content-Type": "application/json"}

        # --- Enumerate users ---
        users_resp = await client.get(f"{KC_ADMIN_URL}/admin/realms/mcp/users", headers=headers)
        if users_resp.status_code != 200:
            return {"keycloak": f"FAILED (list users {users_resp.status_code})"}
        users = users_resp.json()

        # --- Delete unexpected users (attacker artifacts) ---
        deleted: list[str] = []
        for user in users:
            if user["username"] not in KC_EXPECTED_USERS:
                del_resp = await client.delete(
                    f"{KC_ADMIN_URL}/admin/realms/mcp/users/{user['id']}", headers=headers
                )
                if del_resp.status_code in (204, 404):
                    deleted.append(user["username"])
                    log.warning("KC hardening: deleted unexpected user '%s'", user["username"])
                else:
                    log.error("KC hardening: failed to delete '%s': %s", user["username"], del_resp.status_code)
        if deleted:
            results["kc_deleted_users"] = ", ".join(deleted)

        # --- Reset passwords for all expected users ---
        reset_ok: list[str] = []
        for user in users:
            uname = user["username"]
            if uname not in KC_EXPECTED_USERS:
                continue
            expected_pw = KC_USER_PASSWORDS.get(uname, "labpassword")
            pw_resp = await client.put(
                f"{KC_ADMIN_URL}/admin/realms/mcp/users/{user['id']}/reset-password",
                headers=headers,
                json={"type": "password", "value": expected_pw, "temporary": False},
            )
            if pw_resp.status_code == 204:
                reset_ok.append(uname)
            else:
                log.error("KC hardening: password reset for '%s' failed: %s", uname, pw_resp.status_code)
        if reset_ok:
            log.info("KC hardening: reset passwords for %s", reset_ok)

        # --- Enforce directAccessGrantsEnabled=false on mcp-proxy client ---
        clients_resp = await client.get(
            f"{KC_ADMIN_URL}/admin/realms/mcp/clients?clientId=mcp-proxy", headers=headers
        )
        if clients_resp.status_code == 200 and clients_resp.json():
            client_data = clients_resp.json()[0]
            if client_data.get("directAccessGrantsEnabled"):
                patch_resp = await client.put(
                    f"{KC_ADMIN_URL}/admin/realms/mcp/clients/{client_data['id']}",
                    headers=headers,
                    json={**client_data, "directAccessGrantsEnabled": False},
                )
                if patch_resp.status_code == 204:
                    log.warning("KC hardening: disabled ROPC on mcp-proxy client (was enabled)")
                    results["kc_ropc"] = "DISABLED (was enabled — attacker artifact)"
                else:
                    log.error("KC hardening: failed to disable ROPC: %s", patch_resp.status_code)
            else:
                results["kc_ropc"] = "OK (already disabled)"

    results["keycloak"] = "OK"
    return results


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

async def main() -> None:
    log.info("=== MCP Lab Seeder starting ===")

    results: dict[str, str] = {}

    # 1. Wait for Postgres
    log.info("Waiting for PostgreSQL...")
    conn = await wait_for_postgres(max_wait=60)

    # 2. Wait for Vault
    log.info("Waiting for Vault...")
    await wait_for_vault(max_wait=60)

    # 3. Write broker master secret to Vault (idempotent — reads existing if present)
    log.info("Setting up broker master secret in Vault...")
    master_hex: Optional[str] = None
    try:
        master_hex = setup_vault_secret()
        results["vault"] = "OK"
    except Exception as exc:
        log.error("Vault secret write failed: %s", exc)
        results["vault"] = f"FAILED: {exc}"

    # 4. Insert tool_registry rows
    log.info("Seeding tool_registry...")
    try:
        await run_sql_file(conn, SQL_DIR / "tools.sql")
        results["tools_sql"] = "OK"
    except Exception as exc:
        log.error("tools.sql seeding failed: %s", exc)
        results["tools_sql"] = f"FAILED: {exc}"

    # 4b. Onboard servers (server_registry + link tool_registry.server_id + entitlement)
    log.info("Seeding server_registry...")
    try:
        await run_sql_file(conn, SQL_DIR / "servers.sql")
        results["servers_sql"] = "OK"
    except Exception as exc:
        log.error("servers.sql seeding failed: %s", exc)
        results["servers_sql"] = f"FAILED: {exc}"

    # 5. Insert RBAC seed rows
    log.info("Seeding RBAC roles...")
    try:
        await run_sql_file(conn, SQL_DIR / "roles.sql")
        results["roles_sql"] = "OK"
    except Exception as exc:
        log.error("roles.sql seeding failed: %s", exc)
        results["roles_sql"] = f"FAILED: {exc}"

    # 5a. Fix oidc_role_mappings placeholder issuer
    log.info("Fixing OIDC issuer placeholder in oidc_role_mappings...")
    try:
        n = await fix_oidc_issuer_placeholder(conn)
        results["oidc_issuer_fix"] = f"OK ({n} rows updated)"
    except Exception as exc:
        log.error("oidc_role_mappings placeholder fix failed: %s", exc)
        results["oidc_issuer_fix"] = f"FAILED: {exc}"

    # 5b. Revoke placeholder API key hashes
    log.info("Revoking placeholder-hash API keys...")
    try:
        n = await revoke_placeholder_api_keys(conn)
        results["placeholder_key_revoke"] = f"OK ({n} rows revoked)"
    except Exception as exc:
        log.error("Placeholder API key revocation failed: %s", exc)
        results["placeholder_key_revoke"] = f"FAILED: {exc}"

    # 6. Create Grafana service account + token
    log.info("Creating Grafana service account and API token...")
    grafana_token = await create_grafana_token()
    results["grafana"] = "OK" if grafana_token else "FAILED or skipped"
    if grafana_token:
        # Grafana MCP server reads GRAFANA_SERVICE_ACCOUNT_TOKEN from env.
        # Write the token back to .env.lab so the next 'podman-compose up' picks it up.
        env_lab = str(Path(__file__).parent.parent.parent / ".env.lab")
        _write_env_var(env_lab, "GRAFANA_SERVICE_ACCOUNT_TOKEN", grafana_token)
        results["grafana_env"] = "OK (written to .env.lab)"

    # 7. Create NetBox API token
    log.info("Creating NetBox API token...")
    netbox_token = await create_netbox_token()
    results["netbox"] = (
        "OK" if netbox_token else
        "SKIPPED (LAB_NETBOX_ADMIN_TOKEN not set)" if not LAB_NETBOX_ADMIN_TOKEN
        else "FAILED"
    )
    if netbox_token:
        env_lab = str(Path(__file__).parent.parent.parent / ".env.lab")
        _write_env_var(env_lab, "NETBOX_TOKEN", netbox_token)
        results["netbox_env"] = "OK (written to .env.lab)"

    # 7b. Seed M365 client secret into credential_store (Task 2.5)
    if master_hex and results.get("tools_sql") == "OK":
        log.info("Seeding M365 AZURE_CLIENT_SECRET into credential_store...")
        conn_m365 = await wait_for_postgres(max_wait=10)
        m365_ok = await seed_m365_credential(conn_m365, master_hex)
        await conn_m365.close()
        results["m365_cred_store"] = "OK" if m365_ok else "SKIPPED (AZURE_CLIENT_SECRET not set)"

    # 8. Seed self-service MCP API key (Task 2.2b / Task 2.5)
    log.info("Seeding lab-self-service API key...")
    conn3 = await wait_for_postgres(max_wait=10)
    self_service_key = await seed_self_service_api_key(conn3)
    await conn3.close()
    results["self_service_key"] = "OK" if self_service_key else "FAILED"
    if self_service_key:
        env_lab = str(Path(__file__).parent.parent.parent / ".env.lab")
        _write_env_var(env_lab, "SELF_SERVICE_API_KEY", self_service_key)
        results["self_service_env"] = "OK (written to .env.lab)"

    # 9. Create Gitea API token
    log.info("Creating Gitea API token...")
    gitea_token = await create_gitea_token()
    results["gitea"] = "OK" if gitea_token else "FAILED"
    if gitea_token:
        env_lab = str(Path(__file__).parent.parent.parent / ".env.lab")
        _write_env_var(env_lab, "GITEA_ADMIN_TOKEN", gitea_token)
        results["gitea_env"] = "OK (written to .env.lab)"
        # Gitea MCP server supports header-based injection; store in credential_store.
        if master_hex and results.get("tools_sql") == "OK":
            try:
                conn2 = await wait_for_postgres(max_wait=10)
                await store_service_credential(conn2, master_hex, "gitea", "gitea-repos", gitea_token)
                await conn2.close()
                results["gitea_cred_store"] = "OK"
            except Exception as exc:
                log.error("Gitea credential_store write failed: %s", exc)
                results["gitea_cred_store"] = f"FAILED: {exc}"

    await conn.close()

    # 9. Keycloak hardening (idempotent — resets passwords, removes attacker users, disables ROPC)
    log.info("Hardening Keycloak realm state...")
    kc_results = await harden_keycloak()
    results.update(kc_results)

    # 10. Summary
    print("\n" + "=" * 60)
    print("LAB SEEDER SUMMARY")
    print("=" * 60)
    for step, status in results.items():
        icon = "OK" if status == "OK" else "!!"
        print(f"  [{icon}] {step:<20} {status}")

    print("\nTokens created and written to .env.lab (restart compose to apply):")
    if grafana_token:
        print("  GRAFANA_SERVICE_ACCOUNT_TOKEN — written")
    else:
        print("  GRAFANA_SERVICE_ACCOUNT_TOKEN — NOT created (check logs)")
    if netbox_token:
        print("  NETBOX_TOKEN — written")
    elif not LAB_NETBOX_ADMIN_TOKEN:
        print(
            "  NETBOX_TOKEN — SKIPPED (set LAB_NETBOX_ADMIN_TOKEN to an existing "
            "NetBox admin token and re-run seeder)"
        )
    else:
        print("  NETBOX_TOKEN — NOT created (check logs)")
    if gitea_token:
        print("  GITEA_ADMIN_TOKEN — written + stored in credential_store")
    else:
        print("  GITEA_ADMIN_TOKEN — NOT created (check logs)")
    print()
    print("After seeder completes: podman-compose -f podman-compose.lab.yml restart")
    print("to reload env vars into mcp-grafana, mcp-netbox, mcp-gitea containers.")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
