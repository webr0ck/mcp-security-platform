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
    Enable KV v2 at 'secret/' if needed, then write the broker master secret.
    Returns the written hex value (not stored; only printed to confirm success).
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

    master_value = os.urandom(32).hex()

    # BROKER_MASTER_SECRET_PATH is 'secret/data/mcp/broker-master'
    # hvac KV v2 write uses the path WITHOUT the 'data/' prefix.
    # Strip leading 'secret/data/' and use 'mcp/broker-master' as the kv path.
    kv_path = BROKER_MASTER_SECRET_PATH.removeprefix("secret/data/")

    client.secrets.kv.v2.create_or_update_secret(
        path=kv_path,
        secret={"value": master_value},
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

    # 3. Write broker master secret to Vault
    log.info("Writing broker master secret to Vault...")
    try:
        setup_vault_secret()
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

    # 5. Insert RBAC seed rows
    log.info("Seeding RBAC roles...")
    try:
        await run_sql_file(conn, SQL_DIR / "roles.sql")
        results["roles_sql"] = "OK"
    except Exception as exc:
        log.error("roles.sql seeding failed: %s", exc)
        results["roles_sql"] = f"FAILED: {exc}"

    await conn.close()

    # 6. Create Grafana service account + token
    log.info("Creating Grafana service account and API token...")
    grafana_token = await create_grafana_token()
    results["grafana"] = "OK" if grafana_token else "FAILED or skipped"

    # 7. Create NetBox API token
    log.info("Creating NetBox API token...")
    netbox_token = await create_netbox_token()
    results["netbox"] = (
        "OK" if netbox_token else
        "SKIPPED (LAB_NETBOX_ADMIN_TOKEN not set)" if not LAB_NETBOX_ADMIN_TOKEN
        else "FAILED"
    )

    # 8. Summary
    print("\n" + "=" * 60)
    print("LAB SEEDER SUMMARY")
    print("=" * 60)
    for step, status in results.items():
        icon = "OK" if status == "OK" else "!!"
        print(f"  [{icon}] {step:<20} {status}")

    print("\nEnv vars to copy to .env.lab (if not already set):")
    if grafana_token:
        print(f"  GRAFANA_ADMIN_TOKEN=<printed above>")
    else:
        print("  GRAFANA_ADMIN_TOKEN=<not created — check logs>")
    if netbox_token:
        print("  NETBOX_ADMIN_TOKEN=<printed above>")
    elif not LAB_NETBOX_ADMIN_TOKEN:
        print(
            "  LAB_NETBOX_ADMIN_TOKEN=<set this to an existing NetBox admin token, "
            "then re-run seeder to generate NETBOX_ADMIN_TOKEN>"
        )
    else:
        print("  NETBOX_ADMIN_TOKEN=<not created — check logs>")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
