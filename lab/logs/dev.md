# Dev Log — Lab Code Review
Date: 2026-05-01

## Files Reviewed

### proxy/app/credential_broker/adapters/dex.py
**Status**: Fixed
**Issues found**:
1. `build_auth_url()` included `"response_mode": "query"` in the OAuth2 authorization URL parameters. This is a Microsoft MSAL/Entra-specific extension and is not part of the OIDC/RFC 6749 standard. Dex silently ignores it, but it is incorrect and would confuse debugging or break if a future IdP is stricter.
2. `_post_token()` used `data["refresh_token"]` (hard key access). Dex only includes `refresh_token` in the token response when the `offline_access` scope is granted AND the Dex issuer config has `grantTypes: ["authorization_code", "refresh_token"]`. If either condition is not met, the field is absent and the code raises `KeyError`, crashing the enrollment flow.

**Fix applied**:
- Removed `"response_mode": "query"` from `build_auth_url()` parameters. Added a comment explaining why it was removed and that this is an Entra-specific extension.
- Changed `data["refresh_token"]` to `data.get("refresh_token", "")` in `_post_token()`. Added a comment explaining when Dex omits the field.

**Interface conformance**: DexAdapter correctly does NOT extend BaseAdapter. BaseAdapter is Approach B (provision/revoke). DexAdapter is Approach A and correctly exposes `build_auth_url()`, `exchange_code()`, `refresh()` — matching the M365Adapter/BitbucketAdapter interface pattern used by the OAuth router. Verified correct.

---

### proxy/app/routers/oauth.py
**Status**: OK
**Issues found**: None.
- The `"dex"` case in `_get_adapter()` correctly instantiates `DexAdapter` with `issuer_url=settings.DEX_ISSUER_URL`, `client_id=settings.DEX_CLIENT_ID`, `client_secret=settings.DEX_CLIENT_SECRET`, `redirect_uri=settings.DEX_REDIRECT_URI`, `scopes=settings.dex_scopes_list`. All five parameters match `DexAdapter.__init__` exactly.
- `hmac.new(secret, raw.encode(), hashlib.sha256).hexdigest()` is valid Python stdlib usage (not a bug — `hmac.new` is the correct function name, not `hmac.HMAC`).
- State generation and CSRF verification logic is correct.

---

### proxy/app/core/config.py
**Status**: OK
**Issues found**: None.
- `DEX_ISSUER_URL` default is `http://localhost:5556/dex` — correct for lab.
- `DEX_CLIENT_ID` defaults to `mcp-proxy`, `DEX_CLIENT_SECRET` to `mcp-proxy-secret` — consistent with lab Dex config.
- `dex_scopes_list` property splits `DEX_SCOPES` on whitespace; `DEX_SCOPES` defaults to `"openid profile email offline_access"` — this produces the correct list and `offline_access` is included, which is required for refresh token issuance.
- `DEX_REDIRECT_URI` default `http://localhost:8000/auth/callback/dex` is correct for local development.
- `BROKER_MASTER_SECRET_PATH` default is `secret/data/credential-broker`, which differs from the seeder's env default (`secret/data/mcp/broker-master`). Both are set explicitly via env vars in production; the discrepancy in defaults is acceptable but worth noting.

---

### lab/seeder/seed.py
**Status**: OK
**Issues found**: None (all previously flagged concerns verified as correct).
- Vault KV v2 path stripping: `kv_path = BROKER_MASTER_SECRET_PATH.removeprefix("secret/data/")` correctly strips the full prefix. With env var `secret/data/mcp/broker-master`, the result is `mcp/broker-master`. The hvac call uses `mount_point="secret"` — correct per hvac KV v2 API.
- asyncpg connection string uses `DB_HOST`, `DB_PORT`, `DB_NAME`, `DB_USER`, `DB_PASSWORD` — all correct.
- `SQL_DIR = Path(__file__).parent / "sql"` resolves to `/app/sql/` inside the container (seeder Dockerfile copies to `/app/`). Files are read as `SQL_DIR / "tools.sql"` and `SQL_DIR / "roles.sql"` — resolves correctly.
- Grafana SA creation uses `/api/serviceaccounts` — confirmed as the correct Grafana 11.x service accounts API endpoint.
- Script exits via `asyncio.run(main())` with no explicit sys.exit call; on success the coroutine returns normally and the process exits 0. On unhandled exception, asyncio exits non-zero. Correct.
- `DB_HOST` defaults to `"mcp-db"` (the container name). The compose explicitly overrides `DB_HOST: mcp-db` in the seeder environment. Works correctly.

---

### lab/seeder/sql/tools.sql
**Status**: OK
**Issues found**: None.
- All columns referenced (`service_name`, `credential_approach`, `inject_header`, `inject_prefix`) are confirmed present in V007 migration via `ALTER TABLE tool_registry ADD COLUMN IF NOT EXISTS`.
- `ON CONFLICT (name, version)` — confirmed correct: V001 migration defines `CONSTRAINT tool_registry_name_version_unique UNIQUE (name, version)` on `tool_registry`.
- All three tool rows use correct `credential_approach` values (`'A'` for dex-calendar, `'B'` for grafana-query and netbox-query) matching the schema `CHECK (credential_approach IN ('A', 'B'))`.

---

### lab/seeder/sql/roles.sql
**Status**: OK (previously corrected by another agent; verified correct)
**Issues found**: None.
- The file correctly does NOT target a `client_roles` table (which does not exist in V001–V007 migrations). It inserts into `api_keys` using the schema confirmed in V001 and V002.
- `ON CONFLICT (key_id) DO NOTHING` is correct — `key_id` is the PK of `api_keys`.
- `key_hash` values are 64-char hex strings, satisfying the `CHAR(64)` column type and `CHECK (LENGTH(key_hash) = 64)` constraint.
- `roles` values use PostgreSQL array literal syntax `'{"operator"}'` and `'{"auditor"}'` — correct.

---

### mcps.yaml
**Status**: OK
**Issues found**: None.
- `lab-grafana` entry is syntactically correct YAML. Uses `adapter: grafana` (Approach B) — the router has a `"grafana"` case (via the grafana adapter). Correct.
- `lab-dex` entry is syntactically correct YAML. Uses `adapter: dex` (Approach A, `flow: authorization_code`) — the router has a `"dex"` case confirmed in `oauth.py`. Correct.
- No duplicate keys, no missing required fields.

---

### lab/scripts/vault-init.sh
**Status**: Fixed
**Issues found**:
1. No preflight check for vault CLI availability. With `set -euo pipefail`, if `vault` is not installed, the script fails at the first `vault` command with a generic "command not found" error that is not user-friendly and gives no remediation guidance.
2. (Verified OK) `vault secrets enable ... 2>/dev/null || { echo "...already enabled..." }` — correctly handles the already-mounted case without masking other error types (since `2>/dev/null` suppresses Vault's own error text and the `||` block emits a clear message).
3. (Verified OK) Health check using `curl -sf` is correct. Vault dev mode returns HTTP 200 when healthy.

**Fix applied**:
- Added a preflight block immediately after the initial env var assignments that checks `command -v vault` and exits with a clear error message and install instructions if the CLI is missing.

---

### Makefile.lab
**Status**: Fixed
**Issues found**:
1. `lab-rebuild` target ran `$(LAB_COMPOSE) up -d --no-deps proxy lab-grafana lab-netbox lab-seeder` then immediately `$(LAB_COMPOSE) run --rm lab-seeder`. For a service declared `restart: "no"`, `up -d` does not re-run a previously-exited container — but including `lab-seeder` in the `up -d --no-deps` list is misleading and could cause ordering issues if compose decides to start it. The seeder should only be launched via `run --rm`.

**Fix applied**:
- Removed `lab-seeder` from the `up -d --no-deps` line in `lab-rebuild`. The `run --rm lab-seeder` on the next line is the correct and only invocation.

---

### podman-compose.lab.yml
**Status**: OK
**Issues found**: None.
- `lab-seeder` depends_on `db` and `vault` — confirmed: `docker-compose.yml` defines these services as `db` (container: `mcp-db`) and `vault` (container: `mcp-vault`). The `depends_on` keys reference service names, not container names, so `db` and `vault` are exactly correct.
- External network references `mcp-security-platform_internal-net` and `mcp-security-platform_vault-net` match the project name derived from the directory name `mcp-security-platform` and network names `internal-net` / `vault-net` in `docker-compose.yml`. Correct.
- `lab-seeder` environment sets `DB_HOST: mcp-db` (the container hostname on Docker networks) and `VAULT_ADDR: http://mcp-vault:8200` — both correct for inter-container communication.

---

## Bugs Fixed

| File | Bug | Fix |
|------|-----|-----|
| `proxy/app/credential_broker/adapters/dex.py` | `build_auth_url()` included `response_mode: query`, an Entra-specific parameter not supported by standard OIDC/Dex | Removed the `response_mode` key from the params dict; added explanatory comment |
| `proxy/app/credential_broker/adapters/dex.py` | `_post_token()` accessed `data["refresh_token"]` with hard key lookup, causing `KeyError` when Dex omits the field (server config or missing `offline_access`) | Changed to `data.get("refresh_token", "")` with explanatory comment |
| `lab/scripts/vault-init.sh` | No preflight check for vault CLI; script fails with unhelpful "command not found" when vault is not installed | Added `command -v vault` guard with clear error message and install instructions before any vault commands execute |
| `Makefile.lab` | `lab-rebuild` listed `lab-seeder` in `up -d --no-deps` causing ambiguous lifecycle for a `restart: "no"` container, then separately ran `run --rm lab-seeder` | Removed `lab-seeder` from the `up -d --no-deps` invocation; seeder is only launched via `run --rm` |

---

## Issues Requiring Attention

### 1. `BROKER_MASTER_SECRET_PATH` default mismatch
`config.py` defaults `BROKER_MASTER_SECRET_PATH` to `secret/data/credential-broker`, while `seed.py` defaults to `secret/data/mcp/broker-master`. Both values are overridden via environment variables in compose, so this does not affect runtime behavior. However, it creates confusion for anyone running either component standalone. Recommend aligning the defaults to a single canonical value (suggest `secret/data/mcp/broker-master`) in both files and documenting it in `.env.example`.

### 2. `DexAdapter.refresh()` with empty refresh_token
Now that `_post_token()` returns `""` when no refresh_token is present, callers of `refresh("")` will send `refresh_token=` (empty string) to Dex's token endpoint, which Dex will reject with an error. The OAuth router (`oauth.py`) only calls `exchange_code()` during enrollment and does not call `refresh()` directly — but any future code retrieving stored credentials for a user who enrolled without refresh token support will call `refresh("")` and get a 400 from Dex. The calling layer should check if the stored refresh_token is empty and either re-prompt enrollment or return a clear error. This is a design consideration for the credential retrieval path, not a bug in the seeder.

### 3. Dex OIDC endpoint discovery
`DexAdapter` hardcodes endpoint paths as `{issuer_url}/token` and `{issuer_url}/auth`. Per OIDC spec, these should be discovered via `{issuer}/.well-known/openid-configuration`. This is acceptable for a controlled lab environment where the IdP is known, but would fail if the Dex config uses non-default paths. Consider adding a one-time discovery step in `__init__` using httpx to fetch the well-known document for robustness.

### 4. `vault-init.sh` overwrites broker master secret on every run
`vault kv put secret/mcp/broker-master value="$(openssl rand -hex 32)"` generates a fresh random value every time the script runs. If the seeder has already run and stored credentials encrypted with the previous master secret, overwriting the master secret invalidates all stored credentials without warning. The script should check whether the secret already exists (`vault kv get`) before writing, or add a `--force` flag.

---

## Recommendations

1. **Align `BROKER_MASTER_SECRET_PATH` defaults** between `config.py` and `seed.py`. Add the canonical value to `.env.example` with a comment explaining the format requirement for hvac's KV v2 API (the path without the `secret/data/` prefix is what hvac needs internally).

2. **Add an existence check to `vault-init.sh`** before writing the broker master secret. Pattern: `vault kv get secret/mcp/broker-master &>/dev/null || vault kv put ...`. This prevents silently invalidating in-use credentials on re-init.

3. **Add a `refresh_token` presence check in the enrollment flow**. After `exchange_code()`, if `refresh_token == ""`, log a warning and consider either blocking enrollment (the user won't be able to refresh later) or noting it in the credential store so the retrieval path knows to re-prompt.

4. **Consider OIDC discovery in `DexAdapter`**. Fetching `{issuer}/.well-known/openid-configuration` once at startup to resolve token and auth endpoint URLs is the correct OIDC approach and protects against Dex config changes.

5. **Add a `vault` CLI version check** to `vault-init.sh`. KV v2 commands differ between Vault CLI 1.x versions (`vault kv put` vs `vault secrets enable -path=secret kv-v2`). The current script assumes a reasonably modern CLI; adding `vault version` output to the script's startup log aids debugging.
