# mcphubd

Deploys the `mcphubd` binary itself as a digest-pinned podman quadlet.
Expects `postgres`, `redis`, and `vault` roles to have already run (see
`playbooks/site.yml` ordering) — `mcphub_data_network` membership and the
`mcphub-*-password` podman secrets they create are consumed here to build
the `DATABASE_URL` / `REDIS_URL` secrets. Env var names throughout this
role and its templates are verified against the real
`bin/mcphubd/src/config.rs` (100% environment-variable driven — there is
NO config-file reading anywhere in that binary; a previous version of this
role rendered and mounted `mcphubd.toml`, which nothing ever read).

## DATABASE_URL / migration split (new requirement, partially wired)

`fix-store` added `mcphub_store::assert_non_privileged_connection`, which
mcphubd is expected to call at startup and fail closed if the connected
role is a Postgres superuser or owns `audit_events` — either bypasses
every GRANT/REVOKE on that table (TRUNCATE, DISABLE TRIGGER, DROP all
become available), making the append-only guarantee decorative.

This role provisions the roles/secrets that fix requires:
- **`DATABASE_URL`** — the `mcphub_app` role (non-owner, non-superuser;
  password provisioned by `roles/postgres`, LOGIN + least-privilege GRANTs
  from migration `0004_ops.up.sql`). This is what the runtime pool and
  `assert_non_privileged_connection` should see.
- **`MCPHUBD_MIGRATION_DATABASE_URL`** — the `postgres_user` superuser/
  owner role. Needed to actually RUN migrations (`CREATE TABLE`,
  `CREATE ROLE`, etc., none of which `mcphub_app` can do).

**Confirmed NOT yet wired on the binary side** (as of this role's last
update): `bin/mcphubd/src/config.rs::AppConfig` has a single
`database_url` field, and `lib.rs::build_app` runs both
`mcphub_store::pool::connect` AND `mcphub_store::migrate::check` against
that ONE pool. `assert_non_privileged_connection` is defined and unit-
tested in `mcphub-store` but is not called anywhere in `bin/mcphubd` yet.
Until component 1/4 splits this into two connections (one for
`migrate::check`, reading `MCPHUBD_MIGRATION_DATABASE_URL`; one for
everything else, reading `DATABASE_URL`) and wires the assertion in after
connecting the runtime pool, **`DATABASE_URL` alone (mcphub_app) does not
have privilege to run migrations** — a fresh deploy will fail at
`migrate::check` until that wiring lands. This role provisions both
secrets now so the deploy side is ready the moment it does; do not assume
a fresh environment boots cleanly without confirming that wiring first.

## Multi-IDP: both configuration paths

Field shape is `rs/crates/mcphub-identity/src/config.rs::IdpConfig`,
verified against source (not guessed) — see `deploy/idp-examples/SCHEMA.md`.

- **Install-time** (this role): `mcphub_idp_config_file` (per-env YAML, set
  in `inventories/<env>/group_vars/all.yml`) is loaded with `include_vars`
  and rendered into `{{ mcphubd_idp_config_path }}` (`idp.json.j2`) as a
  **bare JSON array** — `FileIdpConfigLoader::from_json` expects exactly
  `Vec<IdpConfig>`, not TOML and not nested under a key, so it is its own
  file, separate from `mcphubd.toml`. Each entry's `client_secret` (which is
  NOT a field of `IdpConfig` — confirmed against source) is read from Vault
  (`vault_idp_secrets_path/<vault_secret_name>`, a deploy-only identifier —
  see below) and injected as its own podman secret.
- **Runtime**: per `rs/ARCHITECTURE.md`, runtime config (persisted to
  Postgres) should win over the file config once written, with the file as
  fallback if Postgres is unreachable at boot, and refusing to start with
  neither present as fail-closed default. **The JSON admin API this
  requires does not exist yet** — confirmed against
  `rs/crates/mcphub-ui/src/router.rs`, which only has a CSRF-protected HTML
  form at `/admin/idps`. See `deploy/idp-examples/API_CONTRACT.md` for the
  proposed contract and `deploy/scripts/configure_idp_runtime.py`, which is
  written against that contract and fails loudly (non-zero exit, clear
  message) against the current 404 rather than pretending to succeed.

### `vault_secret_name` — a deploy-only key, not part of `IdpConfig`

The real struct has no name/identifier field at all. Every
`idp.<vendor>.yml` entry carries one extra key, `vault_secret_name`, used
ONLY to select the Vault path / podman-secret name for that entry's
`client_secret`; `idp.json.j2` explicitly excludes it when rendering the
file mcphubd actually reads, so it never reaches the binary.

### Open question: how does mcphubd actually consume `client_secret`?

`IdpConfig` has no `client_secret` field (confirmed). This role delivers it
as `MCPHUBD_IDP_<VAULT_SECRET_NAME>_CLIENT_SECRET` (a podman secret env
var) on the assumption that some other component (likely `mcphub-creds`,
not `mcphub-identity`) reads it and binds it back to the matching issuer —
but that binding mechanism has not been confirmed against real code. If
that assumption is wrong, IDP entries requiring a confidential client
(`SharedExchange`, or `SharedPassthrough` with client auth) will silently
fail to authenticate outbound even though `idp.json` itself is correct.
Confirm with the integrator once `mcphub-creds`'/token-exchange wiring is
inspectable.

## dedicated_port auth mode (corrected — was modeled as per-server, is actually per-IDP)

`dedicated_port: Option<u16>` is a field on `IdpConfig` itself, not on any
backend-server row (confirmed against source — there is no server-scoped
struct with a port field). One `DedicatedPort` IDP = one listener, shared
by every backend server that uses that IDP. `[listeners] dedicated_range`
in `mcphubd.toml` sets the pool (`dedicated_port_range_start`..`_end`,
default 9000-9100) `playbooks/provision-dedicated-port.yml -e idp_name=<vault_secret_name>`
allocates from — it writes the allocated port into the idp.yml file's
`dedicated_port` field (install-time) and re-runs both `gateway` (opens/
routes it) and this role (re-applies `idp.json` with the port set). The
runtime-API equivalent is the `PATCH .../dedicated-port` route in
`API_CONTRACT.md`, also not yet implemented server-side.

## Secrets

Every secret this role creates is sourced from Vault via AppRole and
injected as a podman secret (`type=env`) — never a plaintext
`Environment=` line. `no_log: true` on every task that touches secret
material. Two different podman secret drivers are in play, deliberately:

- **`file` driver** (`DATABASE_URL`, `MCPHUBD_MIGRATION_DATABASE_URL`,
  `REDIS_URL`, per-IDP `client_secret`s): value IS written to this host's
  disk, base64-encoded (not encrypted) in podman's `secretsdata.json` —
  confirmed against real podman 5.8.3. Acceptable for these: worst case a
  stolen disk image yields DB/redis/IDP credentials, which is bad but
  bounded and independently rotatable.
- **`shell` driver** (`MCPHUB_VAULT_TOKEN`, `MCPHUB_AUDIT_HMAC_KEY`): value
  is NEVER written to disk at all — see `files/vault-secret-driver/` and
  the block comment in `tasks/main.yml`. Used for the credential-broker
  KEK's access path and the audit-chain HMAC key specifically, because
  either one's disclosure is NOT bounded the same way: the KEK decrypts
  every broker-managed credential in the Postgres dump, and the audit HMAC
  key is what makes the audit chain's HMAC meaningful against an attacker
  with DB write access (an unkeyed hash chain proves nothing against that
  threat model — see `mcphub-store`'s audit.rs).

### Vault token TTL (open operational question)

`MCPHUB_VAULT_TOKEN` is a FRESH AppRole-login token minted at every
container start — never a long-lived token sitting on disk. But it is
minted ONCE, at start, and `VaultKekSource`
(`rs/crates/mcphub-creds`) is not confirmed to renew it. If the AppRole's
configured `token_ttl` is shorter than mcphubd's actual uptime, KEK fetches
will start failing mid-run with no restart to fix it until the next deploy
or manual restart. Set the AppRole's `token_ttl`/`token_max_ttl` generously
(e.g. 24h+) until component 3 confirms whether `VaultKekSource` renews its
token itself — if it does, this note can be deleted.

### Audit HMAC key rotation

`MCPHUB_AUDIT_HMAC_KEY` (>= 32 bytes, minimum enforced by `config.rs`) is
fetched live from Vault (KV, `vault_audit_hmac_path`) the same way as the
KEK's access path, via the shell driver — never Postgres-derived (rotating
would otherwise hand the key to the exact attacker-with-DB-write-access
threat model it defends against) and never disk-persisted on this host.

**Rotating it invalidates HMAC verification of every audit row written
under the OLD key** — this is a compliance-relevant action, not a routine
one. Use `playbooks/rotate-audit-hmac-key.yml`, which does exactly one
thing (restart mcphubd so it picks up the current Vault value) and prints
an explicit warning before doing it. There is currently no re-keying/
re-signing mechanism for historical rows — if that's required, it needs a
batch job (component 4's concern, not deploy's) run BEFORE the old key is
removed from Vault.

## Health

No in-container `HealthCmd` — the final `rs/Containerfile` image is
distroless with no shell, so there is nothing to exec a healthcheck command
with. Liveness/readiness is verified externally, from the host network
namespace, by the `health_check` role (`GET /health/ready`) and by
`playbooks/deploy.yml`'s post-deploy gate before it's considered successful.
