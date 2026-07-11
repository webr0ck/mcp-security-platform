# Runbook: Vault Init / Unseal

## Symptom

- Proxy logs show 500s on every OIDC callback, or `kms.py::get_master_secret`
  errors, or credential-broker requests fail with "KMS/Vault unavailable".
- `make health` or `curl -sf http://localhost:8000/health` shows the proxy up
  but the broker path 5xx-ing.
- `podman ps` shows `mcp-vault` running but `vault status` reports `Sealed: true`.
- Fresh `lab-up` never completes because `lab-vault-init` times out waiting
  for Vault to become ready.

## Diagnosis

```bash
# Is the container up at all?
podman ps --filter name=mcp-vault

# Vault status — exit 0 = unsealed/active, exit 2 = sealed, anything else is a hard failure.
podman exec mcp-vault vault status -address=https://localhost:8200 -tls-skip-verify

# Is the broker master secret (KEK) actually present?
podman exec -e VAULT_ADDR=http://127.0.0.1:8200 -e VAULT_TOKEN=<token> mcp-vault \
    vault kv get secret/mcp/broker-master

# Tail the vault container's own log — the lab entrypoint logs every step
# ("[vault-auto-unseal] ...") including init/unseal/token-mint decisions.
podman logs mcp-vault --tail 100
```

## Resolution

This repo has **two different Vault postures** — know which one you're
looking at before "fixing" anything:

1. **Lab (`podman-compose.lab.yml` overlay)** — persistent file-storage Vault
   with a **self-healing auto-unseal wrapper**: `lab/vault/auto-unseal.sh`
   (mounted as the container entrypoint). On every container start it:
   - starts `vault server -config=$CONFIG`,
   - runs `vault operator init -key-shares=1 -key-threshold=1` on first boot
     only, persisting the unseal key + root token to
     `/vault/data/.vault-init` (mode 600, inside the `vault-data` volume —
     never a committed dotenv),
   - unseals automatically using that persisted key on every restart,
   - mints/reuses a **fixed bootstrap token** (`VAULT_BOOTSTRAP_TOKEN`) so the
     proxy/seeder can authenticate with a static literal against a live,
     unsealed Vault,
   - seeds `secret/mcp/broker-master` (the KEK) **only if absent** — it never
     rotates an existing value (would orphan already-encrypted
     `credential_store` rows).

   If this Vault is sealed and NOT auto-recovering, the entrypoint itself is
   failing — check `podman logs mcp-vault` for the `[vault-auto-unseal]` line
   where it stopped. Common cause: the `vault-data` volume was wiped (see
   `docs/runbooks/incident-triage.md` — **never** run `down -v` per repo
   policy) which forces a fresh `operator init`, producing a **new** unseal
   key/root token and, if `secret/mcp/broker-master` was also wiped, a **new
   KEK** — any credential_store rows encrypted under the old KEK become
   permanently undecryptable.

   Manual recovery if you must run the wrapper's steps by hand:
   ```bash
   make -f Makefile.lab lab-vault-init     # runs lab/scripts/vault-init.sh
   ```
   `lab/scripts/vault-init.sh` is a separate, idempotent companion script (not
   the entrypoint) that: waits for Vault health, enables KV v2 at `secret/`,
   writes the broker master secret **only if absent**, and writes
   `secret/mcp/lab-config` (Grafana/NetBox/Dex URLs). Run it any time you
   need to re-assert lab secrets without restarting the container.

2. **Base `docker-compose.yml` (non-lab / production-style)** — Vault runs
   file-storage + TLS with **no dev mode and no auto-unseal**. A fresh
   deploy yields a *sealed* Vault by design (see the comment block above the
   `vault:` service in `docker-compose.yml`). You must manually:
   ```bash
   podman exec -it mcp-vault vault operator init \
       -address=https://localhost:8200 -tls-skip-verify \
       -key-shares=5 -key-threshold=3
   # Securely distribute the 5 unseal key shares to separate key-holders.
   # Then, from 3 different key-holders:
   podman exec -it mcp-vault vault operator unseal -address=https://localhost:8200 -tls-skip-verify
   ```
   **Gap / honesty note:** there is no scripted auto-unseal for this
   production-style posture in this repo — `docker-compose.yml`'s own comment
   says the lab overlay is the only place unseal is automated. A real
   production deployment must add a real auto-unseal seal (cloud KMS
   transit/HSM) — `lab/vault/local.hcl` is referenced as the place to wire
   that in but does not yet configure one. Track this as a known gap, not an
   oversight to route around by copying the lab wrapper.

## Verification

```bash
podman exec mcp-vault vault status -address=https://localhost:8200 -tls-skip-verify
# Sealed: false, Initialized: true

podman exec -e VAULT_TOKEN=<token> mcp-vault vault kv get secret/mcp/broker-master
# value present, non-empty

curl -sf http://localhost:8000/health/ready | python3 -m json.tool
# broker/KMS dependency reports healthy
```

Then confirm a live OIDC login round-trips (proxy no longer 500s on
`/api/v1/auth/oidc/callback`).

## Prevention / Related

- Never run `podman-compose down -v` or otherwise delete the `vault-data`
  volume — see the "Lab DB NOT Fresh-Bootable" guidance and
  `docs/runbooks/incident-triage.md`.
- `docs/runbooks/audit-restore.md` — the KEK also protects nothing about the
  audit archive; that path is separate (MinIO Object Lock), don't confuse the
  two.
- `lab/vault/auto-unseal.sh` is the single source of truth for the lab's
  unseal behavior — read it before assuming any manual `vault operator`
  sequence is required in the lab.
