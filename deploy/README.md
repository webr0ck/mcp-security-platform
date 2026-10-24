# deploy

Ansible + podman-quadlet deployment for `mcphubd` (the Rust rewrite — see
`rs/ARCHITECTURE.md`). Replaces the compose-based lab/tier deploys for this
component; `podman-compose`/`docker-compose` are not used here — quadlets
(systemd `.container`/`.network`/`.volume` units) are the runtime unit.

## Layout

```
deploy/
  ansible/
    ansible.cfg
    requirements.yml         # ansible-galaxy collection.install -r requirements.yml
    inventories/{dev,staging,prod}/hosts.yml + group_vars/
    roles/{common,postgres,redis,vault,mcphubd,gateway,observability,mcp_backends,health_check,rollback}/
    playbooks/{site,deploy,rollback,health-check,smoke-test,configure-idp,provision-dedicated-port}.yml
  quadlets/                  # rendered-unit reference/documentation, see quadlets/README.md
  idp-examples/               # idp.yml schema + Entra/Keycloak/Zitadel worked examples
  configure-idp.sh            # interactive install-time IDP configurator
  scripts/configure_idp_runtime.py   # runtime IDP configurator (admin API)
rs/Containerfile               # mcphubd image build (cargo-chef, distroless, digest-pinned)
rs/loadgen/                    # 3000-agent open-loop load harness (see rs/loadgen/README.md)
```

## Quickstart

```bash
cd deploy/ansible
ansible-galaxy collection install -r requirements.yml

export VAULT_ROLE_ID=... VAULT_SECRET_ID=...   # AppRole creds for this env's Vault, never committed

# First-time full stack (idempotent — safe to re-run)
ansible-playbook -i inventories/dev/hosts.yml playbooks/site.yml

# Configure an IDP (install-time path)
../configure-idp.sh dev
ansible-playbook -i inventories/dev/hosts.yml playbooks/configure-idp.yml \
  -e mcphub_idp_config_file=../idp-examples/idp.dev.generated.yml

# Health-gated deploy of a new mcphubd build
ansible-playbook -i inventories/dev/hosts.yml playbooks/deploy.yml \
  -e mcphubd_image_digest=sha256:<new digest from CI>

# Roll back on demand
ansible-playbook -i inventories/dev/hosts.yml playbooks/rollback.yml

# Smoke test only (CI, post `make lab-up`-equivalent)
ansible-playbook -i inventories/dev/hosts.yml playbooks/smoke-test.yml
```

## Multi-IDP: both configuration paths

See `deploy/idp-examples/SCHEMA.md`. Install-time =
`playbooks/configure-idp.yml -e @idp.yml` (or `configure-idp.sh` to
generate that file interactively); runtime =
`scripts/configure_idp_runtime.py` against the admin API. Both produce the
same `IdpConfig` shape; runtime wins if both are present (per
`rs/ARCHITECTURE.md`).

## Idempotence note: `podman_secret` + `force: true`

Every role that creates a podman secret from a Vault-sourced value
(`postgres`, `redis`, `vault`, `mcphubd`, `observability`) passes
`force: true` so a rotated Vault value actually propagates. Verified in
`containers.podman.podman_secret`'s source
(`.ansible/collections/.../podman_secret.py`): on podman **>= 4.7.0** (this
environment: 5.8.3), `force: true` only triggers a recreate if
`need_update()` detects the data/labels actually changed — so a second run
with an unchanged Vault value is a true no-op (`changed: false`), not an
unconditional recreate. On podman < 4.7.0 the same module recreates the
secret unconditionally every run regardless of content — pin podman to
>= 4.7.0 (the `common` role's package install does not currently enforce a
minimum version; add one if targeting an older distro).

## Known limitations (see individual role READMEs for detail)

- **Single-host colocation only.** `playbooks/site.yml` targets
  `mcp_gateway` for every role; the `mcp_data` inventory group in
  staging/prod is aspirational — cross-host Postgres/Redis/Vault wiring
  (real TCP + firewalling, since podman bridge networks are host-local) is
  not implemented in this pass.
- **Vault bootstrap** (shamir unseal keys) is the one secret that touches
  disk in plaintext, once, at first init — see `roles/vault/README.md`.
  Prod should switch to a cloud KMS seal (`vault_seal_type`) to remove this
  entirely.
- **`provision-dedicated-port.yml`'s admin API call** is written against an
  inferred route (`POST /api/v1/admin/servers/{name}/dedicated-port`) —
  confirm against components 1/2's actual router before relying on it.
- **Observability role** ships Loki + Grafana only (no MinIO/Alertmanager
  yet) — a deliberate scope cut from the Python-platform's full stack,
  flagged, not silent.
- Full end-to-end verification (`site.yml` against real systemd + real
  Vault/Postgres/Redis) has not been run on this dev machine — macOS has no
  systemd, so quadlet unit *activation* could not be exercised locally.
  Every task uses idempotent, state-diffing modules; `ansible-lint` and
  `ansible-playbook --syntax-check` both pass (see the handoff report for
  exact output). This should be the first thing verified on a real Linux
  target before trusting it in staging.
