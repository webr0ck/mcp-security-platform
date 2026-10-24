# postgres

Deploys `mcp-postgres` as a podman quadlet (`.container` + `.volume` units
under `/etc/containers/systemd`). Password is read from Vault via AppRole
(`vault_role_id`/`vault_secret_id`, sourced from `VAULT_ROLE_ID`/
`VAULT_SECRET_ID` env vars — never committed) and injected as a **podman
secret** (`Secret=...,type=env`), never as a plaintext `Environment=` line
in the unit file and never written to disk on the host.

No published port: postgres is reachable only from `mcphub_data_network`
(internal, no route to the outside). `mcphubd` is the only other member.

## Idempotence

`podman_secret` uses `force: true` so a rotated Vault value is detected and
replaces the podman secret; the quadlet templates are declarative
(`ansible.builtin.template`) so a second run with an unchanged Vault value
and unchanged image digest reports `changed=0` on every task except the
Vault lookup itself (which is not idempotence-tracked — it's a read).

## Known limitation

The postgres image's own entrypoint handles first-boot `initdb`; this role
does not manage schema migrations (`infra/db/migrations/*.sql` — that's the
DB engineer's surface, applied by `mcphubd` at startup via sqlx, per
`rs/ARCHITECTURE.md`).
