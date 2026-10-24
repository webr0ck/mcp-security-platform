# vault

Self-hosted Vault instance backing the whole platform. This is the only
place secret material touches disk in plaintext, and only once: the shamir
unseal keys + root token at first init, written to
`{{ vault_init_state_path }}` (`/var/lib/mcphub/vault-init/init.json`,
`0600`, root-only). The task that writes it prints an explicit operator
warning to move it to a break-glass store and delete it from the host.

**Prod should not use shamir.** Set `vault_seal_type` to `azurekeyvault` /
`awskms` / `gcpckms` (see `vault.hcl.j2`) — with a cloud KMS seal there is no
key-ceremony file at all; Vault auto-unseals using the cloud key on every
restart. `inventories/prod/group_vars/all.yml` does not currently override
this — set it as a host_vars override per prod host once the cloud seal is
provisioned; the default keeps prod bootable in a lab/demo without cloud
credentials, which is a deliberate divergence documented here rather than
silently defaulting prod to shamir.

Everything downstream (`postgres`, `redis`, `mcphubd`, IDP client secrets,
the credential-broker KEK — see
[[kek-persistence-decision]] in agent memory) reads its secret material FROM
this Vault via AppRole (`vault_role_id`/`vault_secret_id`, sourced from
`VAULT_ROLE_ID`/`VAULT_SECRET_ID` env vars, never committed). This role does
not create those AppRoles/policies — that is a one-time `vault` CLI
bootstrap documented in `docs/deploy.md`, deliberately kept out of Ansible's
blast radius (AppRole role/secret-ID creation is a security-sensitive,
rarely-changed operation better done by hand with a human watching, not
silently reconciled on every playbook run).

## Idempotence

- TLS cert/key: `community.crypto` modules only regenerate if absent.
- Init: guarded by `GET /v1/sys/init` — the init PUT only fires once.
- Unseal: submitting unseal keys to an already-unsealed Vault is a no-op on
  Vault's side; the task is marked `changed_when: false` since "sealed" is
  runtime state, not managed configuration.
