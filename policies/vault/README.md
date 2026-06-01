# Vault Policies

## deny_platform_admin.hcl

This deny policy **supplements** (does not replace) the positive-capability policy for `platform_admin`. Vault evaluates the most-restrictive result when multiple policies are attached to a role — a `deny` in any attached policy wins over `create`/`read`/`update` in another.

### How to apply

```bash
# Write the deny policy to Vault
vault policy write deny-platform-admin policies/vault/deny_platform_admin.hcl

# Attach to the platform_admin AppRole (alongside its positive-capability policy)
vault write auth/approle/role/platform_admin \
  policies="platform-admin,deny-platform-admin"
```

### Why mount-precise (no wildcards)

A wildcard like `secret/*` with `capabilities = ["deny"]` would also block paths the application legitimately needs — e.g. `secret/data/health`, `secret/data/config`, and any other non-server/non-user paths under the `secret/` mount.

Mount-precise paths (`secret/data/servers/*`, `secret/data/users/*`, etc.) ensure:
1. Only the owner/user secret namespaces are denied for `platform_admin`.
2. Health endpoints, config paths, and other application paths remain accessible under the positive-capability policy.
3. Policy intent is explicit and reviewable without ambiguity.

### Security invariant enforced

**Invariant #3** (from spec `docs/superpowers/specs/2026-05-31-mcp-blind-custody-rbac-design-v3.md`):
> `platform_admin` can manage infrastructure and platform configuration but CANNOT read, write, or delete owner secrets, user tokens, or KEK lifecycle operations (export, rotate, datakey, rewrap).

This policy combined with the ZK-at-rest guarantee (`SessionSUKCustodian`) means even a compromised `platform_admin` credential + full Vault KV read access cannot decrypt wrapped secrets without a live session IKM.
