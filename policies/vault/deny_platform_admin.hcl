# Vault policy: deny_platform_admin
# Generated from canonical mount inventory — DO NOT use wildcards or merge paths.
# Enforces security invariant #3: platform_admin cannot read/modify owner/user secrets
# or lifecycle KEKs. Mount-precise per spec §Security Invariants.
#
# Apply: vault policy write deny-platform-admin policies/vault/deny_platform_admin.hcl
# Then attach to the platform_admin role: vault write auth/.../role/platform_admin policies="platform-admin,deny-platform-admin"

# --- Owner / server secret paths ---
path "secret/data/servers/*" {
  capabilities = ["deny"]
}

path "secret/metadata/servers/*" {
  capabilities = ["deny"]
}

path "secret/delete/servers/*" {
  capabilities = ["deny"]
}

path "secret/undelete/servers/*" {
  capabilities = ["deny"]
}

path "secret/destroy/servers/*" {
  capabilities = ["deny"]
}

# --- User personal token paths ---
path "secret/data/users/*" {
  capabilities = ["deny"]
}

path "secret/metadata/users/*" {
  capabilities = ["deny"]
}

path "secret/delete/users/*" {
  capabilities = ["deny"]
}

path "secret/undelete/users/*" {
  capabilities = ["deny"]
}

path "secret/destroy/users/*" {
  capabilities = ["deny"]
}

# --- Transit KEK lifecycle operations (no export, no rotation, no datakey) ---
path "transit/export/*" {
  capabilities = ["deny"]
}

path "transit/datakey/*" {
  capabilities = ["deny"]
}

path "transit/rewrap/*" {
  capabilities = ["deny"]
}

path "transit/rotate/*" {
  capabilities = ["deny"]
}
