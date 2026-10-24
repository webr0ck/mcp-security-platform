# idp.yml schema

**Ground truth**: `rs/crates/mcphub-identity/src/config.rs` (`struct IdpConfig`)
and `rs/crates/mcphub-identity/src/claims.rs` (`struct RoleMapping`,
`enum ClaimExtract`, `enum RoleName`) — read directly from source, not
inferred from `rs/ARCHITECTURE.md`'s prose (which only documents the
`auth_mode` concept, not the full struct). Verified compiling +
`cargo test -p mcphub-identity` (45 tests) as of this revision.

Every field below is serialized with **no `rename_all`** on `IdpConfig`,
`AuthModeHint`, or `RoleName` — so enum variants serialize as their literal
Rust identifier (`SharedPassthrough`, not `shared_passthrough`). `RoleMapping`'s
`ClaimExtract` DOES carry `#[serde(tag = "kind", rename_all = "snake_case")]`
— so its tag values are snake_case, but the fields inside each variant
(`claim`, `path`, `client_id`) keep their literal names; `rename_all` only
renames the tag/variant name, not a variant's own fields.

```yaml
idps:
  - issuer: <string>                  # exact `iss` claim match, no normalization
    discovery_url: <string|null>      # only if discovery lives at a different
                                       # path than `issuer` (Entra: issuer is the
                                       # v1 tenant URL tokens assert, discovery is
                                       # published at a v2.0 path — see below)
    issuer_aliases: [<string>, ...]   # additional `iss` values accepted for this
                                       # same config (Entra v1/v2 dual-issuer)
    audiences: [<string>, ...]        # token `aud` must intersect this set —
                                       # THIS IS WHAT STOPS A TOKEN MINTED FOR A
                                       # DIFFERENT RELYING PARTY FROM BEING ACCEPTED.
                                       # Never leave empty.
    allowed_algs: [<string>, ...]     # e.g. ["RS256"] — enforced against the JWT
                                       # header itself (alg-confusion defence).
                                       # Never include "none" or an HMAC alg
                                       # unless you specifically use HMAC.
    clock_skew_seconds: <int>         # exp/nbf leeway, e.g. 60
    auth_mode: SharedPassthrough | SharedExchange | DedicatedPort   # PascalCase, no quotes-safe alternative
    dedicated_port: <int|null>        # ONLY meaningful when auth_mode is
                                       # DedicatedPort. This is a property of
                                       # the IDP CONFIG ITSELF, not of any one
                                       # backend server — every backend server
                                       # that uses this IDP shares this one
                                       # listener. Allocated from
                                       # dedicated_port_range_start/end by
                                       # playbooks/provision-dedicated-port.yml.
    supports_token_exchange: <bool>   # RFC 8693; enables SharedExchange
    client_id: <string|null>          # OAuth client for the PKCE browser flow
    redirect_uri_allowlist: [<string>, ...]   # exact-match allowed redirect_uris
                                               # for the PKCE flow — THIS IS WHAT
                                               # STOPS AN OPEN REDIRECT. Never leave
                                               # empty if client_id is set.
    role_mapping:
      rules:
        - extract:
            kind: top_level_array | nested_array | resource_access | zitadel_project_roles
            # top_level_array:        {kind: top_level_array, claim: <string>}
            # nested_array:           {kind: nested_array, path: [<string>, ...]}
            # resource_access:        {kind: resource_access, client_id: <string>}
            # zitadel_project_roles:  {kind: zitadel_project_roles, claim: <string>}
          role_values:
            <raw-claim-value>: SuperAdmin | ServerOwner | SecurityAnalyst | Employee
            # Unmapped raw values are DROPPED, never defaulted to a role —
            # least privilege on ambiguity. An operator who forgets to map a
            # role string gets a user with NO roles, not a user with every
            # role's default deny-safe... but also not the intended access.
            # This is the field most IDP onboardings get wrong; see the
            # worked per-vendor defaults below (mcphub-identity's
            # RoleMapping::default_for(ProviderHint)).
```

`client_secret` is deliberately **NOT** a field of `IdpConfig` at all (checked
against the real struct — it isn't there). Confidential-client secrets are
sourced from Vault at `{{ vault_idp_secrets_path }}/<issuer-slug>` exactly as
documented in `deploy/ansible/roles/mcphubd/README.md` — this part of the
original design was correct and needs no change.

## Per-vendor `role_mapping` defaults (from `RoleMapping::default_for`)

All three ship the same `role_values` map by default (override per-issuer if
your IDP uses different app-role names):

```yaml
role_values:
  mcphub-super-admin: SuperAdmin
  mcphub-server-owner: ServerOwner
  mcphub-security-analyst: SecurityAnalyst
  mcphub-employee: Employee
```

- **Keycloak**: TWO rules — a top-level `roles` claim (if a custom protocol
  mapper adds one) AND Keycloak's default `realm_access.roles` nested claim.
  Both checked; results are deduplicated.
- **Entra**: ONE rule — top-level `roles` claim (Entra app roles land here
  directly when the app registration defines them and the user/group is
  assigned).
- **Zitadel**: ONE rule — the structured
  `urn:zitadel:iam:org:project:roles` claim, where the OBJECT'S KEYS are the
  granted role names (not the values).

## dedicated_port allocation (corrected)

Earlier revisions of this doc modeled `dedicated_port` as a **per-server**
allocation (a separate `{server_name, port}` registry + an admin
`/servers/{name}/dedicated-port` endpoint). That was wrong — the real
`IdpConfig.dedicated_port: Option<u16>` field lives on the **IDP entry**,
not a server row. One dedicated-port IDP = one listener, shared by every
backend server configured to use that IDP. `playbooks/provision-dedicated-port.yml`
now allocates a port and sets it on the named IDP's `dedicated_port` field
(install-time: directly in the idp.yml + re-apply; runtime: via the admin
API contract in `API_CONTRACT.md`, not yet implemented server-side).

## auth_mode selection guide (unchanged from before)

| your IDP situation | auth_mode | requires |
|---|---|---|
| backend trusts the platform IDP's token directly | `SharedPassthrough` | nothing extra |
| backend needs its own IDP, platform IDP supports RFC 8693 | `SharedExchange` | `supports_token_exchange: true` |
| backend needs its own IDP, no token exchange available | `DedicatedPort` | `dedicated_port` set (see above) |

## Worked examples in this directory

- `idp.keycloak.yml` — self-hosted Keycloak, token-exchange enabled, both
  Keycloak role-claim rules.
- `idp.zitadel.yml` — Zitadel, token-exchange enabled, structured
  project-roles claim.
- `idp.entra.yml` — Microsoft Entra ID, `DedicatedPort` (no RFC 8693 to
  arbitrary audiences), demonstrates `issuer_aliases` (v1/v2 dual-issuer)
  and `discovery_url` (published at a different path than the token issuer).

## API contract for the runtime path

See `API_CONTRACT.md` — **the JSON admin API these examples assume does not
exist yet** (only a CSRF-protected HTML form at `/admin/idps`). The
install-time path (`configure-idp.sh` + `playbooks/configure-idp.yml`) does
not depend on it and works today.
