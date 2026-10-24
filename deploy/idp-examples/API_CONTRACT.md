# Admin API contract — IDP config + dedicated_port (proposed, NOT implemented)

**Status: this API does not exist.** Confirmed against
`rs/crates/mcphub-ui/src/router.rs` — the only `/admin/idps` route is a
CSRF-protected HTML form (`GET`/`POST /admin/idps`, `GET /admin/idps/new`),
not a JSON API, and there is no `/admin/servers/.../dedicated-port` route or
equivalent at all. `deploy/scripts/configure_idp_runtime.py` and
`playbooks/provision-dedicated-port.yml`'s runtime path are written against
this contract as a **request for what needs to be built**, not a working
integration. Do not point either at a live environment expecting it to
work. The install-time path (`configure-idp.sh` + `configure-idp.yml`)
does not depend on this and works today.

## Why a separate JSON endpoint, not the existing form

`POST /admin/idps` expects a synchronizer CSRF token bound to a browser
session cookie — that's correct behavior for a form a human fills in, and
must not be weakened for scripting convenience (that would be a real CSRF
hole). A deploy script or CI job has no browser session. It needs a
separate, token-authenticated JSON route, same pattern as any other
machine-to-machine admin action.

## 1. `POST /api/v1/admin/idps` — create or update an IDP config

**Auth**: `Authorization: Bearer <service-credential>` — a super-admin
capability minted for automation (NOT a user's session-derived bearer
token; a distinct service-credential type, analogous to how
`vault_role_id`/`vault_secret_id` are a machine credential distinct from a
human Vault login). Exact minting mechanism is for component 1/2 to define;
this contract only requires that *some* long-lived, revocable,
super-admin-scoped bearer credential exists for automation.

**Request body** — the real `IdpConfig`
(`rs/crates/mcphub-identity/src/config.rs`), verbatim, PLUS one
deploy-only identifier field not on the Rust struct:

```json
{
  "vault_secret_name": "mcp-keycloak",
  "issuer": "https://keycloak.internal/realms/mcp",
  "discovery_url": null,
  "issuer_aliases": [],
  "audiences": ["mcphub-proxy"],
  "allowed_algs": ["RS256"],
  "clock_skew_seconds": 60,
  "auth_mode": "SharedExchange",
  "dedicated_port": null,
  "supports_token_exchange": true,
  "client_id": "mcp-proxy",
  "redirect_uri_allowlist": ["https://gateway.internal:8443/oauth/callback"],
  "role_mapping": { "rules": [ { "extract": {"kind": "nested_array", "path": ["realm_access","roles"]}, "role_values": {"mcphub-super-admin": "SuperAdmin"} } ] }
}
```

`vault_secret_name` is how the SERVER identifies which Vault path to read
`client_secret` from — **the request body never contains the secret
itself**. This mirrors the install-time path exactly: `configure-idp.sh`
already writes `client_secret` to
`secret/mcphub/<env>/idp/<vault_secret_name>` and this endpoint would read
from the same place. `IdpConfig` genuinely has no `client_secret` field —
confirmed against source — so this isn't a workaround, it's the correct
shape.

Server behavior on success: persist to Postgres (per ARCHITECTURE.md,
runtime config wins over file config for the same `issuer`), reload the
in-memory IDP registry, respond `201 Created` (new) or `200 OK` (updated
existing issuer) with the stored `IdpConfig` echoed back (minus any secret
material, since there is none in the struct to echo).

**Errors**: `400` malformed body / an `auth_mode: SharedExchange` entry with
`supports_token_exchange: false` / empty `audiences` or
`redirect_uri_allowlist` when `client_id` is set (these are the
security-critical fields flagged in SCHEMA.md — the API should refuse to
accept a config missing them, not just document that operators should fill
them in). `401`/`403` missing or non-super-admin credential. `409` issuer
collision if the API is upsert-by-`vault_secret_name` rather than
upsert-by-`issuer` (pick one — this contract assumes upsert-by-`issuer`
since that's the struct's natural key per `matches_issuer`).

## 2. `PATCH /api/v1/admin/idps/{issuer}/dedicated-port` — allocate/set dedicated_port

Only valid when the target IDP's `auth_mode` is `DedicatedPort`.

**Request**: `{"port": 9001}` (caller-allocated — the ansible playbook
computes the free port from `dedicated_port_range_start/end` and passes it
here; the server does not do its own allocation, to keep one source of
truth for the range).

**Response**: `200 OK` with the updated `IdpConfig`.

**Errors**: `400` if `auth_mode != DedicatedPort`, `409` if the port is
already assigned to a different issuer (the server should reject a
collision, not silently overwrite).

`{issuer}` is URL-encoded — NOT `vault_secret_name` — since `issuer` is the
struct's actual identity field.

## What changed from the previous (wrong) version of this file

The original draft assumed a per-SERVER `POST /api/v1/admin/servers/{name}/dedicated-port`
endpoint. That doesn't match the real code: `dedicated_port` lives on
`IdpConfig`, there is no server-scoped struct with a port field anywhere I
could find, and no `/admin/servers/...` route exists at all (only
`GET /admin/servers`, an HTML list page). Corrected to the per-IDP `PATCH`
above.
