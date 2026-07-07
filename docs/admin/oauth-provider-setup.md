# OAuth provider profile setup

**Audience:** `admin`/`platform_admin` operators curating which external OAuth providers a
self-service submitter may pick from.

> Commands below assume you're either going through the real gateway/mTLS path, or (for a lab
> walkthrough) running inside the `mcp-proxy` container — see
> [../user/self-service-onboarding.md's Prerequisites](../user/self-service-onboarding.md#prerequisites).

There are two related-but-distinct concepts — don't conflate them:

- **`oauth_provider_policy`** (per issuer+tenant) — the low-level enforcement row: allowed/blocked
  scopes, redirect patterns, client-auth methods. Every `entra_*`/`external_oauth_*` submission is
  validated against a matching row at approval time (see
  [reviewer-approval-guide.md](reviewer-approval-guide.md)). This is the thing that actually gates
  approval — it must exist for approval to succeed.
- **`oauth_provider_profile`** (this doc) — a curated *catalog* sitting above that, so a
  non-expert submitter can pick "Generic OAuth 2.0" or "Same platform IdP" from a list instead of
  hand-typing raw endpoints. Creating/approving a profile does not itself enforce anything at
  submission time — `oauth_provider_policy` still does that. Think of a profile as "the pre-filled
  form", not "the security boundary".

## Creating a profile with RFC 8414 discovery

Most OAuth providers publish a metadata document. Give the issuer or an explicit metadata URL and
let the platform pre-fill everything else:

```bash
curl -sf -X POST http://localhost:8000/api/v1/admin/oauth-provider-profiles \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{
    "slug": "acme-oauth",
    "display_name": "Acme Corp OAuth",
    "provider_type": "generic_oauth2",
    "issuer_or_metadata_url": "https://auth.acme.example.com",
    "default_scopes": ["openid", "profile"]
  }'
```

**Expected output:**
```json
{"profile": {"id": "<uuid>", "status": "draft", "issuer": "...", "authorization_endpoint": "...",
             "token_endpoint": "...", ...}, "discovery_applied": true}
```

`discovery_applied: false` means no `.well-known/oauth-authorization-server` or
`.well-known/openid-configuration` document was reachable — **this is not an error**, it's the
documented fallback. Create the profile again (or `PATCH` — not yet exposed, recreate for now)
supplying `authorization_endpoint`/`token_endpoint` manually; a profile with missing required
fields simply cannot be approved (see below), it isn't silently accepted as complete.

Preview discovery without creating anything:

```bash
curl -sf -X POST http://localhost:8000/api/v1/admin/oauth-provider-profiles/discover \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"issuer_or_metadata_url": "https://auth.acme.example.com"}'
```

## The "Same platform IdP" profile type

`provider_type: "same_platform_idp"` needs none of the external-endpoint fields — it maps to
`kc_token_exchange` under the hood (see
[../user/auth-mode-decision-guide.md](../user/auth-mode-decision-guide.md)). You generally don't
need to create one of these per-server; the wizard's recommendation endpoint
(`POST /api/v1/wizard/recommend-provider-type`) surfaces this option directly without a profile
row.

## Approving a profile

A profile is unusable (`status: "draft"`) until reviewed:

```bash
curl -sf -X POST http://localhost:8000/api/v1/admin/oauth-provider-profiles/$PROFILE_ID/approve \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -d '{}'
```

**Fails closed** in the same two ways `oauth_provider_policy` approval does:

- **Missing required fields** (e.g. `generic_oauth2` with no `token_endpoint` — discovery never
  ran or failed and nobody filled it in) → the profile stays unapprovable, not silently passed.
- **Unknown issuer** — the profile's issuer must already have a matching `oauth_provider_policy`
  row (create one first if it doesn't — see [reviewer-approval-guide.md](reviewer-approval-guide.md)
  for what that row needs). `422` otherwise.
- **High-risk scope** (`write`/`admin`/`mail`/`files`/`offline_access`, checked across BOTH
  `default_scopes` and `allowed_scopes`) requires explicit acknowledgement:

```bash
curl -sf -X POST http://localhost:8000/api/v1/admin/oauth-provider-profiles/$PROFILE_ID/approve \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"high_risk_scopes_approved": true}'
```

Rejecting instead: `POST .../oauth-provider-profiles/$PROFILE_ID/reject` with `{"reason": "..."}`.

## Listing profiles

```bash
curl -sf "http://localhost:8000/api/v1/admin/oauth-provider-profiles?status=pending_review" \
  -H "Authorization: Bearer $TOKEN"
```

## Service adapters (advanced — most providers don't need this)

`service_adapter` (a field on the profile) names a `ServiceAdapter` implementation
(`credential_broker/adapters/service_adapter.py`) for services that need more than a fixed API
base URL — resource/tenant discovery after enrollment, a specific safe verification endpoint, etc.
Leave it `null` unless you know you need one; the reference `GenericServiceAdapter` (the "no extra
discovery needed" case) covers the vast majority of external OAuth services. See
[../reference/injection-modes.md](../reference/injection-modes.md) for the technical contract if
you're adding a new adapter.
