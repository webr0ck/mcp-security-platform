# Auth mode decision guide

**Audience:** anyone submitting an MCP server who needs to answer "how does the platform
authenticate to my upstream service?" without knowing the platform's internal terminology.

You do not need to know what "kc_token_exchange" or "injection_mode" mean to answer this. Answer
the questions below in order; the first one that applies to you is your answer. Once you've
picked, use the exact mode value shown when filling in the submission wizard / API
(`injection_mode` field) — the wizard also exposes this via
`POST /api/v1/wizard/recommend-provider-type` if you'd rather call it directly.

## Question 1 — Does your backend service need no authentication at all from the platform?

→ Use **`none`** ("No credential injection"). Nothing is sent to your upstream beyond the request
itself.

## Question 2 — Is your backend service protected by THIS platform's own sign-in system?

If your MCP server's users already sign in through this platform (the same Keycloak realm), and
your server just needs to know *who* is calling without a separate enrollment step:

→ Use **"Same platform IdP"** (mode value: `kc_token_exchange`). You only need to tell the reviewer
one thing: **what audience your server expects** (a short identifier you choose, e.g.
`my-service`). The platform then exchanges the caller's own sign-in token for a short-lived token
scoped to that audience on every call. Your server's own responsibility (documented so you can
implement it, whichever language you use):

- Validate the token's issuer matches the platform's Keycloak realm issuer.
- Validate the token's audience matches the audience you registered.
- Validate the token has not expired.
- Validate the token's signature against the platform's JWKS.
- Use the token's `sub` claim as the calling user's identity for any per-user authorization your
  server does — never trust any other header for identity.

See [../reference/injection-modes.md#kc_token_exchange](../reference/injection-modes.md) for the
technical detail, and `services/same_idp_verify.py` (platform-side) for the automated check a
reviewer can run against your deployed server to confirm it actually rejects bad tokens.

## Question 3 — Does your service use its own separate OAuth 2.0 sign-in (not this platform's)?

If your backend requires users to authenticate with a *different* identity provider (a SaaS
product's own OAuth, an internal company IdP, Microsoft Entra, etc.):

**3a. Does it support OAuth 2.0 authorization-code flow (a user clicks "sign in" and approves
access)?**

- **Yes, and each user has their own account** → **"External OAuth, per-user"**
  (mode value: `external_oauth_user_token`). You'll need to give a reviewer: the issuer or a
  metadata URL (if the provider publishes RFC 8414 / OIDC discovery, most endpoints can be
  pre-filled automatically — see
  [../admin/oauth-provider-setup.md](../admin/oauth-provider-setup.md)), a client_id/client_secret
  registered with that provider, and the scopes you need.
- **No — it's app-only / service-to-service (client_credentials)** →
  **"External OAuth, app-only"** (mode value: `external_oauth_client_credentials`). Same setup as
  above, minus the per-user enrollment step.

**Is it Microsoft Entra specifically?** Use `entra_user_token` (per-user) or
`entra_client_credentials` (app-only) instead of the generic external-OAuth modes — Entra has a
dedicated, better-supported path.

## Question 4 — Does your service just need a static API key, bearer token, or HTTP Basic auth?

- One shared secret used for every caller → **"Shared service credential"** (mode value:
  `service`).
- A username+password pair (RFC 7617) → **"Basic auth"** (mode value: `basic_auth`).
- A Keycloak service-account client_credentials token → **"Keycloak service account"** (mode
  value: `service_account`).

## Question 5 — None of the above; your server manages its own per-user sessions

→ Use **"Per-user identity (no credential injection)"** (mode value: `user`). The platform
forwards the caller's identity (`X-User-Sub`) but injects no credential — your server is
responsible for its own auth.

## Full reference

For the complete generated table of every mode (including admin-only / deprecated / roadmap ones
you generally should not pick), see [../reference/auth-modes.md](../reference/auth-modes.md).
