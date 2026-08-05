# identity-authentication - build guide (non-normative)

This file is not a specification. `spec.md` states what must be true; this states how to make
it true on the identity providers most teams already have. Nothing here overrides `spec.md`,
and a provider-specific instruction that conflicts with a `SHALL` is a note that the provider
cannot satisfy that requirement, not a licence to relax it.

Every version-specific detail below should be checked against the version you are running.
Providers move; the requirement IDs do not.

---

## 0. The decision that shapes everything else

Two RFCs decide how much of this platform you can build the clean way:

- **RFC 8707 resource indicators** - can the authorization server mint a token whose audience
  is one specific backend, because the client asked for that backend by URI? This is what
  `IDN-006` needs.
- **RFC 8693 token exchange** - can the platform trade a caller's token for a *different*
  token scoped to one backend, without the caller ever holding the second token? This is what
  `credential-broker` needs to avoid storing long-lived secrets.

Check both before you design. The honest summary as of writing:

| Provider | RFC 8707 `resource` | RFC 8693 exchange | RFC 7662 introspection | Practical consequence |
|---|---|---|---|---|
| Keycloak | Partial / version-dependent; audience is normally driven by client scopes and audience mappers, not by the request parameter | Yes, though the feature has moved between preview and supported across major versions - confirm on yours | Yes | Closest to the clean design. Expect to express per-backend audience as a client scope instead of a request parameter. |
| Microsoft Entra ID | No in the v2.0 endpoint; audience follows the scope's API identifier | Not as RFC 8693. On-Behalf-Of is the equivalent flow and is not wire-compatible | No standard access-token introspection | You get delegation, but through a Microsoft-shaped flow, and you cannot introspect. Plan for JWT validation only. |
| Okta | Custom authorization servers give you per-audience control; the `resource` parameter is not the mechanism | Yes on custom authorization servers | Yes | Workable. The org authorization server is much more limited than a custom one - use a custom one. |
| Auth0 | Uses a non-standard `audience` request parameter that achieves the same effect | Token exchange exists but has been reshaped more than once | Yes | Achieves `IDN-006` in substance, not by the RFC's parameter name. Record that in the conformance record. |

**Do not read a "no" as a blocker.** Read it as: that backend moves onto the stored-credential
path in `credential-broker`, and you carry a gap entry per `IDN-016`. A platform where half
the backends use exchange and half use stored credentials is the normal outcome, not a
failure. What is *not* acceptable is a backend that accepts a token the platform did not
audience-restrict - that is `IDN-006` and `IDN-007` failing together, and it is how one
compromised backend replays a token at another.

---

## 1. Keycloak

### 1.1 Realm and client layout

Create one realm for the platform. Inside it:

| Client | Type | Purpose |
|---|---|---|
| `mcp-gateway` | confidential, service accounts on | The platform itself. Validates inbound tokens, performs exchange. |
| `mcp-agent-<name>` | public with PKCE, or confidential | One per agent product. Never share a client across agents - `IDN-009` needs the acting client to be distinguishable. |
| `mcp-admin-ui` | public with PKCE | Operator surfaces. |

Do not put backends in this realm as clients unless they genuinely federate. A backend that
receives a broker-minted credential is not an OAuth client of yours.

### 1.2 Turning off what the spec forbids

Per client, in **Settings → Capability config**:

- Standard flow: **on**
- Implicit flow: **off** (`IDN-016`, OAuth 2.1)
- Direct access grants: **off** - this is the password grant, and it is on by default on new
  clients. Leaving it on is the single most common way a Keycloak deployment silently fails
  OAuth 2.1 conformance.
- Service accounts: on only for `mcp-gateway` and genuine machine clients.

In **Advanced → Advanced settings**, set *Proof Key for Code Exchange Code Challenge Method*
to `S256`. Leaving it blank means Keycloak accepts `plain`, which `IDN-016` rejects. Setting
it per client is what makes the rejection real - there is no realm-wide switch you can rely
on instead.

### 1.3 Audience (`IDN-004`, `IDN-006`)

Keycloak's default access token audience is frequently just `account`, which names nothing
useful and will fail your audience check the moment you enable it. Fix it explicitly:

1. **Client scopes → Create client scope**, one per protected resource, e.g.
   `mcp:resource:gateway`, `mcp:resource:crm`. Type: *Optional* if the client should have to
   ask for it, *Default* if it always applies.
2. Inside the scope, **Mappers → Configure a new mapper → Audience**. Set *Included Client
   Audience* to the target client, or *Included Custom Audience* to the resource URI your
   platform validates against.
3. Assign the scope to the agent clients that may reach that resource.

The result: the client asks for a scope, and gets a token audienced to one resource. That is
`IDN-006` satisfied by mechanism even though the client never sent a `resource` parameter -
which is exactly the substitution `IDN-006`'s third scenario anticipates. Record it in the
conformance record; do not claim RFC 8707 compliance you do not have.

Because the scope, not the request parameter, carries the audience, `IDN-007` becomes an
assignment question: a principal that must not reach a backend must not have that backend's
client scope. Drive scope assignment from the same entitlement store the invocation path
reads, or the two will drift and the token will outrank the policy.

### 1.4 Token type (`IDN-004`)

Keycloak has historically issued access tokens with `typ: Bearer` rather than the RFC 9068
`at+jwt`. If you validate `typ` strictly - and you should, it is what stops an ID token being
presented as an access token - check what your version emits before you pin the value.
Newer versions expose an option to issue `at+jwt`; if yours does, turn it on. If it does not,
pin the value your realm actually emits and assert it in a test, so an upgrade that changes it
fails loudly instead of silently loosening the check.

### 1.5 Endpoints you will wire

With `ISS = https://<host>/realms/<realm>`:

| Purpose | Path |
|---|---|
| Discovery (`IDN-016`, RFC 8414) | `ISS/.well-known/openid-configuration` |
| JWKS (`IDN-004`, RFC 7517) | `ISS/protocol/openid-connect/certs` |
| Token | `ISS/protocol/openid-connect/token` |
| Introspection (RFC 7662) | `ISS/protocol/openid-connect/token/introspect` |
| Revocation (`IDN-012`, RFC 7009) | `ISS/protocol/openid-connect/revoke` |
| End session | `ISS/protocol/openid-connect/logout` |

Fetch discovery once at startup and cache it; fetch JWKS lazily and cache by `kid` with a
bounded refresh. `IDN-004` requires `503` rather than acceptance when JWKS is unreachable, so
your cache must be able to say "I do not have this `kid`" and stop, not fall back to the last
key it happened to hold for a different `kid`.

Realm name appears in every one of those URLs. `IDN-001` forbids the realm name from reaching
an agent. Do not proxy discovery through by copying fields; construct your own document.

### 1.6 Principal identity (`IDN-009`, `IDN-010`)

Keycloak's `sub` is a realm-scoped UUID, stable across username and email changes, and the
same value for every client in the realm. Use `iss + sub`.

Two things to guard:

- Deleting and recreating a user produces a **new** `sub`. Entitlements keyed on the old one
  become orphans, not errors. Decide whether a user delete is an operator-visible event in
  your platform, or you will discover the answer during an incident.
- Realm rename or realm migration changes `iss` for every principal at once. That is
  `IDN-010`'s first scenario and it needs a real remapping path, not a config edit.

### 1.7 Revocation within a bound (`IDN-012`)

Keycloak's session state is server-side, so revocation is achievable, but only if you use it:

- Set access token lifespan short - minutes, not hours. This is your worst-case bound if you
  do nothing else, and `IDN-012` requires you to state it as a duration.
- Configure **back-channel logout** on the agent clients, with the platform as the logout
  URL, and write the resulting session identifier into your revocation store. That turns
  "user disabled upstream" into a push rather than a poll.
- For containment (`IDN-012`, fourth scenario), realm-level session invalidation plus a
  platform-side revocation flag gives you the one-action kill. Do not rely on Keycloak alone:
  your own store must deny even if Keycloak is unreachable, because `IDN-012` says a store
  error denies, and an unreachable IdP during an incident is the expected case.

Map the session identifier from the token's `sid` claim where present, falling back to a
platform-issued identifier for callers with no OIDC session at all - which `IDN-011` requires
you to create for API-key and mTLS callers regardless.

### 1.8 Token exchange for the broker

Keycloak supports `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`, but its
availability and configuration have differed across major versions - it spent a long stretch
behind a preview feature flag, and newer releases split "standard" from "legacy" exchange with
different permission models. Confirm on your version before designing around it. When enabled,
the gateway client exchanges an inbound token for one audienced to a single backend, which is
what lets `credential-broker` avoid storing a secret for that backend at all.

---

## 2. Microsoft Entra ID

Entra will satisfy authentication and delegation well and will not satisfy several of the
protocol requirements. Knowing which is which up front saves a redesign.

### 2.1 App registrations

| Registration | Purpose |
|---|---|
| MCP Gateway API | Exposes an Application ID URI, e.g. `api://mcp-gateway`. Defines delegated scopes and app roles. |
| One per agent client | Requests the gateway's scopes. Public client with PKCE for interactive agents; confidential for daemons. |
| Backend APIs, if federated | Only where the backend genuinely accepts Entra tokens. |

On the gateway registration: **Expose an API** → set the Application ID URI → add scopes such
as `invoke`, and app roles for machine callers. The URI you set here is the `aud` your token
validation compares against - `IDN-004` needs that value configured, not inferred.

### 2.2 The `sub` trap (`IDN-009`)

**This is the one that breaks systems quietly.** Entra's `sub` claim is *pairwise* - the same
human presents a different `sub` to different applications. If you key principals on
`iss + sub` and later add a second app registration, or a second resource, the same person
resolves to a different principal and loses every entitlement and stored credential.

Use `tid + oid` instead:

- `oid` is the object identifier of the user in the directory, stable across applications and
  across username, UPN and email changes.
- `tid` is the tenant identifier, which you need for isolation in any multi-tenant deployment
  and which you must validate rather than accept.

This is exactly the case `IDN-009`'s second scenario is written for, and `IDN-009` requires
the chosen claim to be recorded in configuration - so make the claim name a setting, assert it
in a test, and do not let it be inferred per request.

For guest (B2B) users, `oid` is the object ID *in your tenant*, which is what you want. For
service principals, expect `oid` to identify the service principal object and `idtyp` or the
absence of user claims to distinguish it - use that to satisfy `IDN-009`'s machine-principal
typing rather than guessing from claim shape.

### 2.3 Audience and the missing resource indicator (`IDN-006`)

Entra's v2.0 endpoint does not implement RFC 8707. The v1.0 endpoint had a `resource`
parameter; v2.0 replaced it with scopes that carry the API identifier, e.g.
`api://mcp-gateway/invoke`. The audience follows from the scope requested.

Consequence: a token is audienced to *an API registration*, and every scope on that
registration shares the audience. If you want per-backend audience separation, you need
per-backend app registrations, which means per-backend token acquisition on the client side.
That is real work and it is the reason many Entra deployments end up with one broad
gateway-audienced token and all backend separation done inside the platform.

That is an acceptable outcome only because the platform never forwards the inbound token
(`IDN-008`) and mints a separate downstream credential per backend. If you were forwarding,
this design would be a single token that opens every door - which is the whole failure
`IDN-006` exists to prevent. Record the gap per `IDN-016` and be explicit that `IDN-008` is
carrying the weight here.

A further consequence for `IDN-004`: Entra tokens often carry `aud` as the client ID GUID
rather than the `api://` URI, depending on the registration's manifest and the token version.
Validate against whichever your tenant actually emits, verify it by decoding a real token
during setup, and pin it.

### 2.4 No introspection (`IDN-016`)

Entra does not offer an RFC 7662 introspection endpoint for access tokens. Do not build an
opaque-token path expecting one. Validate the JWT locally:

- Discovery: `https://login.microsoftonline.com/{tenant}/v2.0/.well-known/openid-configuration`
- Keys: from the `jwks_uri` in that document
- Validate `iss` exactly as the discovery document states it, including the tenant GUID.
  Multi-tenant issuers use a template with `{tenantid}` - substitute and compare, never
  accept the template form, and never accept an issuer you did not expect.
- Validate `tid` against your allowed tenants. An unvalidated `tid` in a multi-tenant app is
  a cross-tenant authentication bypass, not a hardening gap.

Record the introspection gap in the conformance record rather than omitting the row -
`IDN-016` requires the gap, not silence.

### 2.5 Delegation: On-Behalf-Of, not RFC 8693

Entra's OBO flow lets the gateway obtain a downstream token for the same user. It is not
wire-compatible with RFC 8693: the request uses
`grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer` with the inbound token as the
assertion and `requested_token_use=on_behalf_of`, and the downstream API must be a registered
application with the gateway granted permission to it.

Where it works, it satisfies the property `credential-broker` wants - a downstream credential
the agent never holds. Where the backend is not an Entra application, it does not apply at
all, and that backend goes on the stored-credential path. Expect a mixed estate.

### 2.6 Revocation (`IDN-012`)

Entra access tokens are not revocable by default within their lifetime, which directly
conflicts with `IDN-012`'s "within a declared bound". Options, in order of strength:

1. **Continuous Access Evaluation**, where the resource participates in near-real-time
   revocation signalling for events such as account disable and password reset. This is the
   mechanism that makes the bound short. It requires work on the resource side and does not
   cover every event.
2. **Short token lifetime** via a token lifetime policy. Blunt but honest, and it makes the
   bound explicit and statable.
3. **Platform-side revocation store** checked on every request. This is what `IDN-012`
   actually mandates and it is not optional regardless of what Entra offers - it is the only
   layer that stays under your control during an incident, and the only one that can deny when
   the IdP is unreachable.

Build 3 first. Treat 1 and 2 as ways to shorten the window before 3 hears about the event.

### 2.7 Conditional Access is not a substitute for `IDN-003`

Conditional Access evaluates at token issuance, not at invocation. It cannot see which tool a
principal is calling or what taint the session carries. It is a useful outer ring; it is not
the chokepoint, and a design that leans on it will have a gap between issuance and invocation
that nothing inspects.

---

## 3. Okta and Auth0, briefly

**Okta.** Use a *custom* authorization server, not the org one - the org server cannot express
per-audience scopes or run access policies, which you need for `IDN-006` and `IDN-007`. Set
the audience on the custom authorization server; each server has one audience, so
per-backend separation means per-server. Token exchange is supported on custom servers.
Introspection is available. `sub` is stable and not pairwise.

**Auth0.** The `audience` request parameter achieves what RFC 8707's `resource` does under a
different name - `IDN-006` is satisfied in substance, and the conformance record should say
"satisfied by a non-standard parameter" rather than claiming the RFC. Define one API resource
server per backend audience. Introspection is available. Note that `sub` encodes the
connection and provider (`auth0|...`, `google-oauth2|...`), so a user who moves between
connections gets a new `sub` - that is `IDN-010`'s first scenario, and account linking is the
mechanism that answers it.

---

## 4. What none of them give you

These are yours to build regardless of provider, and the reason `spec.md` states them as
requirements rather than as configuration:

- **`IDN-011` session as a first-class record.** No IdP gives a session to an API-key or mTLS
  caller. You create one, or taint and revocation have no subject.
- **`IDN-012` fail-closed revocation check on every request.** Every provider's revocation is
  best-effort from your side. Your own store is the enforceable one.
- **`IDN-014` uniform caller-facing responses.** Providers give distinct, helpful errors. That
  is right for a login page and wrong for an invocation API - you must flatten them.
- **`IDN-015` ingress bounds.** IdP throttling protects the IdP, not your audit path or your
  policy engine.
- **`IDN-002` attested tier.** No provider knows whether you meant to be in production.
- **`IDN-005` clock discipline.** Every expiry check above assumes a clock nobody verified.

---

## 5. Setup checklist

Work through in order; each line names the requirement it discharges.

- [ ] Implicit and password grants disabled on every client - `IDN-016`
- [ ] PKCE `S256` enforced per client, `plain` rejected - `IDN-016`
- [ ] Expected audience configured explicitly; startup fails closed without it - `IDN-004`
- [ ] Real token decoded during setup and its `aud`, `iss` and `typ` values pinned - `IDN-004`
- [ ] Signing algorithm set pinned; `none` and unlisted algorithms rejected - `IDN-004`
- [ ] JWKS cache returns "unknown `kid`" rather than a stale key; unreachable JWKS gives `503` - `IDN-004`
- [ ] Principal claim chosen and recorded in configuration, not inferred - `IDN-009`
- [ ] Pairwise-`sub` providers keyed on a cross-application stable claim - `IDN-009`
- [ ] Tenant identifier validated against an allowlist where multi-tenant - `IDN-004`
- [ ] Issuer-change remapping path exists and is audited - `IDN-010`
- [ ] Server-side session record created for every caller including API-key and mTLS - `IDN-011`
- [ ] Revocation store consulted on every request; store error denies - `IDN-012`
- [ ] Revocation bound stated as a duration in the platform's own documentation - `IDN-012`
- [ ] Back-channel logout or equivalent wired into the revocation store - `IDN-012`
- [ ] One-action global containment tested, not just implemented - `IDN-012`
- [ ] Client-certificate header accepted only from an authenticated sender; stripped elsewhere - `IDN-003`
- [ ] Caller-facing denial responses verified indistinguishable across reason codes - `IDN-014`
- [ ] Rate and concurrency bounds on authenticated and unauthenticated ingress - `IDN-015`
- [ ] Clock synchronisation alertable; skew tolerance declared and bounded - `IDN-005`
- [ ] Deployment tier read from an attested source; production assumed on failure - `IDN-002`
- [ ] Conformance record written, including every gap - `IDN-016`
- [ ] MCP specification revision pinned as a version identifier - `IDN-016`
