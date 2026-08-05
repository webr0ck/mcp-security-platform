# authorization-entitlement - build guide (non-normative)

`spec.md` states what must be true. This covers where entitlement state lives, how to source
roles from the identity providers in `identity-authentication/guide.md`, and the one bug this
capability keeps producing.

---

## 0. The bug that keeps coming back

**An empty result set that means "unrestricted".**

It arrives honestly. A profile feature ships; existing deployments have no profiles; making an
absent profile mean "no restriction" is the migration that does not break anyone. Then someone
creates a profile and forgets to add bindings, and that profile - now empty for a different
reason - grants everything.

`ENT-003` closes it by removing the distinction: unresolved, empty, and partially populated all
resolve as allowlists. Empty means empty in every case.

Two consequences worth accepting up front:

- **A misconfigured profile denies rather than over-grants.** That is the correct direction and
  it will generate support tickets. Make the denial reason code specific enough that the ticket
  answers itself.
- **If your implementation already has the permissive default, this is a breaking change**, and
  `ENT-003`'s last scenario says to remove the old path rather than keep both. Keeping both is
  how a caller reaches the permissive semantics by omitting a field - the old path is not
  dormant, it is reachable.

Write the test as: for each of the three empty-ish states, assert the resolved set is empty and
assert it is not the catalog. Assert both, because a resolver returning the catalog and a
resolver returning nothing look identical when the catalog happens to be empty in your fixture.

---

## 1. Where roles come from

Roles belong in the platform, sourced from the identity provider. Do not make the IdP the
authorization store.

**Keycloak.** Realm roles or client roles map cleanly. Add a mapper so roles land in the access
token, then map token roles to platform roles through an explicit table you own. The reason for
the table rather than direct use: `ENT-007` needs role changes appended as attributable history,
and a role that only exists in the token has no history you can read at incident time.

**Entra ID.** App roles on the gateway registration are the closest fit and arrive in the
`roles` claim. Group membership also works but has a trap: for users in many groups, Entra
emits a `_claim_names` / `_claim_sources` overage indicator instead of the group list, and the
application must call the directory to get the real membership. Code that reads the `groups`
claim without handling overage silently sees *no groups* for exactly the users most likely to
be administrators. If you use groups, handle overage explicitly and fail closed when the
directory call fails, per `ENT-001`.

Either way, the token tells you what roles the principal has. It does not tell you what
entitlements they have - those are per-server grants in your store, keyed on the principal
identifier from `IDN-009`.

---

## 2. The store

One resolver, called by both listing and authorization (`ENT-002`). If you write a second
query for the catalog view because the first one is shaped wrong for listing, you have created
the divergence this requirement exists to prevent - the two will drift and the listing will
become the more generous one.

Practical shape:

- `principal_id` is the identifier from `IDN-009`, not an email and not a username.
- Grants are rows, not a column of flags. `ENT-006` needs both directions enumerable - what
  can this principal reach, and who can reach this server - and a flags column answers only one.
- Role assignment and grant history are append-only (`ENT-007`), which is the same property
  `audit-observability` requires of the audit table and can use the same mechanism.
- Revocation is a new row, not a delete. `ENT-007`'s second scenario requires the prior grant
  to stay readable.

Resolution order per operation: role level first, then server-and-operation entitlement, then
profile. All three are allowlists; the result is the intersection, and any of the three failing
to resolve is a deny (`ENT-001`, third scenario).

---

## 3. Caching without breaking `ENT-008`

Entitlement is in the request path, so it will be cached. The rule that keeps it correct:
narrowing changes are event-invalidated, widening changes may wait.

- Revoke, remove from profile, retire principal, decommission server: publish an invalidation
  and treat a failure to invalidate as fail-closed (`ENT-008`, second scenario).
- Grant, add to profile: a bounded delay is acceptable, but the bound must be written down.
  `ENT-008`'s third scenario asks for the asymmetry to be deliberate rather than whatever the
  cache lifetime happens to be.

If your cache cannot be invalidated by event, its lifetime *is* your revocation bound, and you
must state it as such in the same place `IDN-012` states the session revocation bound. An
operator responding to an incident needs one number, not three you have to discover.

---

## 4. Separation of duties (`ENT-005`)

Enforce at the point of use, not only at assignment. Refusing to assign both roles is good
hygiene; refusing the self-approval when it happens is the control. A deployment will
eventually have a principal with both roles - during a migration, in a small team, or because
someone granted them temporarily - and the assignment-time check will not be there.

The machine-principal case (`ENT-005`, second scenario) is the one that actually gets exploited:
a submitter who cannot approve their own server creates a service account and approves with
that. `IDN-013` requires API keys to record their owning human precisely so this resolves back
to the same person. Wire it - the requirement is inert if the approval check does not consult
the owner field.

---

## 5. Checklist

- [ ] One resolver serves both listing and authorization - `ENT-002`
- [ ] Listings filtered server-side; no client-honoured flags - `ENT-002`
- [ ] Non-tool listings (resources, prompts) use the same resolver - `ENT-002`
- [ ] Unresolved, empty and partial profiles all resolve as allowlists - `ENT-003`
- [ ] Test asserts empty result is empty **and** is not the catalog - `ENT-003`
- [ ] Any legacy permissive resolution path removed, not retained - `ENT-003`
- [ ] Profile store failure denies with its own reason code - `ENT-003`
- [ ] Roles mapped from IdP claims through a table the platform owns - `ENT-007`
- [ ] Entra group-claim overage handled; failure to resolve denies - `ENT-001`
- [ ] Grants are rows, enumerable in both directions - `ENT-006`
- [ ] Revocation appends; nothing deletes - `ENT-007`
- [ ] Self-grants explicit and alertable - `ENT-007`
- [ ] Initiate capability is a separate grant from invocation - `ENT-004`
- [ ] Self-approval refused at the point of use, not only at assignment - `ENT-005`
- [ ] Machine principals resolved to their owning human for two-party checks - `ENT-005`
- [ ] Last-administrator removal refused - `ENT-005`
- [ ] Narrowing changes event-invalidated and fail closed - `ENT-008`
- [ ] Widening delay bound stated, not incidental - `ENT-008`
- [ ] Grants revoked when a server is decommissioned or a principal retired - `ENT-006`
