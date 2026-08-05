# authorization-entitlement Specification

## Purpose
Decides what a resolved principal is allowed to see and call. Covers the two-layer role model,
per-server entitlement, named profiles and their resolution rules, and the rule that discovery
and invocation are answered by one resolver so a principal can never invoke what it cannot see.

Depends on `identity-authentication` for the principal. Runs before `policy-enforcement`.
Requirements here are identified `ENT-nnn`. Concrete directory and store configuration is in
`guide.md`, which is non-normative.

## Requirements

### Requirement: ENT-001 Deny-by-default authorization at two levels
Authorization SHALL be evaluated at two independent levels: whether the principal may perform
mediated operations at all, and whether the principal is entitled to the specific server and
operation. Both SHALL default to deny.

#### Scenario: Principal with no role
- **WHEN** a principal with no assigned role performs any mediated operation
- **THEN** the platform SHALL deny

#### Scenario: Principal with a role but no entitlement
- **WHEN** an authenticated principal holds a valid role but has no grant to the target server
- **THEN** the platform SHALL deny
- **AND** the audit event SHALL distinguish "not entitled" from "not authenticated"
- **AND** the caller-facing response SHALL NOT distinguish them, per `IDN-014`

#### Scenario: Entitlement lookup fails
- **WHEN** the entitlement store errors or is unreachable
- **THEN** the platform SHALL deny
- **AND** SHALL NOT fall back to a permissive default
- **AND** SHALL NOT serve a stale cached entitlement past its declared bound

#### Scenario: Both levels must pass
- **WHEN** a principal passes one level and fails the other
- **THEN** the platform SHALL deny
- **AND** neither level SHALL be able to grant on behalf of the other

### Requirement: ENT-002 Discovery and invocation share one resolver
The set a principal can discover SHALL be computed by the same code path that authorizes the
operation. No role, including administrative roles, SHALL be exempt.

#### Scenario: Item hidden from a listing
- **WHEN** an item is not visible to a principal in a listing operation
- **THEN** a direct operation against that item by the same principal SHALL be denied

#### Scenario: Non-tool surfaces
- **WHEN** the principal lists or reads resources, or lists or retrieves prompts
- **THEN** those listings SHALL be computed by the same resolver as invocation
- **AND** an item absent from the listing SHALL NOT be reachable directly

#### Scenario: Administrator operates on an unentitled server
- **WHEN** a platform administrator operates on a server they hold no entitlement to
- **THEN** the platform SHALL deny the call
- **AND** SHALL NOT apply an administrative bypass

#### Scenario: Entitlement revoked between discovery and invocation
- **WHEN** an entitlement is revoked after a client cached a listing
- **THEN** the next operation SHALL be denied on the current entitlement state

#### Scenario: Listing is filtered, not merely ordered
- **WHEN** a listing is returned
- **THEN** items the principal is not entitled to SHALL be absent from it
- **AND** SHALL NOT be present with a flag the client is expected to honour

### Requirement: ENT-003 Named profiles are allowlists, including when empty
A profile SHALL name the set of operations an identity receives. Resolution SHALL be an
allowlist in every state: an unresolved profile, a profile with no bindings, and a profile with
some bindings all resolve to only what is explicitly bound. An empty binding set SHALL resolve
to the empty result set, never to the unrestricted set.

#### Scenario: No profile assigned
- **WHEN** a principal has no profile binding
- **THEN** the resolved set SHALL be empty
- **AND** SHALL NOT default to the unrestricted set

#### Scenario: Profile exists with zero bindings
- **WHEN** a profile has been created but no bindings have been added to it
- **THEN** the resolved set SHALL be empty
- **AND** SHALL NOT be treated as unconfigured and therefore unrestricted

#### Scenario: Partially populated profile
- **WHEN** a profile has bindings for some items but not others
- **THEN** items without an explicit binding SHALL be excluded

#### Scenario: Profile lookup fails
- **WHEN** the profile store errors and no valid cached value is available
- **THEN** the platform SHALL deny
- **AND** SHALL NOT return an empty result that a caller could read as unrestricted
- **AND** the audit event SHALL carry a reason code distinct from an ordinary entitlement denial

#### Scenario: Legacy resolution path exists
- **WHEN** an implementation carries an older resolution path with different default semantics
- **THEN** that path SHALL be identified and removed rather than retained alongside this one
- **AND** a principal SHALL NOT be able to reach the more permissive path by omitting a field

### Requirement: ENT-004 Entitlement to initiate is separate from entitlement to be called
A backend's ability to initiate operations toward the client, as mediated by `POL-003`, SHALL
be a distinct grant. Approving a server for invocation SHALL NOT grant it the ability to
initiate.

#### Scenario: Server approved for invocation only
- **WHEN** a server that holds no initiate grant issues a sampling or elicitation request
- **THEN** the platform SHALL deny it

#### Scenario: Initiate grant made
- **WHEN** a server is granted the ability to initiate
- **THEN** that grant SHALL name the operations permitted
- **AND** SHALL be recorded with the granting principal per `ENT-007`

### Requirement: ENT-005 Role model separates duties
The platform SHALL define distinct roles for platform administration, security review, and
ordinary use, such that no single role can both submit a server and approve it.

#### Scenario: Submitter attempts self-approval
- **WHEN** the principal who submitted a server attempts to approve it
- **THEN** the platform SHALL deny the approval

#### Scenario: Separation defeated through a machine principal
- **WHEN** a principal attempts to satisfy a two-party requirement using a machine principal
  it owns
- **THEN** the platform SHALL resolve the machine principal to its owning human per `IDN-013`
- **AND** SHALL deny if that resolves to the same human

#### Scenario: Principal holds both roles
- **WHEN** a single principal is assigned both the submitting and the approving role
- **THEN** the assignment SHALL be refused, or the platform SHALL still refuse the
  self-approval at the point of use
- **AND** the separation SHALL NOT depend on assignment discipline alone

#### Scenario: Last administrator removed
- **WHEN** an operation would leave the platform with no administrator
- **THEN** the platform SHALL reject the operation

### Requirement: ENT-006 Grants are bounded and reviewable
Every entitlement grant SHALL record who granted it, to whom, for what, and when. A grant SHALL
be revocable individually, and the platform SHALL be able to enumerate every grant held by a
principal and every principal holding a grant to a server.

#### Scenario: Enumerating a principal's access
- **WHEN** an operator asks what a principal can reach
- **THEN** the platform SHALL answer from the same resolver that authorizes operations
- **AND** SHALL NOT answer from a separately maintained view

#### Scenario: Server decommissioned
- **WHEN** a server is removed
- **THEN** the grants naming it SHALL be revoked rather than left resolvable
- **AND** a later server SHALL NOT inherit them by reusing an identifier

#### Scenario: Principal retired
- **WHEN** a principal is retired per `IDN-010`
- **THEN** its grants SHALL be revoked
- **AND** SHALL NOT remain attached to a recycled identifier

### Requirement: ENT-007 Role and entitlement changes are append-only and attributable
Changes to role assignments and entitlement grants SHALL be recorded as immutable history
identifying the actor, the target principal, the change, and the time.

#### Scenario: Role granted
- **WHEN** an administrator grants a role
- **THEN** the platform SHALL append a record naming the granting principal
- **AND** SHALL NOT overwrite or delete prior assignment history

#### Scenario: Role revoked
- **WHEN** a role is revoked
- **THEN** the revocation SHALL be appended as a new record
- **AND** the prior grant SHALL remain readable in history

#### Scenario: Principal grants to itself
- **WHEN** a principal grants a role or entitlement to itself
- **THEN** the record SHALL make the self-grant explicit
- **AND** the condition SHALL be alertable

### Requirement: ENT-008 A change takes effect on the next operation
A revocation or a narrowing change SHALL take effect on the next operation, without waiting for
any cache to expire.

#### Scenario: Entitlement revoked during an incident
- **WHEN** an operator revokes an entitlement
- **THEN** the next operation by that principal SHALL be denied
- **AND** the denial SHALL NOT wait for a cache lifetime to elapse

#### Scenario: Cached entitlement in the request path
- **WHEN** entitlement state is cached for performance
- **THEN** the cache SHALL be invalidated by the events that change it, per `POL-015`
- **AND** an invalidation failure SHALL fail closed

#### Scenario: Widening change
- **WHEN** a grant is widened
- **THEN** it MAY take effect within a declared bound rather than immediately
- **AND** that bound SHALL be stated, so the asymmetry with narrowing is deliberate
