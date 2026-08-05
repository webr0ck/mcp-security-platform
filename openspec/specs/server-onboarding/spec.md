# server-onboarding Specification

## Purpose
The lifecycle that carries a backend server from submission to approved and reachable, and back
out again: quarantine on entry, mediated discovery, dual-control human approval, pinned build
and deployment, verification, release, re-quarantine and decommissioning. Owns the states;
`server-vetting` owns the analysis content.

Depends on `authorization-entitlement` for reviewer roles, `server-vetting` for verdicts and
tiers, and `policy-enforcement` for the mediated verification path. Requirements here are
identified `ONB-nnn`. Concrete workflow configuration is in `guide.md`, which is non-normative.

## Requirements

### Requirement: ONB-001 Servers enter quarantined and leave only by human decision
Every submitted server SHALL start in a state from which no operation can be performed, and
SHALL leave it only through an explicit approval by an authorized reviewer.

#### Scenario: Server submitted
- **WHEN** a server is submitted
- **THEN** no operation against it SHALL be permitted to any principal, including
  administrators
- **AND** its state SHALL be visible to reviewers

#### Scenario: Submission never reviewed
- **WHEN** a submission is left unreviewed
- **THEN** it SHALL remain unreachable indefinitely
- **AND** SHALL NOT time out into an approved state

#### Scenario: State transition attempted out of order
- **WHEN** a transition is requested from a state that does not permit it
- **THEN** the platform SHALL refuse
- **AND** the permitted transitions SHALL be a single definition rather than checks scattered
  across the workflow

### Requirement: ONB-002 Submitted material is untrusted input
Everything supplied at submission - names, descriptions, addresses, manifests, artifacts - SHALL
be treated as untrusted. Submission SHALL NOT be able to cause an effect before approval.

#### Scenario: Submitted address is fetched
- **WHEN** the platform retrieves anything from an address supplied at submission
- **THEN** it SHALL apply the address controls in `NET-007`

#### Scenario: Submitted text is rendered or stored
- **WHEN** submitted names, descriptions or manifest content are stored or displayed to a
  reviewer
- **THEN** they SHALL be treated as content that may carry instructions directed at an agent or
  a reviewer
- **AND** SHALL be screened per `POL-012` and recorded as findings rather than presented as
  neutral metadata

#### Scenario: Submission triggers a build
- **WHEN** submission causes code to be built or executed for analysis
- **THEN** that execution SHALL occur under the isolation constraints applied to backends
- **AND** SHALL NOT run with any credential the platform uses for other purposes

### Requirement: ONB-003 Registration captures what later controls depend on
Registration SHALL record the values other capabilities require to function, and SHALL NOT
complete with them unset.

#### Scenario: Registration completes
- **WHEN** a server is registered
- **THEN** the platform SHALL record the declared injection mode, the integrity level of its
  content and the required integrity level of each of its operations per `POL-009`, its trust
  tier per `VET-002`, its declared egress allowances, and whether it may initiate operations
  per `ENT-004`
- **AND** registration SHALL be refused with any of these unset

#### Scenario: Injection mode without a credential source
- **WHEN** a per-principal credential mode is declared but no such credential source is
  configured
- **THEN** registration SHALL be rejected
- **AND** the error SHALL name the missing configuration
- **AND** the mismatch SHALL NOT be discovered at first invocation

#### Scenario: New capability adds a required registration value
- **WHEN** a capability comes to depend on a value captured at registration
- **THEN** existing registrations lacking it SHALL be surfaced as incomplete
- **AND** SHALL NOT be treated as having a safe default unless one is specified

### Requirement: ONB-004 Discovery during quarantine is mediated, not exempted
Where the platform must contact a submitted server to enumerate its surface, that contact SHALL
occur through the named exception in `POL-008`, on the same chokepoint, under the same isolation
and audit rules as any other call.

#### Scenario: Surface discovery on a quarantined server
- **WHEN** the platform enumerates the surface of a quarantined server
- **THEN** the discovery call SHALL traverse the enforcement path under the verification
  principal
- **AND** SHALL be audited with a reason code distinguishing it from an ordinary operation
- **AND** SHALL NOT make the discovered surface reachable

#### Scenario: Discovery result handling
- **WHEN** discovery returns a surface
- **THEN** the result SHALL be stored as submitted material under `ONB-002`
- **AND** SHALL NOT enter any session

### Requirement: ONB-005 Approval is dual-control, attributable, and records what it approved
Approval SHALL require a principal distinct from the submitter, and SHALL record who approved
what, when, and against which evidence.

#### Scenario: Submitter approves own submission
- **WHEN** the submitting principal attempts approval
- **THEN** the platform SHALL refuse
- **AND** the check SHALL resolve machine principals to their owning human per `ENT-005`

#### Scenario: Approval recorded
- **WHEN** a reviewer approves a server
- **THEN** the platform SHALL record the approving principal, the timestamp, the pinned artifact
  digest, the scan verdict identifier, the assigned trust tier, and the approved surface
  snapshot per `VET-010`
- **AND** the record SHALL be append-only per `ENT-007`

#### Scenario: Evidence changes after approval is recorded
- **WHEN** the verdict or the artifact referenced by an approval is superseded
- **THEN** the approval SHALL NOT silently apply to the new one
- **AND** the platform SHALL require a new approval

### Requirement: ONB-006 Build and deployment are pinned and fail closed
Where the platform builds or launches a server, it SHALL build only the approved digest and
SHALL launch only a successfully built artifact.

#### Scenario: Build requested for an unpinned submission
- **WHEN** no approved digest is recorded
- **THEN** the build SHALL be refused

#### Scenario: Launch requested before build completion
- **WHEN** the deployment state is not one that permits launching
- **THEN** no launch SHALL be attempted
- **AND** the platform SHALL NOT construct the launch invocation at all

#### Scenario: Launch profile cannot be applied
- **WHEN** the hardened runtime profile of `NET-010` cannot be applied in full
- **THEN** the launch SHALL fail
- **AND** SHALL NOT proceed with a reduced profile

### Requirement: ONB-007 Verification gates release
A server SHALL become reachable only after passing a defined sequence of verification checks,
and any single failure SHALL fail closed.

#### Scenario: Verification sequence
- **WHEN** a server is verified
- **THEN** the platform SHALL run a reachability check, a surface-discovery check, an operation
  probe, and a protocol-contract check, all through the mediated path of `ONB-004`
- **AND** SHALL promote the server only on full success

#### Scenario: One check fails
- **WHEN** any check fails
- **THEN** the server SHALL remain unreachable
- **AND** the failure SHALL be recorded in a retrievable verification report

#### Scenario: Probe scope
- **WHEN** the operation probe runs
- **THEN** it SHALL be limited to the operations the verification sequence defines
- **AND** SHALL NOT be capable of invoking an arbitrary operation on the server

#### Scenario: Both onboarding paths
- **WHEN** a server is onboarded either by the platform-built path or by supplying a running
  address
- **THEN** both SHALL use the same verification code path
- **AND** SHALL NOT diverge in the checks applied, except where a check is impossible and its
  absence is recorded per `VET-003`

### Requirement: ONB-008 Protocol contract is machine-checkable and versioned
The platform SHALL define the subset of the protocol a backend must satisfy as a
machine-readable schema, and SHALL validate live responses against it.

#### Scenario: Backend returns a non-conforming surface
- **WHEN** a backend's responses do not match the contract schema
- **THEN** the contract check SHALL record each violation as a finding in the verification
  report
- **AND** SHALL NOT fail in a way that prevents the rest of the report being produced

#### Scenario: Contract version recorded
- **WHEN** a server passes verification
- **THEN** the contract version it was validated against SHALL be recorded against the server
- **AND** SHALL correspond to the protocol revision pinned under `IDN-016`

#### Scenario: Contract version raised
- **WHEN** the platform raises its pinned protocol revision
- **THEN** servers validated against an earlier contract SHALL be identifiable
- **AND** SHALL NOT be treated as validated against the current one

### Requirement: ONB-009 Re-quarantine is always available and immediate
An approved server SHALL be returnable to quarantine at any time, taking effect on the next
operation.

#### Scenario: Server re-quarantined during an incident
- **WHEN** an operator re-quarantines a server
- **THEN** the next operation against it SHALL be denied
- **AND** the denial SHALL NOT wait for a cache expiry

#### Scenario: Automatic re-quarantine
- **WHEN** drift, an expired verdict, or an expired pending decision requires it per
  `VET-009` and `VET-010`
- **THEN** re-quarantine SHALL occur without a human action
- **AND** SHALL be recorded with the condition that caused it

#### Scenario: Re-quarantine during an in-flight operation
- **WHEN** a server is re-quarantined while an operation against it is in flight
- **THEN** the platform SHALL NOT be required to abort the in-flight operation
- **AND** the operation SHALL be recorded so that what completed after re-quarantine is
  reconstructable

### Requirement: ONB-010 Decommissioning is a defined state, not deletion
Removing a server SHALL revoke what depended on it rather than leaving orphaned state, and its
identifier SHALL NOT be reused.

#### Scenario: Server decommissioned
- **WHEN** a server is removed from service
- **THEN** entitlement grants naming it SHALL be revoked per `ENT-006`
- **AND** stored credentials scoped to it SHALL be revoked per `CRD-011`
- **AND** its workload SHALL be stopped

#### Scenario: Identifier reuse
- **WHEN** a new server is registered
- **THEN** it SHALL NOT receive the identifier of a decommissioned server
- **AND** SHALL NOT inherit any grant, credential, approval or snapshot from it

#### Scenario: Audit history after decommissioning
- **WHEN** a server is decommissioned
- **THEN** its audit history and approval records SHALL remain readable
- **AND** SHALL NOT be removed with the registration
