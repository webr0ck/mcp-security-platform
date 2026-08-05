# policy-enforcement Specification

## Purpose
The single invocation chokepoint. Every mediated operation passes through one policy decision
that defaults to deny and fails closed. Also covers the enumeration of the mediated surface,
quarantine enforcement, integrity levels and the taint floor, prompt-injection screening, and
the rule that advisory signals never independently block a call.

Depends on `identity-authentication` and `authorization-entitlement`. Requirements here are
identified `POL-nnn`. Concrete policy-engine configuration is in `guide.md`, which is
non-normative.

## Requirements

### Requirement: POL-001 One invocation chokepoint
All mediated operations SHALL traverse a single enforcement path. No route, transport,
administrative interface or internal caller SHALL reach a backend without passing that path.

#### Scenario: Alternative transport added
- **WHEN** a new transport or route is added that can reach a backend
- **THEN** it SHALL route through the same enforcement function
- **AND** a test SHALL fail if any path reaches a backend without it

#### Scenario: Internal caller reaches a backend
- **WHEN** a platform component rather than an agent originates a call to a backend
- **THEN** that call SHALL traverse the same enforcement path
- **AND** SHALL carry an explicit principal, so no call is unattributed

#### Scenario: Enforcement path is bypassable in one build variant
- **WHEN** a build, tier or feature configuration removes the enforcement path
- **THEN** startup SHALL fail closed
- **AND** the absence SHALL NOT be expressible as configuration

### Requirement: POL-002 The mediated surface is enumerated, and unenumerated operations are denied
The platform SHALL maintain an explicit enumeration of every protocol operation it mediates,
covering at minimum tool invocation, resource listing and reading, prompt listing and
retrieval, and completion. An operation the platform does not recognise SHALL be denied, not
forwarded.

#### Scenario: Non-tool operation invoked
- **WHEN** a principal performs a resource read, a prompt retrieval or a completion request
- **THEN** the operation SHALL traverse the enforcement path
- **AND** SHALL be subject to entitlement, policy, quarantine, integrity and audit on the same
  terms as a tool invocation

#### Scenario: Operation the platform does not recognise
- **WHEN** a request names a protocol operation absent from the enumeration
- **THEN** the platform SHALL deny it
- **AND** SHALL NOT forward it to the backend to see what happens

#### Scenario: Protocol revision adds an operation
- **WHEN** the pinned protocol revision is raised and introduces a new operation
- **THEN** that operation SHALL be denied until it is added to the enumeration with its
  entitlement, integrity and audit treatment defined
- **AND** the enumeration SHALL be a single definition in the codebase

#### Scenario: Resource content is returned
- **WHEN** a resource read returns content
- **THEN** that content SHALL be screened and assigned an integrity level on the same terms as
  tool output
- **AND** SHALL NOT bypass the taint floor because it arrived by a different operation

### Requirement: POL-003 Server-initiated operations are mediated in the other direction
Where the protocol permits a backend to initiate an operation against the client - including
model sampling requests, elicitation of user input, and notifications - the platform SHALL
mediate those requests. A backend SHALL NOT be able to reach the client's model or its user
unmediated.

#### Scenario: Backend requests model sampling
- **WHEN** a backend issues a sampling request
- **THEN** the platform SHALL apply an explicit allow decision naming that backend before
  forwarding it
- **AND** the request content SHALL be screened and audited
- **AND** absence of an explicit allow SHALL deny

#### Scenario: Backend elicits input from the user
- **WHEN** a backend requests input from the human user
- **THEN** the platform SHALL mediate the request
- **AND** the response SHALL be treated as content crossing a trust boundary, not as
  platform-originated data

#### Scenario: Sampling result re-enters the session
- **WHEN** a sampling or elicitation result returns to the session
- **THEN** it SHALL carry an integrity level derived from the backend that requested it
- **AND** SHALL apply to the taint floor

#### Scenario: Backend not entitled to initiate
- **WHEN** a backend that has not been granted the ability to initiate operations attempts one
- **THEN** the platform SHALL deny it and record the attempt as alertable

### Requirement: POL-004 Policy is deny-by-default
The policy engine SHALL be configured so that absence of an explicit allow is a denial. There
SHALL be no wildcard allow and no fallthrough rule.

#### Scenario: No matching policy rule
- **WHEN** no policy rule matches the request
- **THEN** the decision SHALL be deny

#### Scenario: Engine returns something other than an explicit allow
- **WHEN** the policy engine returns an empty result, a null result, an undefined result, or
  any value the platform cannot read as an explicit allow
- **THEN** the platform SHALL treat it as a deny
- **AND** SHALL NOT interpret the absence of a denial as an allow

#### Scenario: No policy loaded at all
- **WHEN** the policy engine is running with no policy loaded
- **THEN** every decision SHALL be a deny
- **AND** the condition SHALL be alertable as distinct from a busy system denying normally

### Requirement: POL-005 Policy failure fails closed
Any inability to obtain a policy decision SHALL result in denial, not in bypass.

#### Scenario: Policy engine unreachable
- **WHEN** the policy engine cannot be contacted
- **THEN** the platform SHALL deny the call with a distinct reason code in the audit event
- **AND** SHALL NOT allow the call
- **AND** the caller-facing response SHALL comply with `IDN-014`

#### Scenario: Malformed policy response
- **WHEN** the policy engine returns malformed output
- **THEN** the platform SHALL deny
- **AND** SHALL NOT parse partial output into an allow

#### Scenario: Policy evaluation exceeds its time bound
- **WHEN** evaluation does not complete within a declared bound
- **THEN** the platform SHALL deny
- **AND** SHALL NOT wait unboundedly, which would convert a slow engine into an outage

#### Scenario: Fail-closed events are observable
- **WHEN** a policy fail-closed denial occurs
- **THEN** the platform SHALL emit an audit event and a metric distinguishing it from an
  ordinary policy deny

### Requirement: POL-006 Policy is integrity-protected and its provenance is checked
At the staging and production tiers the policy engine SHALL load only policy whose origin it
can verify, and verification SHALL be the default rather than an opt-in.

#### Scenario: Unverifiable policy presented
- **WHEN** policy without verifiable provenance is offered at a tier requiring it
- **THEN** the engine SHALL refuse to load it
- **AND** the platform SHALL fail closed rather than serve with no policy

#### Scenario: Policy updated while running
- **WHEN** policy is replaced at runtime
- **THEN** the replacement SHALL be verified before it takes effect
- **AND** the change SHALL be recorded with the identity that made it

#### Scenario: Verification key compromised
- **WHEN** the key used to verify policy provenance must be rotated
- **THEN** a rotation path SHALL exist that does not require disabling verification

### Requirement: POL-007 Quarantine is enforced before policy
An operation against a quarantined server SHALL be denied to every principal, including
administrators, before the policy engine is consulted.

#### Scenario: Quarantined tool invoked by an administrator
- **WHEN** an administrator invokes an operation on a quarantined server
- **THEN** the platform SHALL deny the call before policy evaluation

#### Scenario: Server re-quarantined while in use
- **WHEN** a server is moved to quarantine
- **THEN** the next operation against it SHALL be denied without waiting for a cache expiry

#### Scenario: Quarantine state unavailable
- **WHEN** the quarantine state cannot be determined
- **THEN** the platform SHALL deny
- **AND** SHALL NOT treat an unknown state as not quarantined

### Requirement: POL-008 Verification of a quarantined server is a named exception on the same chokepoint
Verifying a quarantined server requires contacting it, which `POL-007` otherwise forbids. That
contact SHALL be expressed as an explicitly named, narrowly scoped exception evaluated at the
same chokepoint, and SHALL NOT be a second path to a backend.

#### Scenario: Verification probe issued
- **WHEN** the onboarding workflow probes a quarantined server
- **THEN** the probe SHALL traverse the enforcement path
- **AND** SHALL be permitted only under a distinct verification principal that no human or
  agent principal can assume
- **AND** SHALL be audited with a reason code distinguishing it from an ordinary invocation

#### Scenario: Verification probe scope
- **WHEN** a verification probe executes
- **THEN** it SHALL be restricted to the operations the verification sequence defines
- **AND** SHALL NOT be able to invoke an arbitrary operation on the quarantined server

#### Scenario: Principal attempts to invoke as the verification principal
- **WHEN** any request arrives claiming the verification principal from outside the onboarding
  workflow
- **THEN** the platform SHALL deny it and record the attempt as alertable

#### Scenario: Probe result is untrusted
- **WHEN** a verification probe returns content
- **THEN** that content SHALL be treated as untrusted and SHALL NOT enter a session
- **AND** SHALL NOT make the probed operations invocable

### Requirement: POL-009 Integrity levels are defined and assigned
The platform SHALL define a total ordering of integrity levels, SHALL assign a level to every
source of content entering a session, and SHALL assign a required level to every operation.
An unassigned source SHALL take the lowest level and an unassigned operation the highest
requirement.

#### Scenario: Levels defined
- **WHEN** the platform is built
- **THEN** the integrity levels and their ordering SHALL exist as a single definition
- **AND** every level SHALL have stated criteria for what belongs at it

#### Scenario: Source has no assigned level
- **WHEN** content enters a session from a source with no assigned integrity level
- **THEN** it SHALL be treated as the lowest level
- **AND** the omission SHALL be visible to operators rather than silent

#### Scenario: Operation has no assigned requirement
- **WHEN** an operation has no assigned required integrity level
- **THEN** it SHALL be treated as requiring the highest level
- **AND** SHALL therefore be unreachable from any tainted session until assigned

#### Scenario: Level assigned at onboarding
- **WHEN** a server is onboarded
- **THEN** the integrity level of its content and the required level of each of its operations
  SHALL be recorded as part of registration
- **AND** registration SHALL NOT complete with them unset

### Requirement: POL-010 Integrity taint floor
The platform SHALL record that a session as defined by `IDN-011` has consumed content below a
given integrity level, and SHALL be able to prevent a subsequently privileged operation in
that session. The taint marker SHALL be written before the low-integrity result is returned.

#### Scenario: Low-integrity content returned
- **WHEN** an operation returns content from a source below the session's current floor
- **THEN** the taint marker SHALL be recorded before the response is forwarded to the agent
- **AND** a failure to record it SHALL prevent the response being forwarded

#### Scenario: Privileged operation after taint, enforce mode
- **WHEN** a tainted session attempts an operation requiring an integrity level above the
  session's floor and the floor is in enforce mode
- **THEN** the platform SHALL deny with a distinct reason code in the audit event

#### Scenario: Privileged operation after taint, notify mode
- **WHEN** the same operation occurs with the floor in notify mode
- **THEN** the platform SHALL allow the call
- **AND** SHALL record it as an allow-with-notice, never as a plain allow

#### Scenario: Principal holds several sessions
- **WHEN** a principal holds more than one concurrent session and one becomes tainted
- **THEN** the floor SHALL apply per `IDN-011`, so taint cannot be shed by opening a new
  session with the same credential

#### Scenario: Taint store unavailable
- **WHEN** the taint state cannot be read or written
- **THEN** the platform SHALL deny the operation
- **AND** SHALL NOT proceed on the assumption that the session is clean

### Requirement: POL-011 Notify mode is a bounded migration state, not a resting state
A deployment SHALL reach a configuration in which the taint floor denies. Notify mode SHALL
carry a declared expiry, and a deployment that remains in notify past it SHALL be surfaced as
a deficiency rather than treated as configured.

#### Scenario: Taint floor first enabled
- **WHEN** the taint floor is first enabled on a deployment
- **THEN** it MAY default to notify so operators can observe before denying
- **AND** an expiry for that state SHALL be recorded at the same moment

#### Scenario: Notify expiry passes
- **WHEN** the declared expiry passes with the floor still in notify
- **THEN** the condition SHALL be alertable and SHALL appear in the platform's own posture
  reporting as an unenforced control
- **AND** SHALL NOT be reported as a configured taint floor

#### Scenario: Platform reports its own posture
- **WHEN** the platform states which controls are enforcing
- **THEN** a control in notify mode SHALL be reported as detecting and permitting
- **AND** SHALL NOT be counted as a control that stops the behaviour it detects

#### Scenario: Production tier default
- **WHEN** a deployment runs at the production tier as attested under `IDN-002`
- **THEN** the enforcing configuration SHALL be the default
- **AND** notify SHALL require an explicit, recorded, expiring decision to enable

### Requirement: POL-012 Prompt-injection screening is a tripwire, not a boundary
The platform SHALL screen operation arguments and returned content against a single
authoritative pattern set. Screening SHALL NOT be represented as a complete defence, and its
patterns SHALL have exactly one definition in the codebase.

#### Scenario: Injection pattern matched
- **WHEN** content matches an injection pattern
- **THEN** the platform SHALL record the match in the audit event
- **AND** SHALL apply the configured action for that category
- **AND** the match SHALL be available as an input to the policy decision

#### Scenario: Pattern set duplicated
- **WHEN** injection patterns are defined in more than one place
- **THEN** a test SHALL fail - the pattern set SHALL have a single source of truth

#### Scenario: Screening described in platform documentation
- **WHEN** the platform describes what screening provides
- **THEN** it SHALL state that pattern matching is evadable and is a detection aid
- **AND** SHALL NOT present it as preventing prompt injection

#### Scenario: Content is not screenable
- **WHEN** content cannot be screened because it is binary, encoded or oversized
- **THEN** that fact SHALL be recorded and SHALL be available to the policy decision
- **AND** SHALL NOT be recorded as a clean screening result

### Requirement: POL-013 Advisory signals never independently block a call
Heuristic scores SHALL be inputs to a policy decision and SHALL NOT block a call outside it.
Unavailability of a scoring component SHALL NOT deny. This constrains scoring components
only; it SHALL NOT be read as preventing policy from denying on a signal's value, nor as
constraining the taint floor, quarantine, entitlement or any other non-heuristic control.

#### Scenario: Scorer unavailable
- **WHEN** a scoring component errors or times out
- **THEN** the score SHALL default to a neutral value
- **AND** the call SHALL NOT be denied on that basis alone

#### Scenario: Policy denies on a signal's value
- **WHEN** policy is written to deny on a screening match or an anomaly score above a
  threshold
- **THEN** that denial SHALL be permitted and SHALL be an ordinary policy denial
- **AND** this requirement SHALL NOT be cited to prevent it

#### Scenario: Scorer blocks outside the policy decision
- **WHEN** a scoring component short-circuits a call without a policy decision
- **THEN** that SHALL be a defect

### Requirement: POL-014 Policy input contract is explicit
The policy engine SHALL receive one structured input document per call containing the
principal, principal type, roles, session identifier, target server, operation, argument
metadata, integrity levels and advisory signals, and SHALL return an explicit allow with
reason codes.

#### Scenario: Decision recorded
- **WHEN** a policy decision is returned
- **THEN** the platform SHALL record the decision, its reason codes and a decision identifier
  in the audit event

#### Scenario: Input field missing
- **WHEN** a field the contract requires is absent from the input document
- **THEN** the platform SHALL deny
- **AND** SHALL NOT submit a partial document for evaluation

#### Scenario: Contract field removed
- **WHEN** a change removes a contract field
- **THEN** a test SHALL fail - contract fields are must-preserve

#### Scenario: Raw argument values
- **WHEN** the input document is constructed
- **THEN** it SHALL carry argument metadata rather than raw argument values, except where a
  named policy requires a specific value
- **AND** any such exception SHALL be enumerated

### Requirement: POL-015 Decisions are not reused across the state they depend on
A cached or reused decision SHALL NOT outlive the state it was computed from. Quarantine,
revocation, entitlement and taint SHALL be evaluated per operation.

#### Scenario: Decision reused after a state change
- **WHEN** quarantine, entitlement, revocation or taint changes after a decision is computed
- **THEN** a subsequent operation SHALL NOT be permitted on the earlier decision

#### Scenario: Evaluated state and executed call diverge
- **WHEN** state changes between evaluation and the upstream call
- **THEN** the platform SHALL bound the interval between them
- **AND** the bound SHALL be declared rather than incidental

#### Scenario: Cache used for performance
- **WHEN** any decision input is cached
- **THEN** the cache SHALL be invalidated by the events that change it, not by expiry alone
- **AND** an invalidation failure SHALL fail closed per `POL-005`
