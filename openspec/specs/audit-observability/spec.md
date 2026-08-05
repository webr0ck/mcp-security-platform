# audit-observability Specification

## Purpose
Every decision every other capability made must be reconstructable afterwards, without the
audit trail becoming the credential leak. Covers synchronous emission around the upstream call,
redaction, the event schema, append-only storage, retention, and an honest statement of what
tamper-evidence the platform does and does not provide.

Consumes decisions from every other capability. Requirements here are identified `AUD-nnn`.
Concrete storage configuration is in `guide.md`, which is non-normative.

## Requirements

### Requirement: AUD-001 Audit is synchronous with the decision
Every mediated operation and every authentication or authorization rejection SHALL produce an
audit event before the response is returned. An operation that cannot be audited SHALL NOT
proceed.

#### Scenario: Operation completes
- **WHEN** a mediated operation completes
- **THEN** the audit event SHALL be emitted before the response is sent

#### Scenario: Audit emission fails
- **WHEN** the audit write fails
- **THEN** the platform SHALL return an error rather than the result
- **AND** SHALL NOT return an un-audited result

#### Scenario: Rejection at the identity or entitlement layer
- **WHEN** a request is rejected before reaching policy
- **THEN** an audit event SHALL still be emitted

#### Scenario: Non-tool operations
- **WHEN** a resource read, prompt retrieval, completion, sampling request or elicitation is
  mediated
- **THEN** it SHALL be audited on the same terms as a tool invocation
- **AND** the event SHALL name the operation, not only the server

### Requirement: AUD-002 An effect that has occurred is recorded even if the response is not
Emitting the outcome event before the response does not make the upstream call reversible. The
platform SHALL record an intent event before the upstream call and an outcome event after it,
so a failure between them cannot leave a side effect with no trace.

#### Scenario: Upstream call is about to be made
- **WHEN** the platform is about to call a backend
- **THEN** it SHALL have durably recorded an intent event naming the principal, the operation,
  the target and the decision that permitted it
- **AND** a failure to record the intent SHALL prevent the upstream call

#### Scenario: Platform fails after the upstream call
- **WHEN** the platform crashes, times out, or fails to write the outcome event after the
  backend has already acted
- **THEN** the intent event SHALL remain as evidence that the operation may have taken effect
- **AND** the absence of a matching outcome event SHALL be detectable

#### Scenario: Reconciling intent without outcome
- **WHEN** intent events without matching outcome events are enumerated
- **THEN** the platform SHALL surface them as operations of unknown result
- **AND** SHALL NOT report them as either successes or denials

#### Scenario: Operation denied before the upstream call
- **WHEN** an operation is denied and no backend is contacted
- **THEN** a single event SHALL suffice
- **AND** the two-event sequence SHALL NOT be required where nothing could have taken effect

### Requirement: AUD-003 No secret material in any observable output
Audit rows, log lines, metrics, traces and error messages SHALL NOT contain credentials,
tokens, their encodings, or raw operation arguments.

#### Scenario: Operation arguments recorded
- **WHEN** an operation is audited
- **THEN** arguments SHALL be stored as keyed hashes or as metadata
- **AND** raw argument values SHALL NOT be persisted

#### Scenario: Error path would leak a credential
- **WHEN** an exception message would contain a credential or its encoding
- **THEN** the platform SHALL redact it before emission

#### Scenario: Redaction is applied at the sink, not per call site
- **WHEN** a new component emits observable output
- **THEN** redaction SHALL apply without that component opting in
- **AND** a redaction rule SHALL NOT need to be repeated per call site

#### Scenario: Secret in a tracked file
- **WHEN** the repository is scanned
- **THEN** no tracked file SHALL contain a real secret value

#### Scenario: Backend output contains a credential
- **WHEN** a backend returns content containing a credential
- **THEN** that content SHALL NOT be persisted verbatim in the audit trail
- **AND** the presence of the pattern SHALL still be recordable

### Requirement: AUD-004 Human and machine are recorded separately
Every event SHALL record the human principal and the acting client as distinct fields, so
delegation reads as "the platform acted on behalf of the user" rather than "the agent acted".

#### Scenario: Delegated call audited
- **WHEN** an agent performs an operation on behalf of a user
- **THEN** the event SHALL carry the human principal identifier, the principal type, and the
  acting client identifier as separate fields
- **AND** an event carrying one without the other SHALL be treated as unattributable

#### Scenario: Machine-only call audited
- **WHEN** a service principal operates with no human on whose behalf it acts
- **THEN** the event SHALL record the principal type as machine
- **AND** SHALL record the owning human where one exists, per `IDN-013`

#### Scenario: Platform-originated call
- **WHEN** the platform itself originates a call, including a verification probe under
  `POL-008`
- **THEN** the event SHALL name the platform principal explicitly
- **AND** SHALL NOT leave the principal field empty

### Requirement: AUD-005 Event schema is a contract
Every event SHALL carry at minimum: principal and principal type, acting client, roles, session
identifier, target server, operation, decision and reason codes, policy decision identifier,
integrity level and taint state, and a correlation identifier.

#### Scenario: Correlating a call across components
- **WHEN** an operator investigates a single call
- **THEN** the correlation identifier SHALL link the identity decision, the entitlement
  decision, the policy decision, the broker action, the intent event and the outcome
- **AND** SHALL be usable to retrieve them without reconstructing a sequence by timestamp

#### Scenario: Correlation identifier supplied by the caller
- **WHEN** a caller supplies a correlation or trace identifier
- **THEN** the platform SHALL record it as a separate, caller-asserted field
- **AND** SHALL NOT use it as the identifier by which platform events are correlated

#### Scenario: Schema field removed
- **WHEN** a change removes a contract field
- **THEN** a test SHALL fail - contract fields are must-preserve

#### Scenario: Event timestamp
- **WHEN** an event is recorded
- **THEN** its timestamp SHALL come from the platform, subject to `IDN-005`
- **AND** SHALL NOT be taken from the caller or from a backend

### Requirement: AUD-006 Denials and notices are distinguishable in the record and uniform to the caller
An allow accompanied by a warning SHALL NOT be recorded as a plain allow, and a fail-closed
denial SHALL be distinguishable from a policy denial. The distinctions SHALL live in the audit
event, and SHALL NOT be visible to the caller, per `IDN-014`.

#### Scenario: Taint floor in notify mode allows a call
- **WHEN** the taint floor permits a call but records a notice
- **THEN** the event SHALL be an allow-with-notice, with the notice in its own field
- **AND** the notice SHALL NOT be recorded in the denial-reason field

#### Scenario: Control unavailable
- **WHEN** a call is denied because a control was unreachable
- **THEN** the event SHALL carry a reason code naming which control
- **AND** the caller-facing response SHALL NOT reveal it

#### Scenario: Reason codes enumerated
- **WHEN** reason codes are defined
- **THEN** they SHALL be a single enumeration in the codebase
- **AND** a denial SHALL NOT be emitted without one

### Requirement: AUD-007 The audit path is bounded and cannot be weaponised
Because an operation that cannot be audited does not proceed, the audit path is a
denial-of-service target. It SHALL be bounded so that load does not convert into an outage,
and the bounds SHALL work with the ingress limits in `IDN-015`.

#### Scenario: Rejection flood
- **WHEN** unauthenticated or unauthorized requests arrive at high volume
- **THEN** the platform SHALL bound the audit work each such request can cause
- **AND** SHALL NOT allow rejections to exhaust the audit path and deny legitimate operations

#### Scenario: Audit store slows
- **WHEN** the audit store's latency rises
- **THEN** the effect SHALL be observable as a distinct signal before it becomes a denial rate
- **AND** the platform SHALL NOT silently absorb it as general latency

#### Scenario: Buffering considered
- **WHEN** any buffering sits between the decision and durable storage
- **THEN** the durability point SHALL be stated
- **AND** an event acknowledged before that point SHALL NOT be treated as audited for the
  purposes of `AUD-001` or `AUD-002`

### Requirement: AUD-008 Audit storage is append-only, enforced by the storage system
The audit store SHALL be append-only, enforced by the storage system rather than by application
convention. The writing identity SHALL have no capability to update or delete history.

#### Scenario: Application attempts to modify history
- **WHEN** the writing identity attempts an update or delete against the audit store
- **THEN** the storage system SHALL reject it
- **AND** the rejection SHALL NOT depend on application code declining to issue the operation

#### Scenario: Identity separation
- **WHEN** storage identities are provisioned
- **THEN** each component SHALL hold the narrowest capability its function requires
- **AND** the identity that reads audit history SHALL be distinct from the one that writes it

#### Scenario: Schema change to the audit store
- **WHEN** the audit store's structure is changed
- **THEN** the change SHALL be performed by an identity distinct from the writing identity
- **AND** the change SHALL itself be recorded

### Requirement: AUD-009 Events are shipped off-box
Audit events SHALL be emitted as structured records to a stream consumable by an external
system, and the external copy SHALL be treated as authoritative where the threat model includes
the platform operator.

#### Scenario: Structured output
- **WHEN** an event is emitted
- **THEN** it SHALL be written as structured data suitable for ingestion without parsing free
  text

#### Scenario: External sink unavailable
- **WHEN** the external sink cannot be reached
- **THEN** the condition SHALL be alertable
- **AND** the platform SHALL state whether local durability alone satisfies `AUD-001`, rather
  than leaving it implicit

### Requirement: AUD-010 Retention is enforced by the storage system and bounded at both ends
Archived events SHALL be retained under a retention the platform's own credentials cannot
shorten or bypass, for a stated period, and SHALL be disposed of when that period ends.

#### Scenario: Deletion attempted within the retention period
- **WHEN** any application or operational path attempts to delete an archived event within its
  retention period
- **THEN** the storage system SHALL refuse
- **AND** the refusal SHALL NOT depend on the requester declining to try

#### Scenario: Retention mode is bypassable
- **WHEN** the retention mechanism can be overridden by a sufficiently privileged credential
- **THEN** that fact SHALL be stated in the platform's tamper-evidence documentation per
  `AUD-011`
- **AND** the mechanism SHALL NOT be described as write-once storage

#### Scenario: Retention period ends
- **WHEN** the stated retention period elapses
- **THEN** disposal SHALL occur
- **AND** the platform SHALL NOT retain indefinitely by omission

#### Scenario: Records under hold
- **WHEN** records are placed under a legal or investigative hold
- **THEN** disposal SHALL be suspended for those records
- **AND** the hold SHALL itself be recorded with the identity that placed it

### Requirement: AUD-011 Tamper-evidence is stated honestly
The platform SHALL document precisely which tamper-evidence properties it provides and which it
does not. Claims SHALL NOT exceed what the mechanism delivers.

#### Scenario: Documenting the audit guarantee
- **WHEN** the audit guarantee is described
- **THEN** the documentation SHALL state that append-only is enforced by storage capability
  rather than cryptographically
- **AND** SHALL state whether a hash chain or equivalent sequence exists over the event stream
- **AND** SHALL state that a bypassable retention mode is not write-once storage
- **AND** SHALL state that an identity with administrative control of the store is outside the
  detection boundary

#### Scenario: Claim exceeds the mechanism
- **WHEN** any platform-facing or user-facing text describes the audit trail as immutable,
  tamper-proof or write-once
- **THEN** that text SHALL be corrected to name the actual mechanism and its boundary

### Requirement: AUD-012 Security-relevant conditions are alertable
The platform SHALL expose alertable signals for conditions that indicate attack or
misconfiguration.

#### Scenario: Repeated wrong-audience rejections
- **WHEN** the same principal produces repeated audience-mismatch rejections
- **THEN** the condition SHALL be alertable as possible token replay

#### Scenario: Fail-closed rate rises
- **WHEN** fail-closed denials increase
- **THEN** the condition SHALL be alertable as both an availability and a security signal

#### Scenario: Taint floor denial
- **WHEN** a taint-floor denial occurs
- **THEN** it SHALL be alertable as a possible injection kill-chain in progress

#### Scenario: A control stops firing
- **WHEN** a control that normally produces events stops producing them
- **THEN** the absence SHALL be alertable
- **AND** the platform SHALL NOT rely only on alerts that require an event to fire

#### Scenario: Unenforced controls
- **WHEN** the platform reports its posture
- **THEN** controls in a detect-and-permit configuration SHALL be reported as such per
  `POL-011`
- **AND** SHALL NOT be counted among enforcing controls
