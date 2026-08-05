# server-vetting Specification

## Purpose
Nothing runs behind the gateway unscanned, and nothing stays approved because it passed once.
Covers the day-one scan gate, what is scannable and what is not, the trust tier that records
the difference, SBOM and dependency analysis, protocol-aware static analysis, artifact pinning,
verdict expiry, and the drift checks that catch a server changing after approval.

Feeds `server-onboarding`, which owns the human approval workflow. Requirements here are
identified `VET-nnn`. Concrete scanner configuration is in `guide.md`, which is non-normative.

## Requirements

### Requirement: VET-001 Day-one scan gate
No server SHALL leave quarantine without a scan verdict attached to its approval record. A scan
verdict SHALL be an input to human approval, never a substitute for it.

#### Scenario: Approval attempted without a verdict
- **WHEN** an approver attempts to release a server with no scan verdict
- **THEN** the platform SHALL refuse the release

#### Scenario: Scan passes
- **WHEN** a scan completes with no blocking findings
- **THEN** the server SHALL remain in quarantine until a human approves it

#### Scenario: Scan cannot complete
- **WHEN** a scan fails to run or terminates without a verdict
- **THEN** the absence of a verdict SHALL block release
- **AND** SHALL NOT be recorded as a clean result

### Requirement: VET-002 Trust tier records what was actually vetted
Every server SHALL carry a trust tier assigned at approval from an enumerated set. The tier
SHALL be derived from what the platform was able to vet, not from the submitter's assertion, and
each tier SHALL have stated consequences elsewhere in the platform.

#### Scenario: Tier assigned
- **WHEN** a server is approved
- **THEN** it SHALL carry exactly one tier from the enumeration
- **AND** the tier SHALL record whether source, artifact, SBOM and manifest were each obtained
  and analysed

#### Scenario: Tier consequences are defined
- **WHEN** a tier is defined
- **THEN** its effect on rescan cadence, drift response, integrity level and permitted
  operations SHALL be stated
- **AND** a tier with no stated consequences SHALL NOT exist

#### Scenario: Tier unassigned
- **WHEN** a server has no assigned tier
- **THEN** it SHALL be treated at the least trusted tier
- **AND** approval SHALL NOT complete with the tier unset

#### Scenario: Tier raised
- **WHEN** a server's tier is raised
- **THEN** the change SHALL require the same dual control as approval per `ENT-005`
- **AND** SHALL be recorded with the deciding principals

### Requirement: VET-003 What cannot be vetted is recorded as unvetted
The platform SHALL state, per server, which analyses it was able to perform. A server whose
running code the platform cannot obtain SHALL NOT be represented as scanned on the strength of
manifest-level checks alone.

#### Scenario: Server supplied as a running endpoint
- **WHEN** a server is onboarded by supplying a URL rather than an artifact the platform builds
- **THEN** the platform SHALL record that source and artifact analysis were not possible
- **AND** SHALL assign a tier reflecting that
- **AND** SHALL NOT report the server as having passed a code scan

#### Scenario: Artifact obtainable but source is not
- **WHEN** the platform can obtain a built artifact but not its source
- **THEN** the analyses that require source SHALL be recorded as not performed
- **AND** the verdict SHALL enumerate what was performed rather than reporting a single pass

#### Scenario: Platform reports coverage
- **WHEN** the platform reports its vetting posture
- **THEN** servers vetted only at the manifest level SHALL be counted separately
- **AND** SHALL NOT be aggregated with fully analysed servers

### Requirement: VET-004 Machine-readable inventory per server
Every scanned server SHALL produce a component inventory in a standard machine-readable format,
stored with the submission and retrievable by reviewers.

#### Scenario: Inventory generated
- **WHEN** a server is scanned
- **THEN** an inventory SHALL be generated and stored against the submission
- **AND** SHALL be retrievable from the review interface

#### Scenario: Inventory provenance
- **WHEN** an inventory is used as an input to approval
- **THEN** the platform SHALL verify that it was produced by the platform's own analysis of the
  pinned artifact, or that its origin can be verified
- **AND** SHALL NOT accept a submitter-supplied inventory as equivalent

#### Scenario: Activation without a verifiable inventory
- **WHEN** a server would become active with no inventory whose origin the platform can verify
- **THEN** the platform SHALL refuse activation

### Requirement: VET-005 Dependency vulnerability analysis from multiple sources
Dependencies SHALL be evaluated against at least two vulnerability data sources, at scan time
and again when advisory data changes.

#### Scenario: Scan-time evaluation
- **WHEN** a server is scanned
- **THEN** its dependencies SHALL be checked against an ecosystem-specific source and a broad
  cross-ecosystem source

#### Scenario: New advisory published after approval
- **WHEN** advisory data updates and affects a stored inventory
- **THEN** the platform SHALL flag the affected server for review
- **AND** SHALL record that a clean scan is a timestamp, not a permanent property

#### Scenario: Advisory data is stale
- **WHEN** the advisory data the platform evaluates against has not been updated within a
  declared interval
- **THEN** the condition SHALL be alertable
- **AND** verdicts produced against stale data SHALL be identifiable as such

### Requirement: VET-006 Protocol-aware static analysis
Static analysis SHALL include rules for risks specific to this protocol that generic analysers
do not cover, and SHALL run without outbound network access beyond explicitly named sources.

#### Scenario: Instruction-bearing tool description
- **WHEN** a tool description, prompt or resource annotation contains instructions directed at
  the calling agent
- **THEN** the manifest audit SHALL record a finding

#### Scenario: Scanner network access
- **WHEN** a scan runs
- **THEN** the scanner SHALL execute under the isolation constraints of `NET-006` and `NET-010`
- **AND** analysing hostile code SHALL NOT grant that code egress

#### Scenario: Exfiltration or internal-endpoint pattern present
- **WHEN** the code contains credential-exfiltration or internal-metadata-endpoint access
  patterns
- **THEN** the scan SHALL record a finding of the corresponding category

#### Scenario: Severity mapping
- **WHEN** findings are assigned severities
- **THEN** the mapping from finding category to severity SHALL be a single definition
- **AND** which severities block release SHALL be stated rather than left to the approver to
  infer

### Requirement: VET-007 Approval pins an exact artifact, and what runs is what was pinned
Approval SHALL bind a server to an exact commit or artifact digest. Build and deploy SHALL
refuse an unpinned or mismatched artifact, and the running workload SHALL be verifiable as the
pinned one.

#### Scenario: Build against a moved reference
- **WHEN** a build is requested and the resolved commit does not match the pinned digest
- **THEN** the build SHALL fail closed
- **AND** SHALL NOT proceed with the newer commit

#### Scenario: Deployment of an unbuilt artifact
- **WHEN** deployment is requested for a server whose build did not complete
- **THEN** the platform SHALL refuse to launch it

#### Scenario: Running workload differs from the pinned artifact
- **WHEN** the workload actually running does not correspond to the pinned digest
- **THEN** the divergence SHALL be detectable
- **AND** the platform SHALL NOT rely on the launch having been correct as evidence about the
  current state

#### Scenario: Mutable reference used as a pin
- **WHEN** a reference that can be repointed is offered as the pin
- **THEN** the platform SHALL refuse it
- **AND** SHALL require a reference that identifies content rather than a name

### Requirement: VET-008 Verdicts expire
A scan verdict SHALL carry an expiry. An approved server whose verdict has expired SHALL be
treated as unvetted rather than as approved.

#### Scenario: Server exceeds the rescan interval
- **WHEN** an approved server's last verdict is older than the interval for its tier
- **THEN** the platform SHALL re-enqueue it for scanning
- **AND** SHALL expose its staleness

#### Scenario: Verdict expires without a rescan completing
- **WHEN** a verdict passes its expiry and no new verdict has been produced
- **THEN** the server SHALL be surfaced as unvetted
- **AND** SHALL NOT continue to be reported as an approved, scanned server

#### Scenario: Rescan cannot run
- **WHEN** rescanning is not possible because the artifact is no longer obtainable
- **THEN** that SHALL be recorded as an inability to re-vet
- **AND** SHALL NOT extend the existing verdict

### Requirement: VET-009 A blocking finding on an approved server is bounded, not open-ended
Where a rescan produces a blocking finding on a server already in use, the platform MAY leave
it approved pending a human decision. That pending state SHALL carry an expiry, and SHALL NOT
be a resting state.

#### Scenario: Rescan finds a blocking issue
- **WHEN** a rescan produces a blocking finding on an approved server
- **THEN** the platform SHALL surface it for review
- **AND** MAY leave the server approved pending a human decision
- **AND** SHALL record an expiry for that pending state at the same moment

#### Scenario: Pending decision expires
- **WHEN** the pending state passes its expiry with no decision recorded
- **THEN** the server SHALL be returned to quarantine
- **AND** the escalation SHALL be recorded

#### Scenario: Posture reporting
- **WHEN** the platform reports its posture
- **THEN** servers approved with an outstanding blocking finding SHALL be reported as such
- **AND** SHALL NOT be counted among cleanly approved servers

### Requirement: VET-010 Manifest drift detection
The platform SHALL detect a server whose advertised surface changes after approval, whether the
change is made through the platform or at a remote server.

#### Scenario: Approved snapshot captured
- **WHEN** a server is approved
- **THEN** the platform SHALL store the exact advertised surface - tools, resources, prompts,
  their descriptions and schemas - as the approved snapshot for later comparison

#### Scenario: Surface changed through the registry
- **WHEN** a description, schema or upstream address is modified through the platform
- **THEN** the change SHALL trigger a re-audit
- **AND** a critical result SHALL return the server to quarantine

#### Scenario: Remote server changes its manifest
- **WHEN** a remote server's advertised surface differs from the approved snapshot
- **THEN** the platform SHALL detect the difference on a scheduled comparison
- **AND** the response SHALL follow the stated consequence for that server's tier per `VET-002`

#### Scenario: Surface differs at invocation
- **WHEN** the surface presented during an operation differs from the approved snapshot
- **THEN** the platform SHALL treat the operation as unapproved
- **AND** SHALL NOT wait for the next scheduled comparison

### Requirement: VET-011 Vetting is evidence, not enforcement
The platform SHALL treat scanning as evidence for an approver and SHALL NOT represent it as
proof that a server is safe. Runtime mediation SHALL remain the enforcement mechanism.

#### Scenario: Server passes all analyses but behaves maliciously at runtime
- **WHEN** an approved server exfiltrates data through a legitimate-looking operation
- **THEN** containment SHALL come from `network-isolation`, `policy-enforcement` and
  `audit-observability`, not from the scanner

#### Scenario: Vetting result described
- **WHEN** the platform describes what a passed scan means
- **THEN** it SHALL state which analyses ran, against which artifact, at what time
- **AND** SHALL NOT describe the server as safe or trusted

#### Scenario: Vetting used to relax runtime controls
- **WHEN** a proposal would relax a runtime control on the basis of a vetting result
- **THEN** that SHALL be refused
- **AND** the integrity level assigned under `POL-009` SHALL remain governed by the source of
  the content, not by the server's vetting history
