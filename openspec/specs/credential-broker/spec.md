# credential-broker Specification

## Purpose
Removes credentials from the agent entirely. The broker resolves the right credential for one
call, obtains or decrypts it just in time, injects it server-side, and forgets it. Covers the
token-exchange path for backends that federate, the stored-credential path for the more common
case, the key hierarchy and its stated boundary, resolution precedence, and lifecycle.

Depends on `identity-authentication`. Invoked after `policy-enforcement` allows a call.
Requirements here are identified `CRD-nnn`. Concrete key-management configuration is in
`guide.md`, which is non-normative.

## Requirements

### Requirement: CRD-001 The agent never holds a backend credential
No credential intended for a backend SHALL be returned to the agent under any code path,
including error paths, diagnostic routes and audit output. This is the platform's central
property and it holds jointly with `IDN-008`.

#### Scenario: Successful brokered call
- **WHEN** the broker injects a credential into an upstream request
- **THEN** the credential SHALL be added server-side after the agent's request is received
- **AND** SHALL NOT appear in the response to the agent

#### Scenario: Upstream returns an error containing the credential
- **WHEN** a backend echoes an authorization header or credential in an error body
- **THEN** the platform SHALL redact it before the response reaches the agent and before it
  reaches the audit trail

#### Scenario: Agent requests the credential directly
- **WHEN** an agent or a principal invokes any surface that would disclose a stored credential
- **THEN** the platform SHALL refuse
- **AND** no read path SHALL exist that returns plaintext credential material to a caller,
  including to an administrator

#### Scenario: Credential in a diagnostic surface
- **WHEN** a diagnostic, replay or debugging surface reconstructs a request
- **THEN** the credential SHALL be absent or masked
- **AND** the surface SHALL NOT be exempted because it is operator-facing

### Requirement: CRD-002 Plaintext credential lifetime is one call
A decrypted or freshly obtained credential SHALL exist only for the duration of the single
upstream request it serves, and SHALL be cleared on both success and failure paths.

#### Scenario: Upstream call raises
- **WHEN** the upstream request throws an exception
- **THEN** the plaintext SHALL still be cleared before the handler returns

#### Scenario: Credential reuse across calls
- **WHEN** a second call requires the same credential
- **THEN** the broker SHALL resolve and obtain it again
- **AND** SHALL NOT retain plaintext between calls

#### Scenario: Short-lived downstream token obtained
- **WHEN** the broker obtains a downstream token with a remaining lifetime
- **THEN** any caching of that token SHALL be keyed on the principal and the target backend
- **AND** SHALL NOT be reachable by a different principal
- **AND** SHALL be invalidated when the principal's session is revoked per `IDN-012`

#### Scenario: Plaintext would be written outside memory
- **WHEN** any path would write plaintext credential material to disk, to a log, to a trace,
  to an error report or to a crash dump
- **THEN** that path SHALL be a defect

### Requirement: CRD-003 Stored credentials are encrypted under a per-identity key bound to their context
Stored credentials SHALL be encrypted with an authenticated cipher under a key derived per
identity, and the authenticated additional data SHALL bind the ciphertext to its exact stored
context, so a ciphertext moved to another context cannot be decrypted.

#### Scenario: Key derivation
- **WHEN** a credential is written
- **THEN** the platform SHALL derive a per-identity key using a key-derivation function with a
  fresh salt per stored value
- **AND** SHALL encrypt with an authenticated cipher providing at least 256-bit security
- **AND** SHALL guarantee that a nonce is never reused under a given key

#### Scenario: Ciphertext replayed in another context
- **WHEN** a stored ciphertext is copied to a different principal, service or operation context
- **THEN** decryption SHALL fail authentication
- **AND** the platform SHALL fail closed rather than return an error containing any part of the
  payload

#### Scenario: Authenticated additional data is incomplete
- **WHEN** the additional data omits any field that distinguishes one stored context from
  another
- **THEN** that omission SHALL be a defect, because it permits exactly the substitution this
  requirement prevents

#### Scenario: Cipher or parameters change
- **WHEN** the cipher, key-derivation function or parameters are changed
- **THEN** stored values SHALL carry enough information to be decrypted under the scheme that
  wrote them
- **AND** a change SHALL NOT render existing values unreadable

### Requirement: CRD-004 The root of the key hierarchy has a stated trust boundary
The platform SHALL obtain its root key material from a store with a real authentication path,
and SHALL document whether that material is disclosed to the platform in use. A design in
which compromise of the platform discloses every stored credential SHALL be stated as such
rather than described as protected by the store.

#### Scenario: Root material is read by the platform
- **WHEN** the platform reads root key material into its own memory
- **THEN** the documentation SHALL state that compromise of the platform process discloses
  every credential derivable from it
- **AND** SHALL NOT describe the credentials as protected by the secrets store against that
  adversary

#### Scenario: Root material never leaves the store
- **WHEN** the platform instead sends data to the store for wrapping or unwrapping and never
  receives the root key
- **THEN** the documentation SHALL state that compromise of the platform discloses only what it
  asks the store to unwrap while compromised
- **AND** the store SHALL bound and record those requests

#### Scenario: Root material unavailable
- **WHEN** the root key material or the wrapping service cannot be reached
- **THEN** every operation requiring a stored credential SHALL fail closed
- **AND** only operations requiring no credential SHALL proceed

#### Scenario: Root material supplied by configuration
- **WHEN** root key material would come from an environment variable, a file in the deployment
  description, or any value present in the deployment artifact
- **THEN** startup at the production tier SHALL fail closed

### Requirement: CRD-005 Root key rotation is possible without loss
The platform SHALL support rotating root key material, and rotation SHALL neither orphan
existing ciphertext nor require a window in which credentials are unprotected.

#### Scenario: Initial seeding
- **WHEN** the platform initialises root key material
- **THEN** it SHALL seed only if absent
- **AND** SHALL NOT overwrite existing material

#### Scenario: Rotation performed
- **WHEN** root key material is rotated
- **THEN** existing stored values SHALL remain decryptable under the material that wrote them
  until they are re-encrypted
- **AND** the platform SHALL provide a re-encryption path that runs without exposing plaintext
  outside the process boundary already stated in `CRD-004`

#### Scenario: Re-encryption interrupted
- **WHEN** a re-encryption pass is interrupted
- **THEN** it SHALL be resumable
- **AND** values not yet re-encrypted SHALL remain usable

#### Scenario: Rotation after suspected compromise
- **WHEN** rotation follows a suspected compromise
- **THEN** rotating the root material alone SHALL NOT be represented as remediation
- **AND** the stored credentials themselves SHALL be treated as disclosed and rotated at their
  own providers

### Requirement: CRD-006 Exactly one ciphertext codec
The platform SHALL have a single implementation for encrypting and decrypting stored
credentials, used by every writer and every reader, including seeding, migration and
administrative tooling.

#### Scenario: Second codec introduced
- **WHEN** a code path encrypts or decrypts credentials outside the shared codec
- **THEN** a test SHALL fail - divergent codecs cause every stored credential to fail
  authentication at injection time

#### Scenario: Provisioning tooling writes a credential
- **WHEN** seeding, migration or operational tooling writes a credential
- **THEN** it SHALL use the same codec and the same context binding as the request path
- **AND** SHALL NOT construct the stored value independently

### Requirement: CRD-007 Typed injection modes resolved strictly
Each operation SHALL declare how a credential is injected. Resolution SHALL proceed
operation-level, then server default, then none. Parsing SHALL be strict: an empty or unknown
value SHALL fail closed.

#### Scenario: Unknown injection mode
- **WHEN** an operation declares an unrecognised injection mode
- **THEN** the platform SHALL deny the call
- **AND** SHALL NOT fall back to forwarding the request without a credential

#### Scenario: Empty injection mode
- **WHEN** the injection mode is an empty value
- **THEN** the platform SHALL treat it as a parse failure and deny
- **AND** SHALL NOT collapse it to the "no credential required" mode

#### Scenario: Mode requires a credential source that is not configured
- **WHEN** a per-principal mode is declared for a server with no per-principal credential
  source
- **THEN** registration SHALL reject the configuration
- **AND** the mismatch SHALL NOT be discovered at first invocation

#### Scenario: Injection would collide with caller-supplied data
- **WHEN** the request already carries a field the injection mode would write
- **THEN** the platform SHALL overwrite it rather than merge
- **AND** the caller SHALL NOT be able to influence the injected credential by pre-populating
  the field

### Requirement: CRD-008 Token exchange where the authorization server supports it
Where a backend accepts tokens from the same authorization server and that server supports
token exchange, the platform SHALL obtain a downstream token by exchange, authenticating as
itself.

#### Scenario: Exchange performed
- **WHEN** the broker exchanges the caller's token for a downstream token
- **THEN** the request SHALL carry the caller's token as the subject token and its type
- **AND** SHALL name the target backend
- **AND** SHALL request a scope no wider than the subject token's

#### Scenario: Exchange client authentication
- **WHEN** the broker calls the token endpoint
- **THEN** it SHALL authenticate as a confidential client whose credentials the agent does not
  hold

#### Scenario: Issued token audience
- **WHEN** the authorization server returns a downstream token
- **THEN** that token SHALL be audience-restricted to the target backend
- **AND** the platform SHALL verify that restriction before use rather than assuming it

#### Scenario: Delegation claim unavailable
- **WHEN** the authorization server does not record the delegation in the issued token
- **THEN** the platform SHALL still record the acting client and the human principal separately
  in the audit event per `AUD-004`
- **AND** SHALL NOT treat the missing claim as a failure

#### Scenario: Authorization server offers no exchange
- **WHEN** the configured authorization server offers no token-exchange capability, or offers
  one that is not usable for this purpose
- **THEN** the backend SHALL be configured to use a stored credential instead
- **AND** the platform SHALL NOT degrade to forwarding the agent's token

#### Scenario: Exchange fails at call time
- **WHEN** the exchange request fails
- **THEN** the call SHALL fail closed
- **AND** SHALL NOT fall back to a stored credential belonging to a different principal

### Requirement: CRD-009 Stored credentials are a first-class path
Backends with their own authentication - per-principal tokens, service accounts, API keys,
username-and-secret pairs - SHALL be supported through the same encryption and injection
machinery as token exchange, not as a lesser fallback. Most estates will use this path for most
backends.

#### Scenario: Per-principal credential enrolled
- **WHEN** a principal enrols their own backend credential
- **THEN** it SHALL be stored encrypted and bound to that principal's identifier from `IDN-009`
- **AND** SHALL NOT be readable in the context of another principal

#### Scenario: Enrolment path
- **WHEN** a credential is enrolled
- **THEN** it SHALL be submitted over a channel where it is not exposed to the agent
- **AND** the enrolment SHALL be audited without recording the value

#### Scenario: Shared service credential uploaded
- **WHEN** an administrator uploads a shared service credential
- **THEN** the upload SHALL require dual control per `ENT-005`
- **AND** the credential SHALL be linked to the specific server or operation it serves

#### Scenario: Username-and-secret credential stored
- **WHEN** such a credential is stored
- **THEN** it SHALL be stored as structured fields
- **AND** any encoded form SHALL be constructed at injection time
- **AND** neither the fields nor the encoded form SHALL appear in logs, audit records or error
  text

#### Scenario: Malformed stored payload
- **WHEN** a stored credential payload fails to parse
- **THEN** the platform SHALL fail without including any excerpt of the payload

### Requirement: CRD-010 Resolution precedence is fixed and never falls across identities
Credential resolution SHALL prefer a credential owned by the calling principal over a shared
service credential. A missing required credential SHALL be an error, never a fall-through to a
different owner's credential.

#### Scenario: Both principal and service credentials exist
- **WHEN** the caller has their own credential and a service credential also exists
- **THEN** the broker SHALL use the caller's credential

#### Scenario: Required per-principal credential missing
- **WHEN** a per-principal mode is configured and the caller has no enrolled credential
- **THEN** the platform SHALL fail with a distinct reason code in the audit event
- **AND** SHALL NOT use the service credential or another principal's stored value
- **AND** the caller-facing response SHALL comply with `IDN-014`

#### Scenario: Lookup returns more than one candidate
- **WHEN** resolution finds more than one credential at the same precedence level
- **THEN** the platform SHALL fail closed
- **AND** SHALL NOT select one arbitrarily

### Requirement: CRD-011 Stored credentials are not immortal
Every stored credential SHALL carry an owner, a service context, an expiry or review date, and
a revocation and rotation path. Expiry or revocation SHALL fail closed.

#### Scenario: Credential revoked
- **WHEN** a stored credential is revoked
- **THEN** the next call requiring it SHALL fail closed
- **AND** SHALL NOT use a stale copy or another stored value

#### Scenario: Credential rotated
- **WHEN** a credential is rotated
- **THEN** subsequent calls SHALL use the new value without requiring a restart

#### Scenario: Owner departs
- **WHEN** the owning principal is retired per `IDN-010`
- **THEN** its stored credentials SHALL be revoked
- **AND** SHALL NOT remain resolvable

#### Scenario: Credential past its review date
- **WHEN** a stored credential passes its expiry or review date
- **THEN** the condition SHALL be alertable
- **AND** the platform SHALL be able to enumerate every credential in that state

### Requirement: CRD-012 Broker actions are audited and correlated
Every credential resolution, exchange, injection and failure SHALL be recorded against the
correlation identifier of the operation that caused it, without recording the credential.

#### Scenario: Brokered call audited
- **WHEN** the broker acts
- **THEN** the audit record SHALL name which credential source was used, which precedence level
  resolved, and the target backend
- **AND** SHALL identify the credential by a stable non-secret reference, never by value

#### Scenario: Broker failure audited
- **WHEN** resolution, exchange or injection fails
- **THEN** the failure SHALL be audited with a distinct reason code
- **AND** SHALL be distinguishable from a policy denial

#### Scenario: Broker unavailability
- **WHEN** the broker cannot reach the secrets store or wrapping service
- **THEN** operations requiring a credential SHALL fail
- **AND** SHALL NOT forward the upstream request without a credential
- **AND** the condition SHALL be alertable as distinct from ordinary denials
