# identity-authentication Specification

## Purpose
Establishes who is calling before anything else trusts the request. Defines the client
authentication methods and their priority, the token validation rules, the typed principal
model, session definition and revocation, ingress limits, and the OAuth/OIDC standards the
platform must conform to.

This is the first capability to build: every other capability assumes a resolved principal.
Requirements here are identified `IDN-nnn` and are referenced by that ID from other
capabilities. Concrete provider configuration is in `guide.md`, which is non-normative.

## Requirements

### Requirement: IDN-001 Single visible authorization server
The platform SHALL expose exactly one authorization server to agents. Upstream identity
providers, backend token endpoints and secret stores SHALL NOT be discoverable from any
agent-reachable metadata document or error response.

#### Scenario: Agent discovers authorization server
- **WHEN** an unauthenticated agent calls a protected route
- **THEN** the platform SHALL return `401` with a `WWW-Authenticate` challenge carrying a
  `resource_metadata` URL (RFC 9728)
- **AND** that document SHALL name only the client-facing authorization server

#### Scenario: Metadata document field allowlist
- **WHEN** the platform serves protected-resource or authorization-server metadata
- **THEN** it SHALL emit only fields on a declared allowlist, with values it constructs
- **AND** SHALL NOT pass through any field from an upstream metadata document verbatim
- **AND** the allowlist SHALL be a single definition in the codebase, testable by inspection

#### Scenario: Upstream tenancy identifier would appear
- **WHEN** any agent-reachable response would carry an upstream issuer URL, tenancy
  identifier, internal hostname, or upstream key identifier
- **THEN** the platform SHALL substitute its own identifier or omit the field

### Requirement: IDN-002 Deployment tier is attested, not merely configured
Several controls in this specification and others relax below the production tier. The tier
value SHALL come from a source the platform's own runtime configuration cannot assert, and a
deployment SHALL refuse to start when its claimed tier contradicts that source.

#### Scenario: Tier claimed lower than attested
- **WHEN** runtime configuration claims a development or staging tier and the attested source
  indicates production
- **THEN** startup SHALL fail closed
- **AND** the platform SHALL NOT serve traffic under the claimed tier

#### Scenario: Tier source unavailable
- **WHEN** the attested tier source cannot be read
- **THEN** the platform SHALL assume the production tier
- **AND** SHALL NOT fall back to the configured value

#### Scenario: Relaxation is enumerated
- **WHEN** the platform runs below the production tier
- **THEN** it SHALL emit, at startup, a single record naming every control relaxed by that tier
- **AND** that record SHALL be derived from the same definitions the controls read, not
  maintained separately

### Requirement: IDN-003 Client authentication methods with fixed priority
The platform SHALL support mutual-TLS client certificate, OAuth bearer token, and API key
authentication at the agent-facing edge, resolved in that fixed priority order. Selection is
by *presence*, not by success: a credential of a higher-priority type that is present but
invalid SHALL reject the request rather than fall through. Unauthenticated requests to any
invocation route SHALL be rejected before application logic runs.

#### Scenario: Multiple credentials present
- **WHEN** a request carries both a client certificate and a bearer token
- **THEN** the platform SHALL resolve the principal from the client certificate
- **AND** SHALL NOT merge or fall through to the lower-priority method

#### Scenario: Higher-priority credential present but invalid
- **WHEN** a request carries an expired, untrusted or malformed client certificate and a
  valid bearer token
- **THEN** the platform SHALL reject the request
- **AND** SHALL NOT resolve the principal from the bearer token

#### Scenario: No credential present
- **WHEN** a request reaches an invocation route with no recognised credential
- **THEN** the platform SHALL return `401` before executing any application logic
- **AND** SHALL emit a synchronous audit event for the rejection (see `AUD-001`)

#### Scenario: Certificate details arrive as a header
- **WHEN** transport termination happens ahead of the platform and certificate details are
  conveyed in a request header
- **THEN** the platform SHALL accept that header only when the immediate sender is
  authenticated to the platform by a mechanism the caller cannot supply
- **AND** SHALL strip or overwrite that header on every path where the check does not apply
- **AND** production startup SHALL fail closed when no such sender authentication is configured

#### Scenario: Client certificate lifetime
- **WHEN** an mTLS client certificate is issued for agent authentication
- **THEN** its validity period SHALL NOT exceed 24 hours

### Requirement: IDN-004 Token validation is unconditional and ordered
For every request bearing an access token the platform SHALL validate issuer, audience,
expiry and scope, in that order, and reject on the first failure. Audience validation SHALL
NOT be disableable in production.

#### Scenario: Token audience does not name this platform
- **WHEN** a token arrives whose audience claim does not identify this resource server
- **THEN** the platform SHALL return `401`
- **AND** SHALL NOT consult policy, entitlement, or the credential broker

#### Scenario: Audience validation unset in production
- **WHEN** the platform starts in the production tier without an expected audience configured
- **THEN** startup SHALL fail closed

#### Scenario: Audience validation relaxed below production
- **WHEN** audience validation is disabled in a development or lab tier
- **THEN** the platform SHALL record the disabled check per `IDN-002`
- **AND** SHALL NOT silently substitute any other claim for the audience

#### Scenario: Signing key unavailable
- **WHEN** the signing key set cannot be retrieved during token verification
- **THEN** the platform SHALL return `503`
- **AND** SHALL NOT issue a session or accept unverified claims

#### Scenario: Signing algorithm not pinned
- **WHEN** a token declares an algorithm outside the configured set, or declares none
- **THEN** the platform SHALL reject it without further processing

### Requirement: IDN-005 Clock dependence is bounded and observable
Token expiry, certificate lifetime, key rotation, session validity and credential expiry all
depend on the platform's clock. The platform SHALL bound its tolerance for clock error and
SHALL NOT treat an unsynchronised clock as a working one.

#### Scenario: Clock source unsynchronised
- **WHEN** the platform's clock source reports that it is not synchronised
- **THEN** the condition SHALL be alertable
- **AND** the platform SHALL continue to enforce expiry rather than disabling them

#### Scenario: Skew tolerance applied
- **WHEN** a token's expiry or not-before claim is evaluated
- **THEN** the platform SHALL apply a declared, bounded skew tolerance
- **AND** that tolerance SHALL NOT exceed 60 seconds

#### Scenario: Time moves backwards
- **WHEN** the observed time moves backwards across requests
- **THEN** the platform SHALL NOT treat a previously expired token, certificate or session as
  valid again

### Requirement: IDN-006 Audience binding via resource indicators
Where the authorization server supports it, the platform SHALL cause access tokens to be
audience-restricted to the specific resource being called, and SHALL validate that
restriction on ingress regardless of how the client requested it. A token SHALL NOT be
accepted with an audience broad enough to be replayed at a different resource.

#### Scenario: Client requests a specific resource
- **WHEN** a client names this platform as the target resource in its authorization request
- **THEN** the resulting access token SHALL be audience-restricted to that resource

#### Scenario: Client omits the resource indicator
- **WHEN** a client that predates RFC 8707 omits the `resource` parameter
- **THEN** the platform MAY accept the request per a documented per-client allowance
- **AND** SHALL record the client identifier, the route and the omitted parameter as a
  conformance event in the audit stream
- **AND** SHALL still validate the audience on the returned token, so a missing request-side
  parameter never results in an unvalidated audience on ingress

#### Scenario: Authorization server does not support resource indicators
- **WHEN** the authorization server cannot audience-restrict per resource
- **THEN** the platform SHALL record the gap per `IDN-014`
- **AND** SHALL still reject any token whose audience does not name this resource server

### Requirement: IDN-007 Token issuance respects entitlement
Where the platform influences or fronts token issuance, a token audience-restricted to a
protected resource SHALL NOT be issued to a principal that holds no entitlement to that
resource. Entitlement SHALL NOT be enforced only on the invocation path.

#### Scenario: Unentitled principal requests a resource-restricted token
- **WHEN** a principal with no entitlement to a backend requests a token naming that backend
  as the resource
- **THEN** the request SHALL be refused
- **AND** the refusal SHALL be audited

#### Scenario: Issuance-time entitlement cannot be enforced
- **WHEN** the authorization server cannot consult platform entitlement at issuance
- **THEN** backends SHALL NOT be configured to accept platform-issued tokens directly
- **AND** every such backend SHALL be reached only through the invocation chokepoint

### Requirement: IDN-008 No token passthrough
A token presented by an agent SHALL NEVER be forwarded to a backend. The platform SHALL
obtain a separate downstream credential for every upstream call. This applies to any header
or body field that would convey the agent's inbound token, however named.

#### Scenario: Agent token reaches the broker
- **WHEN** the credential broker resolves a credential for an upstream call
- **THEN** the outbound request SHALL carry a credential minted or stored for that backend
- **AND** the agent's inbound token SHALL NOT appear in any outbound field

#### Scenario: Client supplies a downstream credential directly
- **WHEN** a client presents a credential intended for a backend rather than for the platform
- **THEN** the platform SHALL reject the request
- **AND** SHALL NOT forward the supplied value

### Requirement: IDN-009 Typed principal model with stable identity
The platform SHALL resolve every caller to a typed principal identifier that distinguishes
humans from machines and is stable across mutable profile attributes.

#### Scenario: Human principal resolved
- **WHEN** a federated human user is resolved
- **THEN** the principal identifier SHALL derive from claims the identity provider guarantees
  to be immutable and unique within its issuer
- **AND** SHALL NOT derive from email, username, or any other mutable attribute

#### Scenario: Subject claim is not stable across relying parties
- **WHEN** the identity provider issues a subject claim that differs per relying party
- **THEN** the platform SHALL derive the principal from a claim that is stable across relying
  parties within that issuer
- **AND** the claim chosen SHALL be recorded in configuration, not inferred per request

#### Scenario: User changes email address
- **WHEN** a user's email changes at the identity provider
- **THEN** all existing entitlements, credentials and audit history SHALL still resolve to
  the same principal

#### Scenario: Machine principal resolved
- **WHEN** an API-key or mTLS caller is resolved
- **THEN** the principal identifier SHALL carry a distinct type prefix from human principals
- **AND** authorization decisions SHALL be able to discriminate on principal type

### Requirement: IDN-010 Principal identifiers survive provider change and are never reused
The principal identifier keys entitlements, stored credentials and audit history. The
platform SHALL provide an explicit path for issuer change, and SHALL NOT allow a recycled
upstream identifier to inherit a prior holder's access.

#### Scenario: Issuer changes
- **WHEN** the issuer identifier changes through migration, rename or provider replacement
- **THEN** the platform SHALL support an operator-initiated, audited remapping of affected
  principals
- **AND** SHALL NOT silently resolve the same human to a new principal, which would drop
  every entitlement to deny and orphan every stored credential

#### Scenario: Upstream identifier is recycled
- **WHEN** an identity provider reissues a previously used subject identifier to a different
  human
- **THEN** the platform SHALL detect the discontinuity and refuse to resolve the new caller
  to the retired principal
- **AND** the condition SHALL be alertable

#### Scenario: Principal retired
- **WHEN** a principal is retired
- **THEN** its identifier SHALL NOT be reissued
- **AND** its stored credentials SHALL be revoked rather than left resolvable

### Requirement: IDN-011 Session is a defined, bounded concept
A session is the unit that carries revocation state and integrity taint. The platform SHALL
define the session as a server-side record bound to a principal, with an identifier carried
by the credential, an issue time and a bounded lifetime. A session SHALL NOT be equated with
a transport connection.

#### Scenario: Session established
- **WHEN** a caller authenticates by any supported method
- **THEN** the platform SHALL resolve or create a server-side session record bound to the
  principal
- **AND** that record SHALL carry an identifier, an issue time and an expiry

#### Scenario: Caller has no session-bearing credential
- **WHEN** a machine principal authenticates by API key or client certificate
- **THEN** the platform SHALL still establish a session record so that revocation, taint and
  the audit contract have a subject
- **AND** that record SHALL be revocable independently of the credential that created it

#### Scenario: Transport reconnects
- **WHEN** a caller drops and re-establishes its transport while presenting the same
  credential
- **THEN** the same session SHALL be resolved
- **AND** state carried by that session SHALL NOT be reset by the reconnection

#### Scenario: Concurrent sessions for one principal
- **WHEN** a principal holds more than one concurrent session
- **THEN** state that exists to constrain the principal rather than the connection SHALL
  apply across all of that principal's sessions
- **AND** the platform SHALL bound the number of concurrent sessions a principal may hold

### Requirement: IDN-012 Session revocation checked on every request, fail-closed
Every session identifier SHALL be checked against a revocation store on every request. Any
error consulting that store SHALL deny.

#### Scenario: Session revoked mid-use
- **WHEN** a session identifier is present in the revocation store
- **THEN** the platform SHALL reject the request even though the credential has not expired

#### Scenario: Revocation store unreachable
- **WHEN** the revocation store returns an error or times out
- **THEN** the platform SHALL deny the request
- **AND** SHALL NOT allow the request on the assumption the session is still valid

#### Scenario: User disabled at the identity provider
- **WHEN** a user is disabled upstream but holds an unexpired credential
- **THEN** the platform SHALL reject the request within a declared bound
- **AND** that bound SHALL be stated as a duration, not left to credential expiry

#### Scenario: Global containment
- **WHEN** an operator invokes containment during an incident
- **THEN** the platform SHALL be able to revoke every active session in one action
- **AND** subsequent requests SHALL be denied without waiting for any cache to expire

### Requirement: IDN-013 Static inbound credentials are bounded
Where the platform accepts static API keys, each SHALL carry an owner, an expiry and a
revocation path. A static key SHALL NOT be reachable as an implicit fallback when a
higher-priority method fails, and SHALL NOT be the recommended method for human callers.

#### Scenario: API key issued
- **WHEN** an API key is created
- **THEN** it SHALL record an owning principal and an expiry timestamp
- **AND** SHALL be revocable independently of any other key

#### Scenario: API key expired
- **WHEN** an expired API key is presented
- **THEN** the platform SHALL return `401`

#### Scenario: Key issued to a machine acting for a human
- **WHEN** an API key is issued to a machine principal owned by a human principal
- **THEN** the owning human SHALL be recorded on the key
- **AND** decisions that require a distinct human, such as dual control, SHALL treat the key
  as the owning human rather than as an independent party

### Requirement: IDN-014 Caller-facing responses are uniform; detail goes to the audit stream
Rejection reasons that distinguish existence, entitlement, quarantine and configuration state
SHALL be recorded in the audit event and SHALL NOT be distinguishable in the response to the
caller. A caller SHALL NOT be able to enumerate the platform's estate or its degraded
controls from response codes or bodies.

#### Scenario: Unentitled versus non-existent
- **WHEN** a principal invokes a tool it is not entitled to, and when it invokes a tool that
  does not exist
- **THEN** the two responses SHALL be indistinguishable to the caller
- **AND** the audit events SHALL carry distinct reason codes

#### Scenario: Fail-closed denial versus policy denial
- **WHEN** a call is denied because a control was unreachable, and when it is denied by policy
- **THEN** the audit events SHALL carry distinct reason codes
- **AND** the caller-facing responses SHALL NOT reveal which control was unavailable

#### Scenario: Operator-facing surfaces
- **WHEN** a principal holding an operator role retrieves a decision record
- **THEN** the full reason code SHALL be available through that authenticated surface
- **AND** that surface SHALL NOT be the invocation path

### Requirement: IDN-015 Ingress is bounded
Every authenticated and unauthenticated ingress path SHALL be subject to a declared request
rate and concurrency bound. Controls that fail closed on resource exhaustion SHALL NOT be
reachable without such a bound.

#### Scenario: Unauthenticated request flood
- **WHEN** unauthenticated requests arrive at a rate exceeding the declared bound
- **THEN** the platform SHALL shed them at the edge
- **AND** SHALL NOT allow rejected requests to exhaust the audit path, the policy engine, the
  secrets store or the authorization server

#### Scenario: Single principal saturates a shared dependency
- **WHEN** one principal's request rate would exhaust a shared dependency
- **THEN** the platform SHALL bound that principal independently
- **AND** other principals SHALL continue to be served

#### Scenario: Bound reached
- **WHEN** a caller is shed for exceeding a bound
- **THEN** the event SHALL be observable to operators
- **AND** the response SHALL comply with `IDN-014`

### Requirement: IDN-016 Standards conformance is declared and versioned
The platform SHALL conform to the following, and SHALL publish the conformance status of
each. Where a standard is not implemented, or is satisfied by a mechanism other than the one
named, the gap SHALL be recorded rather than omitted.

| Standard | Required behaviour |
|---|---|
| OAuth 2.1 / RFC 6749 | Authorization-code flow; no implicit, no password grant |
| RFC 7636 | PKCE `S256` mandatory; `plain` rejected |
| RFC 6750 | Bearer token presentation in the `Authorization` header |
| RFC 8414 | Authorization server metadata document |
| RFC 9728 | Protected resource metadata, advertised in the `401` challenge |
| RFC 8707 | Resource indicator accepted; tokens audience-restricted |
| RFC 9068 | JWT access tokens typed as access tokens; audience validated by the resource server |
| RFC 7662 | Token introspection supported for opaque tokens |
| RFC 7517 | Key set retrieval and key selection by key identifier |
| RFC 8725 | JWT best practices: pinned algorithms, no unsecured tokens, fail-closed key retrieval |
| RFC 9207 | Authorization response issuer parameter issued and validated |
| RFC 7009 | Token revocation endpoint used for logout and incident containment |
| RFC 8693 | Token exchange for downstream credentials (see `credential-broker`) |
| RFC 9700 | OAuth 2.0 Security Best Current Practice |

#### Scenario: Protocol revision is pinned
- **WHEN** the platform depends on a revision of the MCP specification
- **THEN** that revision SHALL be recorded as a version identifier in the platform's
  conformance record
- **AND** a requirement SHALL NOT be expressed as deference to whatever an external document
  currently says

#### Scenario: Client registration mechanism
- **WHEN** a new client must be registered
- **THEN** the platform SHALL prefer client identifier metadata documents at the pinned MCP
  revision
- **AND** MAY support RFC 7591 dynamic client registration as a documented deprecated fallback

#### Scenario: Authorization server fetches a client-supplied URL
- **WHEN** the authorization server retrieves a document at a URL supplied by a client
- **THEN** it SHALL resolve the address, evaluate it against an allowance list, refuse
  private, loopback and link-local ranges absent an explicit allowance, and connect to the
  resolved address
- **AND** SHALL re-apply that evaluation to the target of any redirect
- **AND** SHALL bound the response size and time

#### Scenario: PKCE downgrade attempted
- **WHEN** a client requests `code_challenge_method=plain`
- **THEN** the platform SHALL reject the authorization request

#### Scenario: Authorization response issuer check
- **WHEN** the authorization server advertises issuer identification support
- **THEN** every code callback SHALL carry the issuer parameter
- **AND** the platform SHALL verify it matches the expected issuer before exchanging the code

#### Scenario: Issuer identification not advertised
- **WHEN** the authorization server does not advertise issuer identification support
- **THEN** the platform SHALL record the gap in its conformance record
- **AND** SHALL continue to bind the authorization response to the request by other means
