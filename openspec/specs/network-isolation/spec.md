# network-isolation Specification

## Purpose
Makes every other guarantee stick. A fully hostile backend MCP server must gain nothing: no
inbound reachability except from the proxy, no unrestricted egress, no lateral movement, and
no route around the mediation path.

Independent of the request path - this capability is enforced by deployment topology and
verified by a check that evaluates every deployment description, not only the canonical one.
Requirements here are identified `NET-nnn`. Concrete runtime configuration is in `guide.md`,
which is non-normative.

## Requirements

### Requirement: NET-001 Backends are unreachable except through the proxy
Backend MCP servers SHALL sit on an internal network with no inbound route. The proxy SHALL
initiate every connection to them.

#### Scenario: Direct connection attempted
- **WHEN** a client attempts to reach a backend without traversing the proxy
- **THEN** the connection SHALL fail at the network layer
- **AND** SHALL NOT depend on the backend refusing it

#### Scenario: Backend attempts to reach another backend
- **WHEN** one backend attempts to connect to another
- **THEN** the connection SHALL be refused unless an explicit named allowance exists

#### Scenario: Backend attempts to reach the proxy's own control surfaces
- **WHEN** a backend attempts to reach an administrative, metrics or health surface of the
  platform
- **THEN** the connection SHALL be refused
- **AND** the platform SHALL NOT rely on those surfaces being unauthenticated but obscure

### Requirement: NET-002 Isolation does not imply trust
A backend confined by this capability is contained, not trusted. Its responses SHALL be
treated as untrusted input by every capability that consumes them.

#### Scenario: Backend response consumed
- **WHEN** a backend returns tool output, a tool list, or any other content
- **THEN** that content SHALL carry the integrity level of untrusted external data
- **AND** network confinement SHALL NOT be cited as a reason to skip screening

#### Scenario: Backend on the internal network is compromised
- **WHEN** a backend is fully controlled by an attacker
- **THEN** the properties in this specification SHALL still hold
- **AND** no capability SHALL grant it standing on the basis of its network position

### Requirement: NET-003 Internal services are not published to the host
Backend servers, the policy engine, the secrets store and the database SHALL NOT be reachable
from outside the internal network in any deployment description, including development
variants.

#### Scenario: Development variant exposes an internal service
- **WHEN** a development or debugging variant makes an internal service reachable from the
  host or from outside the internal network
- **THEN** the isolation check SHALL fail the build

#### Scenario: New deployment description added
- **WHEN** any new deployment description that can produce a running system is added
- **THEN** the isolation check SHALL evaluate it
- **AND** SHALL NOT pass simply because the canonical description is correct

#### Scenario: Deployment mechanism changes
- **WHEN** the platform gains a second deployment mechanism
- **THEN** the isolation check SHALL cover it before that mechanism is used
- **AND** an uncovered mechanism SHALL be treated as a violation, not as out of scope

### Requirement: NET-004 Isolation is continuously verified
The platform SHALL include an automated check that statically evaluates every deployment
description for isolation violations, and that check SHALL run on every proposed change.

#### Scenario: Check runs on a proposed change
- **WHEN** a change is proposed
- **THEN** the isolation check SHALL run
- **AND** a violation SHALL block the change

#### Scenario: Check cannot parse a description
- **WHEN** the check encounters a deployment description it cannot evaluate
- **THEN** it SHALL fail
- **AND** SHALL NOT report success on the basis of the descriptions it could parse

#### Scenario: Static check and running system diverge
- **WHEN** the running topology differs from what the descriptions declare
- **THEN** the divergence SHALL be detectable by a check against the running system
- **AND** the platform SHALL NOT treat the static check as evidence about production

### Requirement: NET-005 Secrets store reachable only from the proxy
The secrets store SHALL accept connections only from the proxy, and SHALL require an
encrypted transport at the production tier as defined by `IDN-002`.

#### Scenario: Unencrypted transport at the production tier
- **WHEN** the secrets store address does not use an encrypted transport at the production
  tier
- **THEN** the platform SHALL reject the configuration at startup

#### Scenario: Backend reaches the secrets store
- **WHEN** a backend attempts to contact the secrets store directly
- **THEN** the connection SHALL be refused at the network layer
- **AND** SHALL NOT depend on the secrets store's own authentication as the only barrier

### Requirement: NET-006 Backend egress is deny-by-default
Backends SHALL have no outbound network access except to explicitly named destinations.

#### Scenario: Backend calls an unlisted external host
- **WHEN** a backend attempts an outbound connection to a host with no allowance
- **THEN** the connection SHALL be blocked
- **AND** the attempt SHALL be recorded in the audit stream and be alertable

#### Scenario: Backend requires a legitimate upstream
- **WHEN** a backend genuinely needs an external API
- **THEN** that destination SHALL be added as an explicit named allowance recorded against
  that backend
- **AND** SHALL NOT be granted by widening the default for all backends

#### Scenario: Allowance is a name, not an address
- **WHEN** an allowance is expressed as a hostname
- **THEN** the enforcement point SHALL evaluate the address actually connected to
- **AND** SHALL NOT permit an arbitrary address because a permitted name once resolved to it

#### Scenario: Egress by a channel the allowance does not cover
- **WHEN** a backend attempts egress by name resolution, by a configured outbound proxy, or
  by any channel other than a direct connection
- **THEN** that channel SHALL be constrained by the same allowance list
- **AND** an unconstrained channel SHALL be treated as an isolation violation

### Requirement: NET-007 Platform egress is bounded
The platform's own outbound connections SHALL be limited to declared destinations. A
component that fetches a URL derived from data under a caller's or a backend's influence
SHALL evaluate the resolved address before connecting.

#### Scenario: Component fetches a derived URL
- **WHEN** the platform fetches a URL derived from registration data, client metadata or
  backend output
- **THEN** it SHALL resolve the address, evaluate it against an allowance list, refuse
  private, loopback and link-local ranges absent an explicit allowance, and connect to the
  resolved address
- **AND** SHALL re-apply that evaluation to the target of any redirect
- **AND** SHALL bound the response size and time

### Requirement: NET-008 Upstream addresses are re-resolved and pinned at call time
The platform SHALL resolve a backend's address at invocation and pin the resolved address for
the duration of that call, so an address registered at approval cannot be rebound later.

#### Scenario: Address changes after registration
- **WHEN** a registered hostname resolves to a different address at invocation time
- **THEN** the platform SHALL evaluate the newly resolved address against its allowances
- **AND** SHALL refuse the call if it resolves to a disallowed range

#### Scenario: Internal address range reached
- **WHEN** a registered upstream resolves into a private, loopback or link-local range with no
  explicit allowance
- **THEN** the platform SHALL refuse the call

#### Scenario: Resolution changes between check and connection
- **WHEN** the address is evaluated and then connected to
- **THEN** the connection SHALL be made to the address that was evaluated
- **AND** the platform SHALL NOT re-resolve the name between the two steps

### Requirement: NET-009 Transport security between proxy and backends is not the identity layer
Mutual TLS between the proxy and backends MAY be used as hardening. It SHALL NOT be treated
as the mechanism that establishes the calling principal. This constrains the proxy-to-backend
segment only; client authentication at the agent-facing edge is governed by `IDN-003`, where
mutual TLS is a first-class method.

#### Scenario: Proxy-to-backend mutual TLS present
- **WHEN** proxy-to-backend mutual TLS is deployed
- **THEN** authorization decisions SHALL still resolve the principal from the identity layer
- **AND** SHALL NOT infer authorization from proxy-to-backend transport identity

#### Scenario: Backend infers a principal from the transport
- **WHEN** a backend treats the proxy's transport identity as the calling principal
- **THEN** the platform SHALL still supply principal information explicitly
- **AND** SHALL NOT rely on the backend deriving it correctly

### Requirement: NET-010 Backend runtime is constrained
Backend workloads SHALL run under a hardened runtime profile with, at minimum: an immutable
root filesystem, no ability to acquire privileges beyond those granted at start, the narrowest
viable set of kernel privileges, a non-privileged user, and bounded memory, processor and
process count.

#### Scenario: Server launched by the platform
- **WHEN** the platform launches a backend server
- **THEN** it SHALL apply the hardened runtime profile
- **AND** SHALL apply the same profile regardless of which onboarding path produced the server

#### Scenario: Backend requires a writable path
- **WHEN** a backend legitimately needs to write
- **THEN** it SHALL be given a bounded, non-executable, ephemeral writable location
- **AND** the root filesystem SHALL remain immutable

#### Scenario: Profile cannot be applied
- **WHEN** the runtime cannot apply a component of the profile
- **THEN** the launch SHALL fail
- **AND** the platform SHALL NOT start the workload with a reduced profile

#### Scenario: Resource bound reached
- **WHEN** a backend exceeds its memory, processor or process bound
- **THEN** the effect SHALL be confined to that backend
- **AND** SHALL NOT degrade the proxy, the policy engine, the audit path or other backends
