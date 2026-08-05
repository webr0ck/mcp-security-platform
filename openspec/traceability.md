# Traceability - spec to invariant to enforcement

Maps each normative requirement in `openspec/specs/` to the invariant it corresponds to in
`docs/ARCHITECTURE.md` §10, and to where that invariant is enforced in the reference
implementation.

This file exists so that `spec.md` files can stay implementation-independent. Earlier revisions
carried `INV-nnn` references inline in normative text, which coupled the specs to one build's
numbering. Those references now live here.

## How to read it

| Column | Meaning |
|---|---|
| Requirement | The normative statement in `openspec/specs/` |
| Invariant | The corresponding row in `docs/ARCHITECTURE.md` §10, where one exists |
| Enforcement | The site named by that invariant row |

**A blank Invariant column means the requirement has no counterpart invariant in this build.**
That is a gap in the reference implementation, not in the spec. Most blanks came from the
validation pass that produced this revision: they are requirements written to close a hole the
implementation has not yet addressed. They are the working list.

The invariant rows themselves carry the authoritative file references; this table cites them in
short form. Where a row's enforcement has moved, fix `docs/ARCHITECTURE.md` §10 and update the
short form here.

---

## identity-authentication

| Requirement | Invariant | Enforcement |
|---|---|---|
| IDN-001 Single visible authorization server | | |
| IDN-002 Deployment tier is attested | | |
| IDN-003 Client authentication methods with fixed priority | INV-009, INV-010 | gateway `ssl_verify_client` + auth middleware; step-ca provisioner |
| IDN-004 Token validation is unconditional and ordered | INV-009 | auth middleware |
| IDN-005 Clock dependence is bounded and observable | | |
| IDN-006 Audience binding via resource indicators | | |
| IDN-007 Token issuance respects entitlement | | |
| IDN-008 No token passthrough | | |
| IDN-009 Typed principal model with stable identity | P1-1 | identity anti-spoofing: email keyed only on an asserted-verified claim |
| IDN-010 Principal identifiers survive provider change | | |
| IDN-011 Session is a defined, bounded concept | | |
| IDN-012 Session revocation checked on every request | INV-014 | `middleware/auth.py::_is_session_jti_revoked` |
| IDN-013 Static inbound credentials are bounded | INV-009 | auth middleware |
| IDN-014 Caller-facing responses are uniform | | |
| IDN-015 Ingress is bounded | | |
| IDN-016 Standards conformance is declared and versioned | | |

Note on IDN-003: the invariant pair records the lab/production listener split. `INV-009` states
"cert OR app-layer auth"; the spec requires selection by *presence* of the higher-priority
credential rather than by its success. Verify the middleware implements presence, not fallthrough.

## network-isolation

| Requirement | Invariant | Enforcement |
|---|---|---|
| NET-001 Backends unreachable except through the proxy | INV-017 | `scripts/check_network_isolation.py` |
| NET-002 Isolation does not imply trust | | |
| NET-003 Internal services are not published to the host | INV-017 | `scripts/check_network_isolation.py` |
| NET-004 Isolation is continuously verified | INV-017 | `make security-check` |
| NET-005 Secrets store reachable only from the proxy | | |
| NET-006 Backend egress is deny-by-default | | |
| NET-007 Platform egress is bounded | | |
| NET-008 Upstream addresses re-resolved and pinned at call time | | |
| NET-009 Transport security is not the identity layer | INV-009 | gateway config |
| NET-010 Backend runtime is constrained | | |

## policy-enforcement

| Requirement | Invariant | Enforcement |
|---|---|---|
| POL-001 One invocation chokepoint | INV-005 (fixed bypass) | `routers/mcp_server.py::_handle_invoke_tool_real` |
| POL-002 The mediated surface is enumerated | | |
| POL-003 Server-initiated operations are mediated | | |
| POL-004 Policy is deny-by-default | INV-003 | `policies/rego/authz.rego` |
| POL-005 Policy failure fails closed | INV-004 | `services/policy.py` |
| POL-006 Policy is integrity-protected | INV-012 | `docker-compose.yml`, `compose.engine.yml`, `check_signed_default.sh` |
| POL-007 Quarantine is enforced before policy | INV-005 | `services/invocation.py`, `routers/mcp_server.py` |
| POL-008 Verification exception on the same chokepoint | | |
| POL-009 Integrity levels are defined and assigned | | |
| POL-010 Integrity taint floor | | |
| POL-011 Notify mode is a bounded migration state | | |
| POL-012 Prompt-injection screening is a tripwire | | |
| POL-013 Advisory signals never independently block | | anomaly heuristic is advisory in the invocation chain |
| POL-014 Policy input contract is explicit | | |
| POL-015 Decisions not reused across the state they depend on | | |

The `INV-005 (fixed bypass)` row is the record of the meta-tool sub-dispatch defect: a
quarantined sub-tool resolved as absent and fell back to the outer tool's identity for every
gate. It is the concrete instance POL-001 and POL-007 are written against.

## authorization-entitlement

| Requirement | Invariant | Enforcement |
|---|---|---|
| ENT-001 Deny-by-default at two levels | INV-003, INV-015 | `policies/rego/authz.rego`; `services/invocation.py::_lookup_profile_with_cache` |
| ENT-002 Discovery and invocation share one resolver | | |
| ENT-003 Named profiles are allowlists, including when empty | INV-016 | `services/invocation.py::_named_profile_has_any_binding` |
| ENT-004 Entitlement to initiate is separate | | |
| ENT-005 Role model separates duties | P1-2 | machine tokens cannot perform human-only profile mutation |
| ENT-006 Grants are bounded and reviewable | | |
| ENT-007 Role and entitlement changes are append-only | INV-011 | PostgreSQL grants (`V003`/`V009`) |
| ENT-008 A change takes effect on the next operation | | |

**ENT-003 contradicts INV-016 deliberately.** The invariant states that a profile with zero
bindings still allows all, and that the legacy per-identity path is default-allow. ENT-003
requires the opposite: an empty profile resolves to the empty set, and any legacy permissive path
is removed rather than retained. The spec is the target state. Closing this is an implementation
change to `_named_profile_has_any_binding` and to the legacy path, plus an amendment to INV-016.

## audit-observability

| Requirement | Invariant | Enforcement |
|---|---|---|
| AUD-001 Audit is synchronous with the decision | INV-001 | `middleware/audit.py`, `services/invocation.py` |
| AUD-002 An effect that occurred is recorded even if the response is not | | |
| AUD-003 No secret material in any observable output | INV-002, INV-008 | `mcp-audit-logger` redaction; trufflehog in CI |
| AUD-004 Human and machine recorded separately | | |
| AUD-005 Event schema is a contract | | |
| AUD-006 Denials and notices distinguishable, uniform to the caller | | |
| AUD-007 The audit path is bounded and cannot be weaponised | | |
| AUD-008 Append-only, enforced by the storage system | INV-011 | PostgreSQL grants (`V003`/`V009`) |
| AUD-009 Events are shipped off-box | INV-007 | archive bucket object lock |
| AUD-010 Retention bounded at both ends | INV-007 | object lock, ≥governance mode, 90d |
| AUD-011 Tamper-evidence is stated honestly | | |
| AUD-012 Security-relevant conditions are alertable | | |

AUD-007 is the counterweight to INV-001. Synchronous audit whose failure produces a 500 makes the
audit path a denial-of-service surface; the spec requires the bound, the invariant does not
mention it.

## credential-broker

| Requirement | Invariant | Enforcement |
|---|---|---|
| CRD-001 The agent never holds a backend credential | INV-013 | `credential_broker/{kms,approaches/approach_a}.py` |
| CRD-002 Plaintext credential lifetime is one call | INV-013 | `credential_broker/` |
| CRD-003 Encrypted under a per-identity key bound to context | INV-013 | per-user HKDF-SHA256 KEK keyed on the authenticated identity |
| CRD-004 Root of the key hierarchy has a stated trust boundary | INV-013 (partial) | master secret; this build is Shape A per `guide.md` §0 |
| CRD-005 Root key rotation without loss | | |
| CRD-006 Exactly one ciphertext codec | | |
| CRD-007 Typed injection modes resolved strictly | | |
| CRD-008 Token exchange where supported | | |
| CRD-009 Stored credentials are a first-class path | | |
| CRD-010 Resolution precedence fixed, never falls across identities | | |
| CRD-011 Stored credentials are not immortal | | |
| CRD-012 Broker actions audited and correlated | INV-013 | synchronous lifecycle audit |

CRD-004 is the requirement to *state* the boundary. INV-013 describes a master secret the platform
reads, which is Shape A: platform compromise discloses every stored credential. That is a valid
choice, and the requirement is that it be documented in those terms rather than described as
"protected by the secrets store".

## server-vetting

| Requirement | Invariant | Enforcement |
|---|---|---|
| VET-001 Day-one scan gate | INV-006 | `services/sbom.py`, `routers/tools.py::update_tool`, DB constraint |
| VET-002 Trust tier records what was vetted | | |
| VET-003 What cannot be vetted is recorded as unvetted | | |
| VET-004 Machine-readable inventory per server | INV-006 | signed per-tool SBOM |
| VET-005 Dependency vulnerability analysis, multiple sources | | |
| VET-006 Protocol-aware static analysis | | |
| VET-007 Approval pins an exact artifact | | |
| VET-008 Verdicts expire | | |
| VET-009 Blocking finding on an approved server is bounded | | |
| VET-010 Manifest drift detection | | |
| VET-011 Vetting is evidence, not enforcement | INV-005 | quarantine gate is the enforcement, independent of scan result |

## server-onboarding

| Requirement | Invariant | Enforcement |
|---|---|---|
| ONB-001 Servers enter quarantined | INV-005 | `services/invocation.py`, `routers/mcp_server.py` |
| ONB-002 Submitted material is untrusted input | | |
| ONB-003 Registration captures what later controls depend on | | |
| ONB-004 Discovery during quarantine is mediated | | |
| ONB-005 Approval is dual-control and records what it approved | INV-006 (partial) | release requires `server_registry` approved with scan passed |
| ONB-006 Build and deployment are pinned and fail closed | | |
| ONB-007 Verification gates release | | |
| ONB-008 Protocol contract machine-checkable and versioned | | |
| ONB-009 Re-quarantine always available and immediate | INV-005 | quarantine gate |
| ONB-010 Decommissioning is a defined state | | |

INV-006 records an open item directly relevant to ONB-005: there is no dedicated release
endpoint, no `released_by`/`released_at` columns, and no distinct release audit event. Release is
enforced inline in the generic PATCH path. ONB-005's requirement to record *what* was approved -
digest, verdict identifier, tier, surface snapshot - is not satisfiable through that path.

---

## Retired invariants

`INV-017` is cited above under `network-isolation` and remains current. No invariant has been
retired. Requirement IDs, once assigned, are never reused; see `README.md`.
