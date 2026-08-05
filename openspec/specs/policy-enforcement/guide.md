# policy-enforcement - build guide (non-normative)

`spec.md` states what must be true. This states how to make it true on the policy engines most
teams pick, and describes the three failure modes that survive a correct-looking policy.

---

## 0. The three ways this capability fails while looking healthy

**The engine answers "nothing" and you read it as "no objection".** This is the single most
common deny-by-default failure, and it is not a policy bug - it is an integration bug in the
code that reads the result. `POL-004` is written to close it: anything that is not an explicit
allow is a deny, including empty, null and undefined.

**Everything detects and nothing enforces.** Screening records matches. The taint floor
defaults to notify. `POL-013` is read as forbidding anything heuristic from blocking. The
result is a platform that produces an excellent audit trail of the attack that succeeded.
`POL-011` and the scoping paragraph in `POL-013` exist for exactly this, and it is worth
checking your deployment against them specifically, because each individual setting looks
defensible on its own.

**Mediation covers tools and nothing else.** The protocol is not only `tools/call`. Resource
reads return content into the session; prompt retrieval returns content into the session;
sampling lets a backend drive the client's model. A chokepoint that only sees tool calls is a
chokepoint with a documented bypass. `POL-002` and `POL-003`.

---

## 1. Open Policy Agent / Rego

### 1.1 The undefined-result problem (`POL-004`)

Rego rules that do not match produce **undefined**, not `false`. If your query asks for
`data.mcp.authz.allow` and no rule body succeeds, the response document has no `allow` key at
all. Code that does `if response.get("allow"): ...` denies correctly by accident; code that
does `if not response.get("deny"): ...` allows the entire policy failing to load.

Three things make this safe rather than lucky:

1. **Declare a default in the policy**: `default allow := false`. This turns undefined into an
   explicit `false` at the source.
2. **Still normalise on the client side.** Do not rely on the policy carrying the default - a
   bundle that fails to load produces the same undefined, and the default is inside the bundle
   that did not load. Treat "no `allow` key", "`allow` is not a boolean", and "`allow` is
   false" as one outcome: deny.
3. **Query a decision object, not a bare boolean.** Return `{allow, reasons, decision_id}` and
   deny when the object does not parse. This gives you `POL-014`'s reason codes and makes a
   malformed response structurally distinguishable from a deny.

Note that querying `data.mcp.authz` returns the whole document, which will be a `200` with a
body even when nothing evaluated. The HTTP status tells you the engine is alive, not that a
decision was made. Never treat `200` as an allow.

### 1.2 Deny-by-default in the policy itself (`POL-004`)

- `default allow := false` at the top of every package that produces a decision.
- No rule whose body can be satisfied without matching a specific principal and operation.
  A rule like `allow { input.roles[_] == "admin" }` is a wildcard allow with extra steps.
- Reason codes are separate from the decision: build `reasons` as a set, and let an empty
  reason set on a deny be a defect your tests catch. A deny with no reason is unauditable.

### 1.3 Timeouts and fail-closed (`POL-005`)

Set a request timeout on the call to the engine and treat expiry as a deny (`POL-005`, third
scenario). Without it, a policy with a pathological evaluation turns into an unbounded wait,
and the difference between "the platform denies" and "the platform stops answering" matters to
everyone above you.

Run the engine as a sidecar or local process, not as a shared remote service. A network hop in
the request path means every network incident is a total platform outage, because you fail
closed. Deny-by-default and a remote policy engine compose badly.

### 1.4 Bundles and provenance (`POL-006`)

OPA supports signed bundles: the bundle carries a signature over a manifest of file hashes,
and the engine verifies it before activation. Enable verification and make it the default
configuration, not an environment-specific flag - `POL-006` requires the default to be the
verifying one, because the failure mode of an opt-in is that one environment opted out.

Two operational details:

- Configure the engine to keep serving its last good bundle if a *new* bundle fails
  verification, and to serve nothing if it has no good bundle. Failing to no-policy is the
  correct fail-closed outcome given `POL-004`, but it is an outage, so alert on it.
- Key rotation (`POL-006`, third scenario): plan to trust two verification keys during
  rotation. If your only rotation path is "disable verification, swap the key, re-enable", you
  have a documented window where `POL-006` is off.

### 1.5 Input document (`POL-014`)

Build one document per call and deny if a required field is missing. Rego will happily
evaluate a policy against a document missing half its fields and return a confident answer,
because a comparison against an undefined field is simply undefined and the rule does not
match. That reads as a deny here, which is safe - but a *missing session identifier* silently
disabling a taint rule is not something you want to discover from the audit trail.

Validate the document against a schema before sending it. OPA can type-check policy against an
input schema at build time, which catches the reverse error: a policy referring to a field the
contract does not have.

Send argument *metadata* - names, types, lengths, hashes - not values (`POL-014`, last
scenario). Argument values in the policy input means argument values in the engine's decision
log, which is an audit-shaped credential leak.

---

## 2. Cedar

Cedar is a reasonable alternative and changes two things.

**Deny-by-default is structural.** Cedar's evaluation is explicitly deny-unless-permitted, and
forbid rules override permit rules. You get `POL-004`'s first scenario from the language rather
than from a `default` declaration. You still need `POL-004`'s second scenario handled in your
integration code - an engine that errors or returns nothing is not the language's concern.

**The schema is mandatory and that is an advantage here.** Cedar entity types and actions have
to be declared, which makes `POL-002`'s enumeration of the mediated surface a schema artifact
rather than a convention. A new protocol operation that is not in the schema cannot be
authorized, which is `POL-002`'s third scenario enforced by the tooling.

The trade: policy signing and distribution are not part of the engine the way OPA's bundle
mechanism is, so `POL-006` is yours to build - verify provenance before loading, and keep the
rotation path that does not require turning verification off.

---

## 3. Integrity levels and the taint floor (`POL-009`, `POL-010`, `POL-011`)

This is platform code, not policy-engine configuration. Getting it right is mostly about
where state lives.

### 3.1 Defining the levels (`POL-009`)

Keep the ordering short and total. A workable four:

| Level | What belongs here |
|---|---|
| `untrusted` | Any content originating outside the platform: backend tool output, resource content, fetched web content, sampling results, user-elicited input |
| `low` | Content from an approved backend whose vetting is current and whose source is internal |
| `normal` | Content the platform itself produced |
| `high` | Operator-supplied configuration and platform-signed data |

The default assignments matter more than the ordering. `POL-009` requires an unassigned source
to take the *lowest* level and an unassigned operation the *highest* requirement. That
combination is deliberately inconvenient: a newly onboarded server with no assignments is
unreachable from any tainted session, which is what forces the assignment to happen at
registration rather than being permanently deferred.

### 3.2 Where taint lives (`POL-010`)

On the session record from `IDN-011`, not on the connection and not in the proxy's memory.
Two consequences you need to design for:

- The write happens *before* the response is forwarded, and a failed write blocks the response
  (`POL-010`, first scenario). That means the taint store is in the request path and its
  latency is your latency. Co-locate it with the session store.
- `POL-010`'s fourth scenario - taint applies across a principal's concurrent sessions - is the
  one people implement last and it is the one that makes the control real. If taint is
  per-session and a principal can open a second session with the same credential, the floor is
  a suggestion.

### 3.3 Getting out of notify mode (`POL-011`)

Store the expiry alongside the mode. Not a comment, not a ticket - a field the platform reads.
Then:

- surface "in notify past expiry" wherever the platform reports its own posture, described as
  *detecting and permitting*
- default to enforce at the production tier, per `IDN-002`'s attested tier, so that a new
  production deployment is enforcing on day one and notify is the exception someone has to
  ask for

The reason this is a `SHALL` and not advice: a control in notify mode reports a clean audit
trail full of allow-with-notice events, and those read as successes on a dashboard. Nothing in
the system objects to staying there.

---

## 4. Verifying quarantined servers (`POL-008`)

The onboarding workflow needs to talk to a server that `POL-007` forbids talking to. The wrong
fixes are a second code path to backends, or a boolean that suspends quarantine.

The shape that works:

- A verification principal that exists only inside the platform, has no credential any external
  caller can present, and is rejected outright if it appears on an inbound request
  (`POL-008`, third scenario).
- An allowance keyed on that principal plus the specific server plus the specific operations
  the verification sequence performs. Not "any operation on a quarantined server".
- The same chokepoint, the same audit, a distinct reason code.
- The returned content never enters a session (`POL-008`, fourth scenario). This is the part
  that is easy to get wrong: if the discovered tool list flows into the same handling as a
  normal tool list, a hostile quarantined server has just written into your session state
  before anyone approved it.

---

## 5. Checklist

- [ ] Any result that is not an explicit allow is treated as a deny, in integration code - `POL-004`
- [ ] `default allow := false` present, and not relied on as the only defence - `POL-004`
- [ ] No policy rule can be satisfied without matching a specific principal and operation - `POL-004`
- [ ] A deny with no reason code fails a test - `POL-014`
- [ ] Request timeout set on policy evaluation; expiry denies - `POL-005`
- [ ] Policy engine local to the proxy, not a shared remote service - `POL-005`
- [ ] Provenance verification is the default configuration, not an opt-in - `POL-006`
- [ ] Two-key rotation path exists that never requires disabling verification - `POL-006`
- [ ] No-policy-loaded state alertable and distinct from ordinary denials - `POL-004`
- [ ] Mediated surface enumerated once; unenumerated operations denied - `POL-002`
- [ ] Resource and prompt content screened and integrity-assigned like tool output - `POL-002`
- [ ] Server-initiated sampling and elicitation mediated, screened, audited - `POL-003`
- [ ] Sampling results carry the requesting backend's integrity level - `POL-003`
- [ ] Integrity levels defined once, total ordering, criteria per level - `POL-009`
- [ ] Unassigned source defaults lowest; unassigned operation defaults highest - `POL-009`
- [ ] Levels assigned at registration; registration blocks without them - `POL-009`
- [ ] Taint written before the response is forwarded; write failure blocks it - `POL-010`
- [ ] Taint applies across a principal's concurrent sessions - `POL-010`
- [ ] Taint store unavailable denies - `POL-010`
- [ ] Notify mode carries a stored expiry the platform reads - `POL-011`
- [ ] Past-expiry notify reported as *detecting and permitting*, not as configured - `POL-011`
- [ ] Enforce is the production-tier default - `POL-011`
- [ ] Unscreenable content recorded as unscreened, not as clean - `POL-012`
- [ ] Screening documented as evadable detection, not as prevention - `POL-012`
- [ ] Verification principal unassumable from outside; attempts alertable - `POL-008`
- [ ] Verification probe scoped to the verification operations only - `POL-008`
- [ ] Probe results never enter a session - `POL-008`
- [ ] Argument metadata sent to the engine, not argument values - `POL-014`
- [ ] Decision inputs invalidated by event, not by expiry alone - `POL-015`
