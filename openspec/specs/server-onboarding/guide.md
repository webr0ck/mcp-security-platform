# server-onboarding - build guide (non-normative)

`spec.md` states what must be true. This covers the state machine, the verification path that
looks contradictory until you see the exception, and the two places onboarding leaks.

---

## 0. The contradiction and its resolution

Read `ONB-001` and `ONB-007` together and they look unbuildable: a quarantined server permits no
operation to any principal, yet verification requires invoking an operation on a quarantined
server.

The resolution is `POL-008`, and it is worth stating plainly because the tempting fix is the
wrong one. The tempting fix is a bypass - a code path in the verifier that talks to the backend
directly, skipping the enforcement point. That gives you a second, unaudited, unpolicied route
to every backend, built by you, in the one component that talks to servers nobody has approved
yet. It is the single worst thing you can build in this platform.

What `POL-008` requires instead:

- The verification call goes through the **same** enforcement point as every other call.
- It carries a **verification principal** that no external caller can obtain or assume. It is not
  an admin account, not a service account with a password anyone can hold. It exists only inside
  the verification path.
- Policy has an explicit rule: this principal, on this server, during this state, for these
  operations. Everything else still denies.
- The results never enter a session (`ONB-004`, second scenario). A discovered surface is
  evidence for a reviewer, not a capability an agent can now reach.

If you cannot express "principal X may do Y only while the server is in state Z" in your policy
language, fix that before building verification. Every workable policy engine can.

---

## 1. The state machine (`ONB-001`)

Make transitions a single table, not conditionals scattered through handlers. `ONB-001`'s third
scenario is specifically about this: onboarding is where checks get duplicated, and duplicated
checks drift.

A workable set:

| State | Reachable? | Leaves by |
|---|---|---|
| `submitted` | no | analysis completing, or rejection |
| `vetted` | no | human approval (`ONB-005`), or rejection |
| `approved` | no | build and launch (`ONB-006`) |
| `verifying` | no, except the `POL-008` path | verification passing or failing |
| `active` | yes | re-quarantine (`ONB-009`), decommission (`ONB-010`) |
| `quarantined` | no | re-verification, or decommission |
| `decommissioned` | no | nothing |

Two properties to enforce in the table itself rather than in prose:

- **Only one state is reachable.** Any check of the form "is this server usable" resolves to a
  single equality against `active`. If it becomes a set membership test, someone will add to the
  set.
- **No timed transition ever increases reachability.** Timers may move a server to
  `quarantined` (`VET-008`, `VET-009`). No timer may move it toward `active`. `ONB-001`'s second
  scenario exists because the alternative - a submission that becomes approved through inaction -
  is the shape most workflow engines produce by default when you add a timeout.

---

## 2. Registration is where later capabilities break (`ONB-003`)

Every field `ONB-003` demands exists because something downstream fails silently without it:

| Captured at registration | Fails without it |
|---|---|
| Injection mode and its credential source | Uniform "credential not provisioned" at first invocation, investigated as a broker bug - see `credential-broker/guide.md` §4 |
| Content integrity level, operation required levels (`POL-009`) | Taint enforcement has nothing to compare and permits everything, or denies everything |
| Trust tier (`VET-002`) | Drift response has no defined consequence |
| Declared egress allowances | `NET-006` has no allowlist to enforce, so it enforces nothing |
| May-initiate flag (`ENT-004`) | Server-initiated operations either all deny or all permit |

Refuse registration on any unset value rather than defaulting. The defaults look harmless field
by field and are catastrophic together: a server registered with no integrity level, no tier and
no egress allowance is a server every control treats as unconstrained.

`ONB-003`'s third scenario is the maintenance case. When you add a capability that needs a new
registration field, existing rows will not have it. Surface them as incomplete. The failure mode
is a migration that backfills a permissive value across the whole estate in one statement, and
nobody ever revisits it.

---

## 3. Approval (`ONB-005`)

**Dual control is about the human, not the account.** `ENT-005` resolves machine principals to
their owning human, and onboarding is the place that check matters most: a submitter who owns
the automation account that also holds the approver role has self-approval without ever
appearing to. Do the resolution before the comparison.

**Record what was approved, not that approval happened.** `ONB-005`'s second scenario lists the
fields, and the reason for each is that they are the things that can change underneath the
decision:

- The pinned digest - because a tag can be repointed (`VET-007`).
- The verdict identifier - because a rescan produces a new verdict (`VET-008`).
- The tier - because tiers can be raised (`VET-002`).
- The surface snapshot - because a remote server can change its manifest (`VET-010`).

An approval that records only "approved by A at time T" cannot answer the only question that
matters during an incident: was the thing running the thing that was approved.

`ONB-005`'s third scenario follows directly. When any referenced evidence is superseded, the
approval does not carry over. This is unpopular in operation - it means a routine rescan can
require re-approval - so tune it by tier and by whether the verdict changed materially, but do
not let it degrade to "the approval is on the server, not on the evidence".

---

## 4. Verification (`ONB-007`, `ONB-008`)

Four checks, in order, all through the `POL-008` path:

1. **Reachable.** The address responds at all.
2. **Surface discovery.** It enumerates tools, resources and prompts. This output becomes the
   `VET-010` snapshot.
3. **Operation probe.** One real operation completes end to end. This is the check that catches
   the interesting failures - credential injection wired to the wrong mode, a backend that
   enumerates fine and rejects every call, network policy that permits the handshake and blocks
   the request body.
4. **Protocol contract.** Responses validate against your schema.

The probe needs a bound (`ONB-007`, third scenario). A verifier that can invoke any operation on
a quarantined server is a general-purpose backdoor with a workflow wrapped around it. Restrict it
to operations the server declares as read-only, or to a designated health operation, and refuse
to probe anything else. If a server has no safe probe target, record that rather than widening
the verifier.

**Both onboarding paths use the same code.** `ONB-007`'s fourth scenario exists because the
URL-supplied path is the one where checks get skipped - there is no build, so the build-adjacent
checks feel inapplicable, and skipping spreads from there. Where a check genuinely cannot run,
record its absence per `VET-003`. Do not branch the verification function.

**The contract check reports rather than aborts** (`ONB-008`, first scenario). A reviewer looking
at a failed onboarding wants every violation at once. A check that stops at the first one turns
one review cycle into five.

Version the contract (`ONB-008`, second and third scenarios). Protocol revisions change what is
valid, and a server validated against an older revision has not been validated against the
current one. Store the version on the server record so raising the pin produces a list rather
than an assumption.

---

## 5. Re-quarantine and the in-flight case (`ONB-009`)

Re-quarantine is the incident response control, so latency matters. Whatever caches a server's
state must be invalidated on the transition, not left to expire. If your enforcement point holds
a five-minute cache, re-quarantine takes five minutes, and that is the number to put in the
runbook rather than "immediate".

`ONB-009`'s third scenario is the honest one. Operations in flight when the state changes will
sometimes complete. Do not build elaborate abort machinery for this - just make sure the audit
record distinguishes them, so an incident timeline shows what completed after containment rather
than implying containment failed.

Automatic re-quarantine (`VET-008`, `VET-009`, `VET-010`) matters more than the manual path in
practice, because the manual path only fires when someone already knows there is a problem.

---

## 6. Decommissioning (`ONB-010`)

The failure here is deletion. Someone removes a registration row and:

- Entitlement grants naming the server remain, referencing nothing.
- Stored credentials scoped to it remain, unowned and unreviewed.
- The workload keeps running, now unmediated by the registry that no longer knows about it.
- Its audit history is gone along with the row.

Make decommissioning a state with a defined sequence, and run the revocations before stopping the
workload rather than after.

**Identifier reuse** (`ONB-010`, second scenario) is the same class of bug as principal
identifier reuse in `IDN-010`. A stale grant naming `payments-server` becomes a live grant on a
different server the moment someone registers that name again. Use identifiers that are never
reissued and keep the human-readable name as a separate, non-authoritative label.

---

## 7. Checklist

- [ ] Submission state permits no operation to any principal, including administrators - `ONB-001`
- [ ] No timer or timeout moves a server toward reachable - `ONB-001`
- [ ] Permitted transitions are one table, not scattered checks - `ONB-001`
- [ ] Exactly one state is reachable; the check is an equality, not a set test - `ONB-001`
- [ ] Submitted addresses fetched under the egress controls - `ONB-002`
- [ ] Submitted names and descriptions screened as potentially instruction-bearing - `ONB-002`
- [ ] Analysis builds run under backend isolation with no platform credential - `ONB-002`
- [ ] Registration refused with injection mode, integrity levels, tier, egress or initiate flag unset - `ONB-003`
- [ ] Mode-versus-source mismatch rejected at registration, not at first invocation - `ONB-003`
- [ ] Registrations missing a newly required field surfaced as incomplete, not backfilled permissively - `ONB-003`
- [ ] Quarantine discovery traverses the enforcement point under the verification principal - `ONB-004`
- [ ] Verification principal is not obtainable by any external caller - `ONB-004`
- [ ] Discovery results never enter a session - `ONB-004`
- [ ] Self-approval blocked after resolving machine principals to owning humans - `ONB-005`
- [ ] Approval records digest, verdict id, tier and surface snapshot, not just approver and time - `ONB-005`
- [ ] Superseded evidence invalidates the approval rather than carrying over - `ONB-005`
- [ ] Build refused without an approved digest - `ONB-006`
- [ ] Launch never constructed from a state that does not permit it - `ONB-006`
- [ ] Partial runtime profile fails the launch rather than reducing it - `ONB-006`
- [ ] All four verification checks run; any failure keeps the server unreachable - `ONB-007`
- [ ] Operation probe bounded to declared-safe operations - `ONB-007`
- [ ] Built and URL-supplied paths share one verification function - `ONB-007`
- [ ] Contract violations all reported in one report, not first-failure abort - `ONB-008`
- [ ] Contract version stored per server; raising the pin produces a list - `ONB-008`
- [ ] Re-quarantine invalidates caches rather than waiting for expiry - `ONB-009`
- [ ] Automatic re-quarantine wired to verdict expiry, pending expiry and drift - `ONB-009`
- [ ] Operations completing after re-quarantine distinguishable in audit - `ONB-009`
- [ ] Decommissioning revokes grants and credentials before stopping the workload - `ONB-010`
- [ ] Identifiers never reissued; human-readable name is a separate label - `ONB-010`
- [ ] Audit and approval history survives decommissioning - `ONB-010`
