# server-vetting - build guide (non-normative)

`spec.md` states what must be true. This covers a workable trust-tier enumeration, the scanner
toolchain, and the two things about vetting that are easy to overstate.

---

## 0. What vetting actually buys, and what it does not

Two honest statements to hold onto while building this:

**A scan is a timestamped statement about an artifact, not a property of a server.** It says:
these analyses, against this digest, at this time, found these things. Everything in `VET-008`
and `VET-011` follows from that sentence. A platform whose dashboard says "24 servers scanned"
without saying *when* and *what was scanned* has converted a timestamp into a property, which
is the error `VET-011`'s second scenario names.

**You cannot scan what you cannot obtain.** A server onboarded as a URL is a black box. You can
compare its advertised manifest against a snapshot, and that is genuinely useful, but it is not
a code scan and `VET-003` forbids reporting it as one. This is the requirement most likely to
be quietly dropped during implementation, because the alternative - a visible column saying
"not analysed" next to a third of your estate - is uncomfortable. That discomfort is the
correct signal.

---

## 1. A workable trust-tier enumeration (`VET-002`)

Tiers must be derived from what was vetted, and each must have stated consequences. A four-tier
set that satisfies `VET-002`:

| Tier | Basis | Consequences |
|---|---|---|
| `platform-built` | Source obtained, built by the platform from a pinned commit, full static analysis, inventory produced by the platform | Longest rescan interval; drift triggers re-audit; eligible for the higher integrity levels its content can carry |
| `artifact-pinned` | Built artifact obtained and pinned, analysed; source not available | Shorter rescan interval; drift triggers re-audit |
| `manifest-only` | Running endpoint supplied; only the advertised surface can be compared | Frequent manifest comparison; drift returns to quarantine automatically rather than raising an alert; content fixed at the lowest integrity level |
| `unvetted` | Verdict expired, rescan impossible, or tier unset | Not invocable |

The consequences column is what makes the tier real. `VET-002`'s second scenario forbids a tier
with no stated effects, and the reason is that tiers without consequences become a label
reviewers assign by feel, and then a field nobody reads.

Note the asymmetry in the drift row: a `manifest-only` server is the one you can least afford
to leave running through a change, precisely because you cannot inspect what changed. Alerting
is the weaker response and it belongs on the tiers where you have other evidence.

Tier raising needs dual control (`VET-002`, fourth scenario) because "just bump it to
platform-built" is otherwise the path of least resistance around every constraint above.

---

## 2. Toolchain

**Inventory.** Generate it yourself from the pinned artifact. `VET-004`'s second scenario is
specifically about not accepting a submitter-supplied inventory: a component list provided by
the party being vetted describes what they say is there. Common generators produce standard
formats from an image or a source tree; run one, store the output against the submission.

**Vulnerability data.** Two sources, per `VET-005`. In practice: one ecosystem-specific advisory
database for the language the server is written in, and one broad cross-ecosystem database.
They disagree more than you expect - different severities, different affected ranges, different
lag - and the disagreement is information for the reviewer, so surface both rather than merging
into one number.

`VET-005`'s third scenario matters operationally: an air-gapped or infrequently-updated scanner
produces confident clean verdicts against data from six months ago. Record the advisory data
version in the verdict, and alert when it goes stale.

**Static analysis.** Generic analysers will not find the protocol-specific problems. The rules
worth writing yourself:

- Instructions in tool descriptions, prompt templates and resource annotations, directed at the
  calling agent rather than at a human reader (`VET-006`, first scenario). This is the tool
  description attack and generic linters have no concept of it.
- Credential access patterns: reading environment variables that look like secrets, reading
  well-known credential file locations, reading cloud instance-metadata addresses.
- Outbound calls to addresses not in the server's declared allowance, which cross-checks
  `NET-006`.
- Schema fields that invite the agent to pass credentials as arguments.

**Scanner isolation (`VET-006`, second scenario).** You are running analysis over code
submitted by someone you do not trust. Build steps execute submitted code. Run it under the
same constraints `network-isolation` puts on backends: no egress beyond named sources, hardened
runtime profile, resource bounds. A scanner with a container-registry credential and unrestricted
egress is a better target than anything it scans.

---

## 3. Pinning that survives (`VET-007`)

Pin content, not names. A tag can be repointed at a different image; a branch moves; `latest`
is not a pin at all. `VET-007`'s fourth scenario refuses these outright, and the check is
mechanical: does the reference identify the bytes, or does it identify a label that resolves to
bytes?

`VET-007`'s third scenario is the one usually missing. The launch was correct; six weeks later
the workload has been restarted, rescheduled, or updated by something outside the platform. If
your only evidence is "we launched the right thing", you have evidence about the past. Verify
the running workload's digest against the pin on a schedule, and treat a mismatch as
re-quarantine rather than as a logging event.

---

## 4. Getting out of the pending state (`VET-009`)

A rescan finds a critical vulnerability in a server that thirty people use daily. Quarantining
it immediately is disruptive; leaving it approved is the decision nobody makes explicitly.

The mechanism that works is the same one `POL-011` uses for notify mode: the pending state
carries a stored expiry, and expiry escalates automatically. Not a reminder, not a ticket - a
field the platform acts on.

Set the expiry from the finding's severity, and record who is expected to decide. Then
`VET-009`'s third scenario keeps it visible: a server approved with an outstanding blocking
finding must not be counted among cleanly approved servers in any posture report. Otherwise the
number that leadership sees is unchanged while the risk is not.

---

## 5. Drift detection (`VET-010`)

Snapshot the whole advertised surface at approval, not just tool names. Descriptions and schemas
are where the interesting changes happen - a tool that keeps its name and acquires an
instruction in its description has changed in exactly the way that matters and in the way a
name-only comparison misses.

Include resources and prompts. `POL-002` made them mediated operations; they are equally
capable of carrying injected instructions, and a drift check that covers only tools has the
same blind spot the chokepoint used to have.

`VET-010`'s fourth scenario is the cheap high-value one: compare at invocation, not only on the
schedule. You already have the server's response in hand; checking it against the snapshot
costs a comparison and closes the window between a change and the next scheduled poll. A remote
server that changes its manifest and is caught on the next call is caught in seconds rather than
hours.

---

## 6. Checklist

- [ ] No release without a verdict; a failed scan is not a clean result - `VET-001`
- [ ] Trust tiers enumerated, each with stated consequences - `VET-002`
- [ ] Tier derived from what was vetted, not from the submitter's claim - `VET-002`
- [ ] Tier raising requires dual control - `VET-002`
- [ ] Servers vetted only at manifest level recorded as such and counted separately - `VET-003`
- [ ] Verdict enumerates which analyses ran, not a single pass flag - `VET-003`
- [ ] Inventory produced by the platform from the pinned artifact - `VET-004`
- [ ] Submitter-supplied inventory never accepted as equivalent - `VET-004`
- [ ] Two vulnerability data sources; disagreements surfaced, not merged - `VET-005`
- [ ] Advisory data version recorded in the verdict; staleness alertable - `VET-005`
- [ ] Protocol-specific rules for instruction-bearing descriptions and schemas - `VET-006`
- [ ] Scanner runs under the same isolation as a backend - `VET-006`
- [ ] Severity mapping is one definition; blocking severities stated - `VET-006`
- [ ] Pins identify content; mutable references refused - `VET-007`
- [ ] Running workload digest verified against the pin on a schedule - `VET-007`
- [ ] Verdicts carry an expiry; expired means unvetted, not approved - `VET-008`
- [ ] Inability to re-vet recorded rather than extending the verdict - `VET-008`
- [ ] Pending-decision state carries a stored expiry that escalates automatically - `VET-009`
- [ ] Servers with outstanding blocking findings excluded from clean counts - `VET-009`
- [ ] Approved snapshot covers descriptions and schemas, not just names - `VET-010`
- [ ] Snapshot covers resources and prompts, not just tools - `VET-010`
- [ ] Surface compared at invocation, not only on the schedule - `VET-010`
- [ ] No platform text describes a scanned server as safe or trusted - `VET-011`
- [ ] No runtime control relaxed on the basis of a vetting result - `VET-011`
