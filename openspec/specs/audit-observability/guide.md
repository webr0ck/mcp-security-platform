# audit-observability - build guide (non-normative)

`spec.md` states what must be true. This covers append-only storage on PostgreSQL, retention on
object storage, and the two design problems that make this capability harder than it looks.

---

## 0. Two problems worth understanding before you build

**Synchronous audit makes the audit path a weapon.** `AUD-001` says an operation that cannot be
audited does not proceed. That is correct and it means anyone who can make your audit store
slow can deny your platform. It is worse than it first appears because rejected requests are
audited too (`AUD-001`, third scenario), so an unauthenticated flood produces audit load
without ever authenticating. `AUD-007` and `IDN-015` are the pair that fixes this: bound
ingress at the edge, and bound the audit work a single rejected request can cause. Building
either alone leaves the hole open.

**Auditing before the response is not auditing before the effect.** The natural reading of
"emit the event before returning the response" is satisfied by writing the event after the
backend has already done the thing. If the platform then dies, the backend transferred the
money and nothing recorded it. `AUD-002` splits this into intent-then-outcome. It costs a
second durable write per operation, which is real, and it is the difference between "we can
reconstruct what happened" and "we can reconstruct what we managed to finish".

---

## 1. Append-only on PostgreSQL (`AUD-008`)

Three roles, not one:

| Role | Capability on the audit table |
|---|---|
| writer | `INSERT` only |
| reader | `SELECT` only |
| migrator | schema changes, used by migrations, never by the application |

```sql
REVOKE ALL ON audit_events FROM PUBLIC;
GRANT INSERT ON audit_events TO app_writer;
GRANT SELECT ON audit_events TO app_reader;
```

The application connects as `app_writer`. It does not hold `UPDATE` or `DELETE`, so
`AUD-008`'s first scenario holds even when application code is compromised - the database
refuses, rather than the application declining to ask.

Details that undo this if missed:

- **Table owner.** The owning role can always modify the table regardless of grants, and can
  drop the triggers below. The application role must not own the table. Migrations run as the
  owner; the application never does.
- **Superuser.** Outside the boundary entirely. Say so in the `AUD-011` documentation rather
  than pretending otherwise.
- **`TRUNCATE`** is a separate privilege from `DELETE`. Revoking `DELETE` and leaving
  `TRUNCATE` grantable leaves the whole table removable.
- **Default privileges.** New tables created later can pick up grants you did not intend.
  Set `ALTER DEFAULT PRIVILEGES` deliberately.
- **Row-level security** does not help here and is often reached for by mistake. RLS restricts
  which rows a role sees or writes; it does not stop a role with `UPDATE` from updating the
  rows it can see.

Add a rule or `BEFORE UPDATE OR DELETE` trigger that raises, as defence in depth. It is not the
control - grants are - but it catches the case where someone grants `UPDATE` during a debugging
session and forgets to revoke it.

For `AUD-002`, intent and outcome are two rows sharing the correlation identifier, not one row
updated twice. Updating is precisely what the writer role cannot do, which is the design
working rather than an obstacle.

Reconciliation query for `AUD-002`'s third scenario: intent rows with no outcome row sharing
their correlation identifier, older than your operation timeout. Run it on a schedule and alert
on a non-zero count. Without this the two-phase write is bookkeeping nobody reads.

---

## 2. Retention on object storage (`AUD-010`)

Object lock with a retention period is the mechanism. Two modes exist in most implementations
and they are not equivalent:

- **Governance-style retention** can be overridden by a caller holding a specific elevated
  permission. Useful, and it is *not* write-once storage. `AUD-010`'s second scenario and
  `AUD-011` both require you to say so.
- **Compliance-style retention** cannot be shortened or removed by anyone, including the
  account root, until the period elapses. This is what "cannot be shortened or bypassed by the
  platform's own credentials" actually means.

Choose deliberately. Compliance mode means a misconfigured retention period is unfixable and
you pay storage for it - that is the cost of the guarantee, and if you are not willing to pay
it, you are in governance mode and should describe your trail accordingly.

Bucket configuration:

- Versioning on, which object lock requires.
- Retention default set at the bucket, and also set explicitly per object - a bucket default
  applies to new objects and does not retroactively protect what is already there.
- The platform's own write identity must not hold the permission that bypasses governance
  retention. If it does, the retention is decorative from the threat model's perspective.
- A lifecycle rule for disposal at the end of the period (`AUD-010`, third scenario). Object
  lock stops early deletion; nothing removes the object afterwards unless you configure it.
  "Retained forever" is a data-protection finding, not extra safety.

Legal hold is a separate flag from retention and is the right mechanism for `AUD-010`'s fourth
scenario, because it suspends disposal without changing the retention period. Record who placed
it, in the audit trail, using the same append-only path.

---

## 3. Redaction at the sink (`AUD-003`)

`AUD-003`'s third scenario is the one that determines whether this holds over time. Redaction
implemented as "remember to scrub before you log" fails at the first new component. Implement
it as a processor on the logging and event pipeline, so a component that emits a credential is
redacted without having opted in.

What to cover:

- Structured event fields, by field name and by value pattern.
- Exception messages and stack traces, which is where credentials most often escape - a
  connection string in a driver error, a token in a request-echo.
- Metric labels and trace attributes. Easy to forget; a high-cardinality label carrying a token
  is a leak with a long retention.
- Backend output (`AUD-003`, last scenario). You want to record *that* a credential pattern
  appeared without recording the value.

Argument handling: store names, types, lengths, and a keyed hash of the value. The key matters -
an unkeyed hash of a short or low-entropy argument is reversible by guessing, which turns your
"hashed" audit trail back into a plaintext one.

---

## 4. Correlation (`AUD-005`)

Generate the correlation identifier at the edge, on the platform, and use it for every event in
the operation: identity decision, entitlement decision, policy decision, broker action, intent,
outcome.

`AUD-005`'s second scenario is a small thing that matters: if a caller supplies a trace
identifier, record it in its own field and do not adopt it. A caller who can choose the
correlation identifier can collide two operations deliberately, and your incident
reconstruction becomes something they influence.

Do not reconstruct sequences by timestamp. Clocks are the subject of `IDN-005` for a reason, and
two events written in the same millisecond have no order.

---

## 5. Alerting on absence (`AUD-012`)

The alerts that fire on events are the easy half and every deployment has them. `AUD-012`'s
fourth scenario asks for the other half: alert when a control that normally produces events
stops. A screening component that crashed produces no matches, which looks exactly like a quiet
week.

Practical form: for each control that emits, record its last-emission time and alert on a gap
longer than its normal quiet period. Low effort, and it is the only signal that catches a
control silently removed from the request path.

Pair it with `POL-011`: posture reporting must show detect-and-permit controls as unenforced.
A dashboard that counts an allow-with-notice as a working control is how a platform arrives at
"everything is green" while permitting the thing it detects.

---

## 6. Checklist

- [ ] Every mediated operation and every rejection audited, including non-tool operations - `AUD-001`
- [ ] Audit write failure blocks the result - `AUD-001`
- [ ] Intent event durable before the upstream call; failure blocks the call - `AUD-002`
- [ ] Intent and outcome are two rows, not one row updated - `AUD-002`
- [ ] Scheduled reconciliation of intent-without-outcome, alerting on non-zero - `AUD-002`
- [ ] Writer role holds `INSERT` only; `UPDATE`, `DELETE`, `TRUNCATE` all absent - `AUD-008`
- [ ] Application role does not own the audit table - `AUD-008`
- [ ] Reader and writer identities separate - `AUD-008`
- [ ] Schema changes run as a distinct identity and are themselves recorded - `AUD-008`
- [ ] Retention mode chosen deliberately; bypassability documented - `AUD-010`, `AUD-011`
- [ ] Write identity does not hold the retention-bypass permission - `AUD-010`
- [ ] Retention set per object, not only as a bucket default - `AUD-010`
- [ ] Disposal at end of retention configured; not retained by omission - `AUD-010`
- [ ] Legal hold available and its placement audited - `AUD-010`
- [ ] Redaction runs at the sink, not per call site - `AUD-003`
- [ ] Exception messages, metric labels and trace attributes covered - `AUD-003`
- [ ] Argument hashes are keyed - `AUD-003`
- [ ] Correlation identifier generated by the platform; caller-supplied one kept separate - `AUD-005`
- [ ] Timestamps from the platform, subject to clock discipline - `AUD-005`
- [ ] Audit work per rejected request bounded, paired with ingress limits - `AUD-007`
- [ ] Durability point stated wherever buffering exists - `AUD-007`
- [ ] Reason codes are one enumeration; no denial without one - `AUD-006`
- [ ] Caller-facing responses uniform across reason codes - `AUD-006`
- [ ] Absence-of-events alerting in place per control - `AUD-012`
- [ ] Posture reporting shows detect-and-permit controls as unenforced - `AUD-012`
- [ ] No platform text calls the trail immutable, tamper-proof or write-once - `AUD-011`
