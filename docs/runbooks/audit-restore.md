# Runbook: Audit Event Investigation / Restore

## Symptom

- An investigation needs audit events older than the live retention window
  (rows no longer in `audit_events`).
- Someone asks "prove this row was never modified" during an incident
  post-mortem or compliance audit.
- The nightly archival job appears to have stopped running (no new
  `audit-events/YYYY/MM/DD/*.jsonl` objects in MinIO).

## How archival actually works (read before assuming pg_cron)

There are **two** archival mechanisms referenced in this repo's history —
know which one is live:

1. **Active mechanism**: `observability/compliance-checker/checker.py::
   archive_old_audit_events()` (Python, async), scheduled entirely by
   `observability/compliance-checker/entrypoint.py`'s own in-process cron
   parser (5-field cron, default `COMPLIANCE_CRON_SCHEDULE="0 2 * * *"` =
   02:00 UTC daily). No pg_cron, no system cron, no root access required —
   runs as the compliance-checker container's own non-root process (UID
   1001), and also runs once immediately on container startup so a fresh
   deploy gets a baseline pass. Steps:
   1. Selects `audit_events` rows older than the retention cutoff.
   2. Serializes them to JSONL.
   3. Uploads the JSONL to the MinIO **compliance-archive** bucket
      (`MINIO_COMPLIANCE_ARCHIVE_BUCKET`, default `compliance-archive`) at
      key `audit-events/<YYYY>/<MM>/<DD>/<run_id>.jsonl`, with S3 Object
      Lock (`ObjectLockMode` = `COMPLIANCE` or `GOVERNANCE`,
      `MINIO_OBJECT_LOCK_MODE` env, default falls back to `GOVERNANCE` on an
      invalid value) and a `retain_until` date
      `MINIO_RETENTION_DAYS` days out — this is the actual WORM guarantee
      (INV-007), independent of the Postgres immutability trigger.
   4. Copies the same rows into the `audit_events_archive` **table**
      (idempotent — `ON CONFLICT DO NOTHING`).
   5. **Only deletes** from live `audit_events` if
      `ENABLE_AUDIT_DELETE_AFTER_ARCHIVE=1` **and** the delete happens
      **after** the MinIO upload succeeds — if MinIO is down, rows stay in
      `audit_events` rather than being lost. This is deliberately
      conservative: the default is to accumulate archive copies, not race
      ahead of a confirmed durable copy.
2. **Legacy/optional SQL path**: `infra/db/migrations/V005__retention_policy.sql`
   defines a `plpgsql` function of the **same name**
   (`archive_old_audit_events(p_retention_days, p_batch_size)`) that moves
   rows directly from `audit_events` to `audit_events_archive` in-DB, and
   wires it to `pg_cron` **if the extension is available** (falls back to
   a documented manual `psql` crontab line if not — see the migration's own
   comment block for the exact `0 1 * * * psql ... "SELECT
   archive_old_audit_events();"` line). This is a DB-native alternative to
   the same job; don't assume both are running in the same environment —
   check which one is actually configured before troubleshooting "why
   didn't archival run."

## Diagnosis

```bash
# Is the compliance-checker container alive and on schedule?
podman logs mcp-compliance-checker --tail 100 | grep -i archiv

# Live audit_events row count / oldest row (retention window health)
podman exec mcp-db psql -U mcp_app -d mcp_security -c \
  "SELECT count(*), min(event_ts), max(event_ts) FROM audit_events;"

# Archive table row count
podman exec mcp-db psql -U mcp_app -d mcp_security -c \
  "SELECT count(*), min(event_ts), max(event_ts) FROM audit_events_archive;"

# Confirm Object Lock is actually enabled on the MinIO bucket (INV-007 check
# the checker itself runs at startup — verify_object_lock_startup)
podman exec mcp-minio mc retention info local/compliance-archive 2>/dev/null \
  || podman logs mcp-compliance-checker --tail 200 | grep -i "object.lock"

# List archived JSONL objects for a given day
podman exec mcp-minio mc ls local/compliance-archive/audit-events/2026/07/07/
```

## Resolution — querying/restoring events

**Events still in the live table or the DB archive table** — query directly:
```bash
podman exec mcp-db psql -U mcp_app -d mcp_security -c \
  "SELECT event_id, event_ts, client_id, tool_name, outcome, request_id
   FROM audit_events_archive
   WHERE event_ts BETWEEN '2026-01-01' AND '2026-02-01'
   ORDER BY event_ts;"
```

**Events only in MinIO JSONL (already archived + deleted from Postgres, if
`ENABLE_AUDIT_DELETE_AFTER_ARCHIVE=1` is set)** — pull and grep/jq the
object:
```bash
podman exec mcp-minio mc cp local/compliance-archive/audit-events/2026/01/15/<run_id>.jsonl /tmp/
cat /tmp/<run_id>.jsonl | jq 'select(.client_id == "<client>")'
```

**"Restoring" a deleted live-table row** means re-inserting it from the
JSONL/archive-table copy — note `audit_events` itself has NO update/delete
path available to any application role (see immutability guard below), so a
"restore" is always an `INSERT`, never an update-in-place, and should be
treated as a DBA-approved, out-of-band operation, not a routine one.

## The append-only / immutability guarantee

`infra/db/migrations/V003__db_roles.sql` installs
`fn_audit_events_immutability_guard()` as a `BEFORE UPDATE OR DELETE`
trigger (`trg_audit_events_immutability`) on `audit_events`, and a mirrored
`fn_audit_archive_immutability_guard()` /
`trg_audit_events_archive_immutability` trigger on `audit_events_archive`.
Both **unconditionally raise an exception** (`ERRCODE = 'insufficient_privilege'`)
on any UPDATE or DELETE, regardless of which role executes it — this is
defense-in-depth on top of the fact that `proxy_app` only has INSERT (no
UPDATE/DELETE) on `audit_events`, and `compliance_checker_app` only has
SELECT. Physically removing/altering an archived row requires a DBA
connecting as a superuser role and **disabling the trigger** first — an
action that is itself logged at the OS/Postgres log level, and is
explicitly called out in `V005__retention_policy.sql`'s comments as
requiring out-of-band approval, never a routine operation.

## Verification

```bash
# Confirm you cannot UPDATE/DELETE as the app role (expected to fail loudly)
podman exec mcp-db psql -U mcp_app -d mcp_security -c \
  "DELETE FROM audit_events WHERE event_id = '<any-id>';"
# ERROR: audit_events is append-only. UPDATE and DELETE are prohibited...

# Confirm archived events are retrievable and match the live/archive-table copy
diff <(podman exec mcp-db psql -U mcp_app -d mcp_security -tAc \
  "SELECT event_id FROM audit_events_archive WHERE event_ts::date='2026-01-15' ORDER BY event_id") \
  <(cat /tmp/<run_id>.jsonl | jq -r .event_id | sort)
```

## Prevention / Related

- Never disable the immutability triggers outside a DBA-approved,
  documented exception — this is the platform's core tamper-evidence
  guarantee.
- `docs/runbooks/incident-triage.md` — the `audit_events` table is one of
  the first places to look during any investigation.
- If you find `ENABLE_AUDIT_DELETE_AFTER_ARCHIVE=1` is unset in an
  environment where storage growth on `audit_events` is a real concern,
  that's expected/conservative-by-default, not a bug — confirm MinIO/Object
  Lock health before ever considering enabling it.
