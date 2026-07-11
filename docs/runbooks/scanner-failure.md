# Runbook: Scanner-Worker Job Failure / Stuck Submission Scan

## Symptom

- A submission never leaves "scanning" state in the portal UI, or
  `server_registry.scan_status` stays `scan_running` indefinitely.
- A scan job's `scan_status` lands on `'error'` even though the repo looks
  fine.
- `queue_depth()` / dead-letter metrics show jobs piling up in `dead_letter`.

## Diagnosis

```bash
# Overall queue health — status counts (queued/running/completed/failed/dead_letter)
podman exec mcp-db psql -U mcp_app -d mcp_security -c \
  "SELECT status, COUNT(*) FROM scan_jobs GROUP BY status;"

# Anything actually dead-lettered? (never silently dropped — always visible here)
podman exec mcp-db psql -U mcp_app -d mcp_security -c \
  "SELECT job_id, server_id, github_url, job_type, attempts, max_attempts, last_error, updated_at
   FROM scan_jobs WHERE status = 'dead_letter' ORDER BY updated_at DESC LIMIT 20;"

# A specific server's job history
podman exec mcp-db psql -U mcp_app -d mcp_security -c \
  "SELECT job_id, status, attempts, max_attempts, last_error, claimed_by, claimed_at, heartbeat_at
   FROM scan_jobs WHERE server_id = '<server_id>' ORDER BY created_at DESC;"

# Is the worker process even alive / claiming jobs?
podman logs mcp-scanner-worker --tail 100

# Any jobs stuck 'running' with a stale heartbeat (worker crashed mid-job,
# no automatic timeout/reaper for this today — see gap note below)?
podman exec mcp-db psql -U mcp_app -d mcp_security -c \
  "SELECT job_id, status, claimed_by, heartbeat_at, now() - heartbeat_at AS age
   FROM scan_jobs WHERE status = 'running' ORDER BY heartbeat_at ASC;"
```

## Understanding the job lifecycle

`scan_jobs.status` transitions (per `scanner_worker/worker.py` and
`proxy/app/services/scan_queue.py`):

```
queued --(worker claims, FOR UPDATE SKIP LOCKED)--> running
running --(scan_engine.run_scan succeeds)--> completed
running --(exception during processing)--> queued (retry, attempts++)
                                          -> dead_letter (attempts >= max_attempts)
```

- The scanner-worker **never** writes `server_registry.scan_status` or
  `block` — it structurally lacks the DB grant (V063 migration). It only
  writes RAW findings to `scan_raw_results`. A **separate** process,
  `scan_evaluator` (`proxy/app/services/scan_evaluator.py`), is the *only*
  code path that reads raw results, applies policy, and sets
  `server_registry.scan_status` to one of `blocked` / `error` /
  `review_required` / `passed` (precedence: blocked > error >
  review_required > passed — worst-known status always wins).
- `scan_status = 'error'` specifically means the scan pipeline reported a
  `missing_tool: true` finding (a required scanner binary — e.g. semgrep,
  a dependency-audit tool — was unavailable in the worker container) with no
  blocking finding otherwise; this is a **fail-closed environment problem**,
  not a code-quality verdict on the submitted repo. Check
  `scan_raw_results.raw_findings` for `"missing_tool": true` entries and
  their `"file"`/`"line"` (empty for a missing-tool finding) to identify
  which tool was absent, then fix the worker image/toolchain.
- A dead-lettered job means the worker itself threw an exception (e.g. clone
  failure, timeout, crash) on every attempt up to `max_attempts` — check
  `last_error` for the actual exception message.

## Resolution

**Requeue a dead-lettered job** — there is no dedicated "retry" API endpoint
in this repo; requeue directly via the submission scan endpoint with
`force=true`, or manually via SQL if you need an exact resubmission of the
same job:

```bash
# Preferred: re-trigger via the existing submission/rescan pathway
# (enqueue_scan() with force=True bypasses the in-flight dedup check and
# always inserts a fresh row rather than returning the existing dead_letter one)
curl -s -X POST -H "Authorization: Bearer $ADMIN_TOKEN" \
  http://localhost:8000/api/v1/submissions/<server_id>/submit -d '{"force": true}'

# Or, if you specifically want to resurrect the exact same job row for
# forensic continuity, reset it back to queued (loses the dead_letter history
# in last_error unless you've already captured it above):
podman exec mcp-db psql -U mcp_app -d mcp_security -c \
  "UPDATE scan_jobs SET status = 'queued', attempts = 0, last_error = NULL,
   claimed_by = NULL, claimed_at = NULL, updated_at = now()
   WHERE job_id = '<job_id>';"
```

**Worker not claiming any jobs at all** — check the container is up and
restart it:
```bash
podman ps --filter name=mcp-scanner-worker
podman restart mcp-scanner-worker
```

**Missing-tool errors** — rebuild/patch the scanner-worker image to include
the missing tool, then requeue affected jobs (they will not self-heal by
retrying against the same broken image).

**Clone failures** — check `docs/runbooks/git-provider-setup.md` first (bad
host/token config is the most common cause), then
`docs/runbooks/private-cidr-allowlisting.md` if the target is self-hosted on
a private range.

## Verification

```bash
# Confirm the job completes and the server's scan_status resolves
podman exec mcp-db psql -U mcp_app -d mcp_security -c \
  "SELECT job_id, status, attempts, last_error FROM scan_jobs WHERE job_id = '<job_id>';"

podman exec mcp-db psql -U mcp_app -d mcp_security -c \
  "SELECT server_id, scan_status, updated_at FROM server_registry WHERE server_id = '<server_id>';"

# Queue depth should show the job moved out of dead_letter/queued into completed
make -f Makefile.lab lab-smoke   # or: curl proxy /health for a general sanity check
```

## Prevention / Related

- There is **no automatic reaper** for jobs stuck in `running` with a stale
  `heartbeat_at` (e.g. worker process killed mid-scan) in this repo today —
  this is a known gap; the diagnosis query above is the only current way to
  spot one. If you hit this, manually reset the row to `queued` as shown.
- `docs/runbooks/git-provider-setup.md` — most scan failures trace back to
  git host/token misconfiguration.
- `docs/runbooks/quarantine-release.md` — a `scan_status` other than
  `passed`/`not_applicable` blocks tool release from quarantine; fixing the
  scan is often the actual unblock needed for a stuck release request.
