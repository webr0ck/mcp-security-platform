# Acceptance-Suite Findings — 2026-07-05

Product bugs surfaced while building/running the AT0–AT3 acceptance suite
(`lab/tests/acceptance/`). Each was kept as a red/xfail test, not papered over.
Owner will fix separately. Run that surfaced them:
`lab/tests/acceptance/results/20260705T130535Z/`.

Confidence key:
- **Confirmed** — root cause traced directly in source by inspection.
- **Reproduced** — observed failing at runtime; exact root cause plausible but not fully traced.

---

## F-1 — `entra_client_credentials` injection mode cannot be provisioned via the admin API
**Severity:** High · **Confidence:** Confirmed (API gap) + Reproduced (credential-store decrypt) · **Blocks:** m365-graph invocation (AT1 `test_entra_client_credentials_m365_graph`, AT2 m365 tests)

**Confirmed part —** `proxy/app/routers/admin_credentials.py:296`
```python
valid_modes = ("none", "service", "user", "service_account", "oauth_user_token")
```
This list omits both `entra_client_credentials` and `kc_token_exchange`. The
`update_injection_mode` handler rejects those two modes with `400 VALIDATION_ERROR`,
so a tool that the dispatcher *does* support in those modes can never have its
`injection_mode` set to them through the only admin write path.

**Reproduced part —** the dispatcher's entra path
(`proxy/app/credential_broker/dispatcher.py:~560`) retrieves the credential via
`retrieve_credential(user_sub="__service__", service="entra", owner_type="service", …)`,
while the admin write path (`admin_credentials.py:164-177`) encrypts with
`approach_a.encrypt(secret, user_sub, master, owner_type=…)`. At runtime the m365
path failed to decrypt (`InvalidTag`), consistent with the two paths disagreeing on
the encryption envelope / AAD binding. Confirm the exact envelope mismatch before fixing.

**Fix direction:** add `entra_client_credentials` (and `kc_token_exchange`) to
`valid_modes`; then make the admin encrypt path and the dispatcher decrypt path
agree on owner scope + AAD for service-owned Entra credentials. Add a positive
provisioning test once fixed.

---

## F-2 — pip-audit `block_on: critical` can never block a submission
**Severity:** High · **Confidence:** Confirmed · **Location:** `proxy/app/services/submission_scanner.py:~405`

```python
severity_order = ["low", "medium", "high", "critical"]
block_threshold = severity_order.index(block_on)   # 3 for "critical" (the default)
...
sev = vuln.get("fix_versions", [""])[0] and "high" or "medium"
```

Every dependency vulnerability is mapped to **"high" or "medium"** only — the code
can never emit `"critical"`. With the shipped default `dependency_audit.block_on: critical`
(`scan-config.yaml`), `sev_idx >= block_threshold` is never true, so **no CVE of any
real severity blocks a submission** through the dependency-audit scanner. The gate
looks configured but is a no-op.

Also note `except (json.JSONDecodeError, Exception)` on the parse — `Exception`
swallows everything, so a pip-audit crash silently yields zero findings.

**Fix direction:** map real severity from pip-audit output (use the advisory/CVSS
severity, not `fix_versions` presence); narrow the except clause. Add a fixture
with a known-critical CVE that must set `scan_status='failed'`.

---

## F-3 — a once-invoked tool name can be neither reused nor hard-deleted
**Severity:** Medium · **Confidence:** Confirmed (constraint) + Reproduced (delete deadlock) · **Location:** `infra/db/migrations/V001__initial_schema.sql:84`

```sql
CONSTRAINT tool_registry_name_version_unique UNIQUE (name, version)
```

The uniqueness is a plain constraint with **no `WHERE deleted_at IS NULL`** partial
predicate. Soft-deleted rows keep occupying `(name, version)`, so re-registering a
tool under a name that was ever used collides. Hard-deleting the stale row instead
was observed to fail: `audit_events`' append-only trigger blocks the FK's
`ON DELETE SET NULL`, so the row can't be removed either. Net: the name is stuck.

**Fix direction:** replace the constraint with a partial unique index
(`CREATE UNIQUE INDEX … ON tool_registry (name, version) WHERE deleted_at IS NULL`);
decide an audit-preserving path for FK nulling (e.g. defer/allow the trigger for
`SET NULL`, or repoint the FK). Migration + test for register→soft-delete→re-register.

---

## F-4 — concurrent submission scans can hang indefinitely
**Severity:** Medium (availability) · **Confidence:** Reproduced, not root-caused · **Location:** `proxy/app/services/submission_scanner.py` (`scan_submission` background task)

Two `scan_submission()` background tasks running concurrently hung indefinitely;
each step completes quickly when run serially. Recovery required restarting the
`mcp-proxy` container. Likely a shared-resource contention (DB pool exhaustion,
a lock, or a bounded subprocess/semaphore around trufflehog/mcp_checker/pip-audit),
but not yet traced.

**Fix direction:** reproduce with two overlapping submits, capture task stacks
(`py-spy dump` on the proxy), check for pool/semaphore starvation and whether the
scanners share a non-reentrant resource. Bound concurrency explicitly if needed.

---

## Not a product bug — lab-tickets xfail
`kc_token_exchange` / lab-tickets-query xfails (AT1/AT2) trace to a **lab-seeding gap**:
no `server_registry` row for `lab-tickets-query`. Re-seed fix is documented in
`README.md`. No code change required.

---

## T5 — taint-floor live verification (2026-07-11, VERIFY loop, one-off manual run)

Article 4 (`Vault/00_AI/mcp-security-platform-launch/article_4_signed-trust-envelope_v3.md`)
claims the taint floor is "Built and tested" but cites only unit/adversarial
tests; no acceptance test exercised it live and `TAINT_FLOOR_ENABLED` defaults
to `False` in `proxy/app/core/config.py`. This lab's `.env.lab` already sets
`TAINT_FLOOR_ENABLED=true` (line 198) — no flag flip or restart was required;
`podman exec mcp-proxy env` confirmed it live before starting.

**Steps run against the live stack** (not added as a permanent acceptance test
in this pass — a manual, reproducible one-off; commands below are the record):

1. `UPDATE server_registry SET trust_tier=0 WHERE name='lab-echo';` — made an
   already-approved, already-invokable server temporarily untrusted (stands in
   for "register a trust_tier=0 server").
2. Invoked `ping` on `lab-echo` through the real gateway as alice → `200`,
   real echo response. Restored `trust_tier=2` immediately after.
3. Confirmed the taint write landed in Redis:
   `GET mcp_taint:244e5ee0cc237be3` → `1`, `TTL` → `3590` (~1h, matches the
   article's "up to an hour" claim). Key = `mcp_taint:` +
   `sha256("alice@corp")[:16]`, per `taint_store.py`.
4. Invoked `grafana-query.list_datasources` (credential-injecting, so its
   effective `required_integrity` is bumped to ≥1 per `taint_floor.py`) as the
   now-tainted alice → `200` with body text `"Access denied: session
   restricted by trust policy"` (the friendly HTTP-200 wrapper — same class
   documented elsewhere in this file). `audit_events` for that call:
   `outcome=deny`, `opa_reasons=["taint_floor:required_integrity=1"]`,
   confirming the deny fired for the exact reason the article claims, not a
   coincidental other gate.
5. Cleaned up: `DEL mcp_taint:...` in Redis; `trust_tier` was already restored
   to 2 in step 2.

**Verdict: steps 1–3 of the article's 4-step experiment are CONFIRMED live**
against the running lab, with the flag already on (not a synthetic/simulated
run).

**Step 4 (Redis-failure fail-closed) — NOT executed live.** Stopping/killing
`mcp-redis` would have broken every other service on the shared, currently-up
lab stack mid-verification-loop (session state, rate limiting, anomaly
scoring) — judged too destructive to run unilaterally. Verified by code
inspection instead: `taint_store.py`'s `is_tainted()` catches any read
exception and returns `True` (fail-closed tainted); `mark_tainted()` raises
`TaintStoreError` on a write failure, which `invocation.py`'s write-before-
forward call site does not catch, so it propagates to a fail-closed request
failure (comment: "A write failure raises TaintStoreError -> the request
fails closed (500)."). This matches the article's claim, but is a code-level
citation, not a live-observed outage test. **NEEDS_USER_INPUT if a live Redis
outage test is required**: it would need either a dedicated/disposable Redis
instance for this one test, or an accepted window of full lab downtime — flag
before scheduling.

No permanent acceptance test was added for this (out of scope for a
one-off verification pass); if this becomes a permanent regression gate, the
steps above are the exact commands to encode into a
`lab/tests/acceptance/test_at5_taint_floor.py`.
