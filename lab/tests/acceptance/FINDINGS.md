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
