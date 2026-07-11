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

---

## T2 — ES256 trust-envelope sign/verify, live (2026-07-11, VERIFY loop 2)

**Starting state: the mechanism was live-untested AND not even switched on.**
`podman exec mcp-proxy env` showed `TRUST_ENVELOPE_ENABLED=false` and no
`TRUST_OBSERVER_ENABLED` at all — both default `False` in `config.py`, and
`TRUST_OBSERVER_ENABLED` was never wired into `docker-compose.yml`'s proxy
`environment:` block in the first place (only `TRUST_ENVELOPE_ENABLED` was).
Turning it on live surfaced three real, unrelated bugs, all fixed on `main`:

1. **Volume-name mismatch.** `make labeler-init` bind-mounts the literal
   `labeler-data` volume; podman-compose (no `name:` pin) creates
   `mcp-security-platform_labeler-data` instead — two different volumes, so
   the proxy mounted an empty one and `TrustVerifier` init threw
   `FileNotFoundError`. Fixed: pinned `name: labeler-data` in
   `docker-compose.yml`'s volume def.
2. **0700-root / 0600-root file perms unreadable by the proxy's non-root
   uid (1001).** `infra/pki/init-labeler-pki.py` wrote the whole `/labeler`
   dir and every file inside it (including the *public* certs) as
   owner-only, owned by whatever uid the root-in-container init job mapped
   to under rootless Podman — not uid 1001. Fixed: dir now `0755`;
   `sub_ca.crt`/`leaf.crt`/`leaf.key` now `0644` (world-readable — they're
   either public or the proxy is the intended reader); `sub_ca.key` stays
   `0600` (the "proxy can never access sub_ca.key" invariant is enforced by
   this file mode, since proxy mounts the *same* directory read-only).
   Applied the same fix to `renew-labeler-leaf.py`.
3. **Unhandled crash on verifier-init failure.** `main.py`'s
   `TRUST_OBSERVER_ENABLED` block called `init_verifier()` (eager file I/O)
   with no try/except, unlike every sibling optional-startup step — bug #1
   crash-looped the whole proxy instead of degrading gracefully. Fixed:
   wrapped in try/except + `logger.warning`, matching the existing pattern.

With those three fixed, `TrustLabeler`/`TrustVerifier` both initialise
cleanly (`podman logs mcp-proxy`: `"TrustLabeler initialised"` /
`"TrustVerifier initialised (sub_ca=/labeler/sub_ca.crt)"`).

**Architecture caveat that shapes what "reject" can mean here:**
`trust_observer.py`'s docstring is explicit — *"Never blocks or raises — the
observer is advisory (demonstrations D4/D5/D6 only)."* Grepped the whole
`proxy/app` tree for any code that reads `VerifierVerdict.accepted`: zero
call sites outside the observer and its own tests. **No code path in this
repo gates, denies, or 403s a request on envelope-verify failure.** The
observer only ever re-verifies the envelope the proxy itself *just signed*,
synchronously, in the same function, before the response leaves the process
— there is no reachable seam where a client-supplied tampered envelope could
be fed back in over the wire. This matters for article 4: "signed trust
envelopes" is real, live, ES256, and independently verifiable — but it is
**not currently a live enforcement control**, only an advisory/log-only one
(the actual live *enforcement* control for tainted-session denial is the
separate SEP-1913 taint floor already verified in the T5 entry above).

**Live proof, committed as `lab/tests/acceptance/test_at2_trust_envelope_verify.py`:**

1. `test_valid_envelope_accepted_end_to_end` — real credential-injecting call
   (`gitea-repos`/`list_repos`, `injection_mode=service`) through the full
   gateway → auth → entitlement → OPA → credential-broker chain as alice;
   asserts the response's `_meta["io.mcp-security-platform/trust-envelope/v0.1"]`
   carries a genuine `alg=ES256` signature with a real x5c chain, and that
   the actual gitea repo data (`gitadmin/clean-mcp` etc.) came back — i.e.
   the credential injection genuinely happened, not just the envelope math.
   `podman logs mcp-proxy` for this call:
   `TrustObserver accepted tool=gitea-repos server=6b8d... rank=2` (direct
   registry-tool dispatch path only — see note below on `invoke_tool`).
2. `test_tampered_and_unsigned_envelopes_rejected` — signs a real envelope
   with `TrustLabeler` pointed at the *same* live-mounted PKI files
   (`/labeler/leaf.{crt,key}`, `/labeler/sub_ca.crt`) the running proxy
   process uses for every real request (its in-memory singleton isn't
   reachable from a fresh interpreter, but the on-disk cert/key material is
   identical), then proves `TrustVerifier.verify()` rejects: a corrupted
   `content_hash` → `signature_invalid`, a corrupted signature value →
   `signature_invalid`, the same valid envelope replayed against a
   different `result_id` (binding mismatch) → `signature_invalid`, and no
   envelope at all → `no_envelope`. Executed via `podman exec mcp-proxy
   python3 -c <probe>` — same code, same live cert material, same process
   image as production requests.

Both tests pass in a live `run_full_acceptance.sh` run: `33 passed, 2
skipped, 0 failed` (see run below).

**Note — `invoke_tool` wrapper calls don't hit the observer.** The
platform's `invoke_tool` meta-tool builds its own envelope
(`server_id="__platform__"`, `trust_tier=4`) via a second, separate call
site in `mcp_server.py` (~line 1608) that does **not** call
`trust_observer.observe_result()` — only the direct
`tools/call {"name": "<registered-tool>", ...}` dispatch path does (~line
979). Both paths sign; only one is observed. Not fixed (out of scope for a
verify loop — flagging for the architect/engineer if per-call observability
is meant to be universal).

**Known operational gap — 15-minute leaf TTL, no working renewal.** The
`labeler-renewal` sidecar (compose profile `trust-envelope`) is supposed to
rotate the leaf cert every 12 minutes, but it currently **cannot start** in
this lab: it's wired to `observability-net` only, which has no egress, so
its `pip install cryptography` at container start fails DNS resolution and
it crash-loops forever. Net effect: ~15 minutes after `make labeler-init`,
every envelope verify starts failing `chain_validation_failed` (confirmed —
this is exactly what happened mid-loop when the full suite was re-run ~15
min after the initial PKI generation; fixed by re-running `make
labeler-init`, which is idempotent for the sub-CA and reissues a fresh
leaf). **NEEDS_USER_INPUT / follow-up**: either give `labeler-renewal`
egress (a network it's currently not on) or bake `cryptography` into a
purpose-built image instead of `pip install`-ing python:3.12-slim at
startup — until then, `TRUST_ENVELOPE_ENABLED=true` in this lab needs
`make labeler-init` re-run roughly every 15 minutes, and the new AT2 test
will start failing with `chain_validation_failed` (not a regression, just an
expired lab cert) whenever that lapses. Documented in `.env.lab.example`.

**Flags are lab-local only.** `.env.lab` is gitignored; `TRUST_ENVELOPE_ENABLED=true`
/ `TRUST_OBSERVER_ENABLED=true` were added there for this loop's live proof
but will NOT persist to a fresh lab bring-up or CI unless someone copies
them from `.env.lab.example` (documented there with the caveats above) —
this is intentional (matches how every other lab secret/flag is handled),
just flagging so a future loop doesn't wonder why the observer is silent
again.

---

## T3 — Redis fail-closed for the taint floor, live (2026-07-11, VERIFY loop 2)

**Method:** scoped `podman network disconnect` of `mcp-proxy` from the
pairwise `proxy-redis-net` (the *only* network `mcp-redis` is reachable on
besides `internal-net`, and `mcp-redis` is proxy's private Redis — nothing
else in the stack dials it). This cuts Redis reachability for `mcp-proxy`
only; every other container, including `mcp-redis` itself, is fully up and
undisturbed for the whole test window.

**Procedure and live evidence:**

1. **Baseline** — alice invokes `gitea-repos`/`list_repos` (a real
   credential-injecting call) through the gateway: `200`, real repo data
   back (`gitadmin/clean-mcp`, `gitadmin/lab-demo`, `gitadmin/malicious-mcp`).
2. `podman network disconnect mcp-security-platform_proxy-redis-net
   mcp-proxy` — confirmed with `podman exec mcp-proxy getent hosts
   mcp-redis` → `unreachable`.
3. **Same call, same token, during the outage** → `429
   {"error": {"code": "RATE_LIMITED", "message": "Too many requests"}}` —
   i.e. denied, not allowed through. `podman logs mcp-proxy` for this
   window: `ERROR app.services.limits get_rate_limit failed for
   alice@corp, using role_default=300: Error -2 connecting to redis:6379.
   Name or service not known` plus `WARNING Redis roles cache miss` /
   `WARNING Failed to cache roles in Redis` — a genuine, logged Redis
   outage, not a coincidental rate limit from prior traffic.
4. `podman network connect mcp-security-platform_proxy-redis-net mcp-proxy`
   — `podman exec mcp-proxy getent hosts mcp-redis` resolves again.
5. **After recovery** (past the per-client rate-limit window) — same call →
   `200`, real repo data again. Normal operation resumed.

**Important precision on what this proves vs. what it doesn't isolate.**
The deny observed here (`429 RATE_LIMITED`) comes from
`mcp_server.py::_check_rate_limit` (`app.services.limits.get_rate_limit`),
**not** from `taint_store.py`'s `is_tainted()`/`mark_tainted()` directly —
that per-client rate limiter also talks to Redis and, per its own
`_RATE_LIMIT_FAIL_OPEN` env-gated default (`false` unless
`RATE_LIMIT_FAIL_OPEN=true` is set — it is not, in this lab), **also** fails
closed on a Redis exception (comment: `# MCP-006: fail closed by default`).
Because this rate-limit check runs earlier in the request path than the
taint-floor gate, it intercepts first during a full Redis outage — the
credential-injecting call never reaches `taint_store.is_tainted()` in this
particular live run, so `taint_store.py`'s own fail-closed branch specifically
was **not** independently exercised over the wire (it remains verified only
by code inspection: `is_tainted()`'s bare `except Exception: return True`,
`mark_tainted()`'s `raise TaintStoreError` propagating uncaught to a 500 at
the write-before-forward call site in `invocation.py`).

**Net result:** the *system-level* guarantee the article implies (a Redis
outage cannot silently fail a credential-injecting call open) is **live-
confirmed end-to-end** — every credential-injecting call denied during the
outage, none silently allowed, and full recovery afterward. The *specific*
taint-floor fail-closed code path is still only code-verified, not
wire-verified in isolation, because a different, earlier fail-closed gate
(the per-client rate limiter, same Redis dependency) masks it under a full
outage. Isolating `taint_store.py` alone would need bypassing or exempting
the rate limiter for one test client — not attempted (would mean patching
production dispatch code just to make a gap testable, out of scope for this
loop). Not added as a permanent acceptance test — the network
disconnect/reconnect is disruptive enough (breaks the fail-open session
cache and rate limiting for the whole window, not just the taint check)
that it shouldn't run unattended in the pinned suite; this is a documented,
repeatable manual procedure per the task's own fallback allowance.
