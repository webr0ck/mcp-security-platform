# Acceptance test suite (AT0–AT3)

Full, real-lab (no mocks) acceptance suite for the mcp-security-platform. Runs
pytest against the actual running Podman lab stack over the network — real
Keycloak tokens, real Grafana/NetBox/Entra backends, real Postgres, real
submission scanner (trufflehog + pip-audit + vendored mcp_checker), real
Gitea.

## What's covered

| Group | File | Covers |
|---|---|---|
| AT0 | `test_at0_preflight.py` | proxy `/health` all-ok, Keycloak realm reachable, NetBox/Grafana/Entra reachable directly (bypassing the platform) |
| AT1 | `test_at1_auth_matrix.py` | One real invocation per injection mode (service, user, entra_client_credentials, kc_token_exchange, KC service-account JWT) + negatives (no token, garbage token, unentitled principal) |
| AT2 | `test_at2_real_data.py` | Invoke via the proxy vs. call the backend directly, cross-verify the platform never returns data the backend doesn't have |
| AT3 | `test_at3_onboarding.py` | Full self-service submission lifecycle: malicious repo → scan blocked → reviewer approval refused; clean repo → scan passed → approve → provide-url → discover → activate → entitle → invoke (real echo response) |

## Running

```bash
make -f Makefile.lab lab-acceptance
# or directly:
bash lab/scripts/run_full_acceptance.sh
```

The runner brings the lab up if it's down, runs the AT3 Gitea fixture setup
(idempotent), executes the full suite, and writes
`lab/tests/acceptance/results/<UTC-timestamp>/{run.log,results.xml,REPORT.md}`.

To run a single group directly (lab must already be up):

```bash
python3 -m pytest lab/tests/acceptance/test_at1_auth_matrix.py -v
```

## Environment requirements

- `podman` + `podman-compose`, lab stack up (`make -f Makefile.lab lab-up`)
- `.env.lab` present at repo root (git-ignored; holds lab credentials — never
  printed by any test or script here, always masked to first 4 chars if it
  must appear in output at all)
- `openssl`, `git`, `curl`, `python3` with `httpx`/`pytest` on the host

## Non-obvious environment facts discovered while building this suite

These cost real debugging time; they're recorded here (and in `conftest.py`'s
module docstring) so nobody re-derives them from scratch:

1. **SEC-05 ingress guard** (`proxy/app/middleware/ingress.py`) rejects any
   HTTP peer that isn't the gateway container or loopback. Running tests from
   the **host** machine means `http://localhost:8000` (the historically
   documented "direct proxy" URL) now 403s with `INGRESS_DENIED`. This suite
   goes through the gateway (`https://<LAB_HOST>:8443`) for everything, and
   uses `podman exec mcp-proxy curl localhost:8000/...` (real loopback) only
   for `/api/v1/tools/{id}`, which the gateway gates behind mTLS (see next).
2. **`/api/v1/tools/` is mTLS-only at the gateway** (`lab/nginx/conf.d/mcp-proxy-lab.conf`,
   PRD-0006 R-2). No step-ca client cert is available to this suite, so tool
   activation goes via the proxy's own loopback instead (bypasses nginx
   entirely, which also happens to satisfy the SEC-05 guard above).
3. **ModSecurity/CRS quirks** on the gateway: a JSON body containing the bare
   tool name `"whoami"` gets 403'd (CRS 932100, Unix command injection
   signature) — an unrelated WAF false positive on a legitimately-named MCP
   tool, not an auth/entitlement issue. A JSON body containing a raw IPv4
   literal (e.g. a `github_repo_url` built from `.env.lab`'s `LAB_HOST` IP)
   gets 403'd too (CRS 934110, SSRF/IP-literal rule) — always address lab
   hosts by container DNS name in request bodies sent through the gateway.
4. **The B-coarse taint floor** (`proxy/app/services/taint_floor.py`,
   `TAINT_FLOOR_ENABLED=true` in `.env.lab`) denies any tool with
   `required_integrity>=1` (the default for every tool in this lab) once a
   principal has invoked **any** server at `trust_tier<2`.
   `server_registry.trust_tier` defaults to **0** for every freshly onboarded
   server — only the lab's pre-seeded servers (`lab-echo`, `lab-grafana-mcp`,
   `lab-netbox-mcp`, `lab-m365`, etc.) are seeded at tier 2. This is real,
   correct-by-default security behavior, not a bug, but it means: (a) a newly
   onboarded AT3 server will taint whoever invokes it unless a reviewer
   assigns it a trust tier (this suite does, mirroring the lab's own seeding
   pattern), and (b) any test that deliberately invokes a low-trust tool
   (`lab-tickets`, `trust_tier=0`) taints that principal for up to an hour —
   clear the Redis key (`conftest.clear_taint` equivalent) before/after such a
   test so it doesn't spuriously fail every later test using the same
   identity.
5. **Gitea can't be registered as a submission-scanner git provider as-is.**
   `proxy/app/services/git_providers.py`'s URL-matching regex requires a
   literal `https://<host>/...` with **no port suffix** (i.e. the default
   443), and lab-gitea only serves plain HTTP on `:3000`. Making Gitea itself
   listen on `:443` over native HTTPS was tried and reverted — the
   `gitea/gitea:1.22` binary refuses to bind `:443` unless running as root
   (which it explicitly refuses to do) or holding `CAP_NET_BIND_SERVICE` as a
   non-root user, and `podman-compose` in this environment does not apply
   `cap_add:` from an override file to an already-created service. The
   working fix is a small `nginx:alpine` TLS-terminating sidecar
   (`lab-gitea-tls`) reverse-proxying to `lab-gitea:3000` — see
   `fixtures/setup_gitea_fixtures.sh` for the full script. The proxy
   container's git client trusts that sidecar's self-signed cert via
   `GIT_SSL_CAINFO` (its `$HOME` is read-only, so `git config --global` isn't
   an option) — this pins the *entire* container's git-over-https trust store
   to that one CA for the duration, which is fine because nothing in this
   suite clones a real public host, but `teardown_gitea_fixtures.sh` reverts
   it regardless.
6. **`proxy/scan-config.yaml` (repo root) is a decoy.** The submission
   scanner reads `Path(__file__).parents[2] / "scan-config.yaml"`, which
   resolves to **`proxy/scan-config.yaml`**, bind-mounted live into the
   running container at `/app/scan-config.yaml` by `docker-compose.dev.yml`'s
   `./proxy:/app` mount. The repo-root copy is never read by the running
   proxy. Any scan-gate tuning (like this suite's `acceptance_test_planted_marker`
   custom rule) must go in `proxy/scan-config.yaml`, not the root one.

## Product bugs found (not worked around — see REPORT.md and inline `xfail` markers)

- **`entra_client_credentials` has no working admin provisioning path.**
  `admin_credentials.py`'s `PUT /admin/credentials/{tool_id}` always encrypts
  with the per-user-KEK `approach_a.encrypt()` scheme, but the
  `entra_client_credentials` injector decrypts via the raw-master-secret KMS
  envelope (`kms.py`) — incompatible ciphertext formats, so decryption fails
  with `InvalidTag` on every call regardless of what's uploaded
  (`proxy/app/credential_broker/dispatcher.py:562`). Separately,
  `admin_credentials.py:296`'s `update_injection_mode` `valid_modes` doesn't
  even include `entra_client_credentials` / `entra_user_token` /
  `kc_token_exchange`, so those tools can't be reconfigured through that
  endpoint either. See `test_at1_auth_matrix.py::test_entra_client_credentials_m365_graph`
  (`xfail`).
- **`submission_scanner.py`'s `pip-audit` severity mapping never reaches
  "critical".** `proxy/app/services/submission_scanner.py:399` maps every
  finding to `"high"` (if a fix version exists) or `"medium"` — never
  `"critical"` — while `scan-config.yaml`'s default `dependency_audit.block_on:
  critical` only blocks at severity index 3 (`"critical"`). The dependency-CVE
  gate can therefore **never** block a submission under the shipped default
  config, no matter how severe the CVE. Confirmed by inspection; not exercised
  live in this suite (AT3 blocks via the `custom_rules` marker instead, which
  does work).

- **`tool_registry_name_version_unique` has no `WHERE deleted_at IS NULL`.**
  A soft-deleted tool row permanently occupies its `(name, version)` pair —
  the name can never be reused. Worse, you can't hard-DELETE around it either
  for any tool that was ever invoked: `audit_events.tool_id` has `ON DELETE
  SET NULL`, but `audit_events` is guarded by
  `fn_audit_events_immutability_guard`, which rejects the `UPDATE` the FK
  cascade itself tries to run — so a `DELETE FROM tool_registry` for such a
  row fails outright. `test_at3_onboarding.py`'s `clean_mcp_upstream` fixture
  works around this by **renaming** (not deleting) any leftover `echo` tool
  row from a previous run, so re-registration under the same name succeeds.

## Lab repairs performed to make AT1/AT2 meaningful

The lab's pre-seeded credentials for 3 of the 4 auth-matrix tools were
broken; without these (one-time, already-applied) fixes AT1/AT2 would only
ever exercise the negative/error paths. All were done through the platform's
own admin APIs or a direct DB repair mirroring an existing working row's
shape — never product code changes:

- **grafana-query (service) / netbox-query (user, alice)**: `credential_store`
  rows existed but failed to decrypt (`InvalidTag` — broker master-secret
  drift, a known class of issue per `project_mcp_credential_master_drift` in
  agent memory). Re-provisioned both via `PUT /admin/credentials/{tool_id}`.
- **lab-tickets-query**: `tool_registry.server_id` was `NULL` — the tool had
  no backing `server_registry` row at all, so the DNS-rebind revalidation
  guard always fail-closed with "registered as public but resolves to
  private IP(s)". Inserted a `server_registry` row + `upstream_allowlist_entry`
  matching the other 3 lab tools' pattern, and an entitlement grant for
  alice. The platform now correctly performs the `kc_token_exchange` and
  forwards the call — but `lab-mcp-lab-tickets` itself then rejects it with
  `Unauthorized: [Errno -2] Name or service not known`, a DNS/config issue
  inside that container, unrelated to the platform's auth path (still `xfail`).
- **m365-graph**: had no `entra_tenant_id`/`entra_client_id`/`credential_id`
  configured at all. Set those directly and uploaded an `entra_client_secret`
  credential — this is what surfaced the encryption-scheme-mismatch bug
  described above, which is unresolved (still `xfail`).
- **svc-mcp-agent** (Keycloak client\_credentials service account) carries no
  `agent` realm role — its token only has `default-roles-mcp` /
  `offline_access` / `uma_authorization`. RBAC middleware denies it before
  entitlement/credential logic ever runs. Documented as a lab KC-config gap
  (fail-closed is correct behavior for an under-privileged principal), not
  fixed — `test_service_account_jwt_invokes_service_tool` asserts the actual
  403 rather than assuming success.

## Coverage gaps / follow-ups

- `entra_user_token` and `oauth_user_token` / `service_account` injection
  modes are not exercised (no lab fixture wired for them).
- No Playwright/UI layer exists yet in this repo — this suite is API/CLI only.
- The `entra_client_credentials` and `kc_token_exchange` live-invoke paths are
  `xfail`, not skipped, specifically so a future fix flips them green instead
  of the fix going unnoticed.
- **Reproduced but unexplained: two concurrent `scan_submission()` background
  tasks can hang forever.** Submitting the malicious and clean fixtures back
  to back (before the first one's scan finished) left both stuck at
  `scan_status='running'` indefinitely — no further log lines, no exception,
  no subprocess visible under `/proc` in the proxy container. Every scanner
  step (`trufflehog`, `pip-audit`, the vendored `mcp_checker`, `syft`) runs
  in well under 15s when called standalone or one-at-a-time, and a *serial*
  run of both fixtures completes normally (this is why `test_at3_onboarding.py`
  runs them sequentially and the suite as a whole passes) — so this is a real
  concurrency issue in `scan_submission`'s `asyncio.gather` /
  `BackgroundTasks` handling, not a scanner slowness problem. Recovering
  required restarting `mcp-proxy`; the stuck rows were soft-deleted
  (`server_id`s `868d20b7…`/`493bfb31…`, since removed). Not root-caused —
  flagging for whoever owns `submission_scanner.py`/`BackgroundTasks` next.
