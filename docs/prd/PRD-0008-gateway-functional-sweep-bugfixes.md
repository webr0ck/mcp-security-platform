# PRD-0008 — Gateway Functional Sweep: Bug-Fix Batch

- **Status:** DRAFT — findings verified live against the running lab; ready for parallel fix.
- **Date:** 2026-07-11
- **Author:** Claude (full-functionality MCP gateway check, requested by platform owner), SSH-verified
  against `webr0ck@100.119.138.35` (~/Code/mcp-security-platform).
- **Scope:** Ten independently-verified defects found during a full functional sweep of every
  registered MCP tool plus a live browser-login incident, plus a live sign-out incident (R-10). Each
  item below was reproduced with a concrete command/log excerpt, not inferred. Items are independent —
  no ordering dependency between R-1..R-10, they may be fixed in parallel by separate owners.
- **Non-goals:** New features, UI changes, policy redesign beyond the specific denials described,
  re-architecting the tool-registry dispatch layer (only the specific bug is in scope).
- **Precedents:** existing internal/external issuer-URL split in `proxy/app/routers/oidc_browser.py`
  (`_issuer_url_internal()` / `_issuer_url_external()`), already used correctly for the browser
  redirect and incorrectly *not* used for the server-side token exchange (see R-1).

---

## R-1 — OIDC browser login fails with `token_exchange_failed` (502)

**Symptom:** user cannot log into `https://100.119.138.35:8443/`; browser lands on
`/api/v1/auth/oidc/callback` and receives
`{"error":"token_exchange_failed","detail":"Authentication failed. Check server logs for details."}`.
Confirmed live: nginx access log shows `502` with `Content-Length: 98` for both callback attempts
(04:12:07, 04:12:24 UTC 2026-07-11).

**Root cause:** `proxy/app/routers/oidc_browser.py`, function around line 420-444. The Keycloak
discovery document (`/.well-known/openid-configuration`) always advertises **external** URLs
(`https://100.119.138.35:8443/...`) for every endpoint — including `token_endpoint` — because
Keycloak's `KC_HOSTNAME` is set to the external IP, regardless of which URL was used to *fetch* the
discovery doc. The `/login` code path already knows this and rewrites `auth_endpoint` before
redirecting the browser (line ~217: `auth_endpoint.replace(_issuer_url_internal(), _issuer_url_external())`).
The token-exchange code path has no equivalent rewrite — it POSTs directly to the external
`token_endpoint`, which routes back out through nginx's TLS listener (cert issued by the lab's
internal `mcp-step-ca`). Reproduced directly inside the `mcp-proxy` container:
```
curl -k https://100.119.138.35:8443/realms/mcp/.well-known/openid-configuration   → 200
curl    https://100.119.138.35:8443/realms/mcp/.well-known/openid-configuration   → SSL certificate problem: unable to get local issuer certificate
```
httpx's default `AsyncClient()` hits the same trust failure as the unadorned curl call, is caught by
the broad `except Exception as exc` at line ~443, logged via `logger.exception(...)`, and surfaces as
the 502 the user sees. (Separately noted: that `logger.exception` call did not appear in `podman logs
mcp-proxy` for either failed attempt in the exact time window — worth a quick sanity check as part of
this fix that the app's logger config actually flushes ERROR-level records to stdout, since "Check
server logs for details" is currently not actionable.)

**Fix:** before the `client.post(token_endpoint, ...)` call, rewrite `token_endpoint` from external →
internal the same way `auth_endpoint` is rewritten from internal → external, e.g.
`token_endpoint = token_endpoint.replace(_issuer_url_external(), _issuer_url_internal())`. This makes
the server-to-server call go directly to `http://lab-keycloak:8080/...` over the container network,
avoiding the TLS hairpin entirely (matches how `_discover()` itself already reaches Keycloak).
Alternative if internal rewrite is undesirable for some reason: mount the step-ca root CA into the
proxy image and point httpx at it with `verify=<path>` — more moving parts, not preferred.

**Acceptance criteria:**
- Manual login via `https://100.119.138.35:8443/portal` completes without a 502.
- `podman logs mcp-proxy` shows no `SSL certificate problem` during a login attempt.
- Existing `proxy/tests/` OIDC test(s) still pass.
- If the missing-log-line issue above turns out to be real (not just a race in what was tailed),
  fix the logger config so `logger.exception` calls are visible in `podman logs mcp-proxy`.

---

## R-2 — Tool-registry passthrough wrappers forward the wrong name upstream

**Symptom:** calling the platform's own per-server MCP tool wrappers directly (`gitea-repos`,
`notes-store`, `netbox-query`, `lab-tickets-query`, `m365-graph`, `m365-graph-delegated`,
`echo-basic`, `echo-sa`, `echo-dex-external`, `rag-assistant`, `search-kb`) returns
`"Unknown tool: <wrapper-name>"` even though the catalog marks every one of them `active` /
`enabled_for_your_profile: true`.

**Root cause (verified via `invoke_tool` + `tools/list`):** these wrappers appear to forward
`name=<registered-server-name>` (e.g. `"gitea-repos"`) as the JSON-RPC `tools/call` target, but the
upstream MCP server's actual tool names are different — e.g. the `gitea-repos` server's real tools
are `list_repos`, `get_repo`, `list_issues`, `create_issue`, `list_pull_requests`,
`get_file_contents`, `list_branches` (confirmed via `invoke_tool(tool_name="gitea-repos",
method="tools/list")`). The wrapper never resolves to a real per-tool name, so every direct
wrapper call round-trips to the upstream server, which correctly replies "Unknown tool: gitea-repos".

**Fix:** find wherever these single-tool-per-server wrapper functions are generated/dispatched
(likely the same registry/dispatch layer `invoke_tool` uses — grep for how MCP tool schemas are
surfaced to the platform's own client, e.g. `tool_registry`, `dynamic_tools`, or similar under
`proxy/app/`). Either (a) auto-expand each registered server into its *real* per-tool wrappers at
discovery time (mirroring what `tools/list` already returns), or (b) if a single default wrapper per
server is intentional, have it default to the server's first/primary tool rather than echoing the
server name as the tool name. Given `invoke_tool` already does this correctly when given an explicit
`name` in `arguments`, prefer wiring the direct wrappers through the same code path with the right
per-tool name instead of duplicating logic.

**Acceptance criteria:**
- Calling the platform's own `gitea-repos`-family wrapper tools succeeds (or, if wrappers are
  intentionally removed in favor of `invoke_tool`, the catalog stops advertising them as directly
  callable — pick whichever is less surprising and document the choice).
- `search-kb` and `rag-assistant` (both flagged `risk_level: medium`, likely most-used) work end to
  end with a real query.

---

## R-3 — OPA denies `self-service-mcp`, `plan_mcp_server`, `check_submission_status` despite catalog marking them enabled

**Symptom:** calling any of these three returns `MCP error -32003: Access denied by policy` for
`alice@corp` (roles: `agent, offline_access, admin, grafana-admin`), even though
`list_available_mcps` reports `enabled_for_your_profile: true` and `status: active` for all three.

**Root cause:** not yet isolated to a specific rego rule — needs a policy-engineer read of
`policies/rego/` for the rules gating these three tool names specifically. Given the caller holds
`admin`, this is either (a) an intentional restriction unrelated to role (e.g. these three are
gated on something else — profile binding, `is_testing`, an allow-list separate from role) that
should be reflected in the catalog (`enabled_for_your_profile` is misleading if policy still blocks
it), or (b) a genuine rule bug (e.g. a rule keyed to the wrong tool_name string, or an allow-list
that was never updated when these three tools were added — `check_submission_status`,
`plan_mcp_server`, and `self-service-mcp` all live on the same upstream, `lab-mcp-self-service`,
per `list_registered_tools`, suggesting a shared rule scoped to that upstream rather than per-tool).

**Fix:** read the mcp-opa audit log for one live denial (`mcp-opa` container logs the full OPA input
JSON per request — same technique used to inspect the anomaly-scored `search-kb` call during this
sweep) to see exactly which rule fires, then either fix the rule or fix the catalog's
`enabled_for_your_profile` computation so it reflects reality (don't claim enabled when policy will
still deny).

**Acceptance criteria:**
- `alice@corp` (or whichever role is intended to have access) can successfully call all three tools,
  OR the catalog correctly reports `enabled_for_your_profile: false` with a reason if access is
  intentionally restricted.

---

## R-4 — Anomaly-detector lockout is broader and less recoverable than intended

**Symptom:** firing 9 parallel `invoke_tool` calls (a normal `tools/list` discovery sweep, not a
credential-stuffing or scraping pattern) tripped `anomaly_threshold_exceeded`. After that, `ping`,
`slow_tool`, and every subsequent `invoke_tool` call were denied by policy for the rest of the
session — but `get_my_profile`, `security_pulse_summary`, `list_registered_tools`, and
`list_available_mcps` kept working throughout. No recovery was observed within the ~15 minutes of
continued testing.

**Root cause:** not yet isolated — needs the anomaly-scoring logic in `policies/rego/` (or wherever
`anomaly_score` / `anomaly_cutoff` — seen as `0.0` / `0.85` in the OPA input earlier in the same
session, before the burst — is computed and persisted, likely Redis-backed given `mcp-redis` is in
the compose stack). Two separate questions worth answering: (1) is a 9-call parallel `tools/list`
burst actually the intended trigger threshold, or is the cutoff too sensitive for legitimate
discovery traffic; (2) why does the lockout apply to `ping`/`slow_tool`/`invoke_tool` specifically
but not the other four tools called in the same window — is that deliberate scoping (e.g. only
tools above a risk_level threshold are gated by anomaly score) or a bug in which tools consult the
anomaly score at all.

**Fix:** document the intended anomaly-scoring behavior (what triggers it, what it blocks, how/when
it clears — TTL? manual reset? admin action?) and align the implementation to it. At minimum, a
burst of parallel read-only discovery calls from a single already-authenticated admin identity
should not indefinitely lock out basic liveness checks (`ping`) without any visible recovery path or
operator signal.

**Acceptance criteria:**
- Documented trigger condition and recovery path (e.g. "clears after N minutes" or "requires
  `self-service-mcp` reset" — whichever is intended).
- `ping` is either exempted from anomaly gating (it's a liveness probe) or its denial is time-bound
  and observably clears.

---

## R-5 — `lab-mcp-wazuh` crash-loops

**Symptom:** container cycles `Up 1 second (starting)` repeatedly; `wazuh-siem` tool shows
`status: disabled` in the catalog as a result.

**Root cause (from `podman logs lab-mcp-wazuh`):**
```
TypeError: issubclass() arg 1 must be a class
Traceback (most recent call last):
...
```
repeating on every restart — a real Python bug at import/startup time, not a transient issue.

**Fix:** get the full traceback (`podman logs lab-mcp-wazuh` was tail-truncated during the sweep —
pull the complete stack), identify the offending `issubclass()` call (likely a decorator or
type-registry pattern being handed an instance / non-class value, e.g. a Pydantic model instance
instead of the model class, or a version mismatch between the MCP SDK and a plugin/tool-registration
decorator), and fix the call site or pin the dependency causing the mismatch.

**Acceptance criteria:** `podman ps` shows `lab-mcp-wazuh` reaching `healthy`/steady running state;
`wazuh-siem` appears as `status: active` in `list_available_mcps`.

---

## R-6 — `lab-mcp-grafana` unhealthy

**Symptom:** `invoke_tool(tool_name="grafana-query", ...)` returns
`MCP error -32602: tool 'grafana-query' not found: tool not found`; `podman ps` shows
`lab-mcp-grafana` as `unhealthy`.

**Root cause:** not yet isolated — needs `podman logs lab-mcp-grafana` and its healthcheck
definition (likely in `podman-compose.lab.yml`) to see what's failing (commonly: waiting on a
Grafana API token/service-account that isn't provisioned yet, or the healthcheck hitting the wrong
port/path).

**Fix:** address whatever the logs show; re-verify `grafana-query` end to end afterward (the KB doc
`local-lab-podman.md` documents a real-Grafana MCP server pattern at `localhost:8100/mcp` if this
turns out to be a real-vs-lab config mismatch).

**Acceptance criteria:** `lab-mcp-grafana` reaches `healthy`; `invoke_tool(tool_name="grafana-query",
method="tools/list")` returns a real tool list; a basic query succeeds.

---

## R-7 — `mcp-compliance-checker`: unimportable audit logger + malformed webhook URL

**Symptom (from `podman logs mcp-compliance-checker`):**
```
ERROR entrypoint mcp_audit_logger not importable — cannot verify hash integrity. Check that the
shared library is installed in this container.
...
ERROR entrypoint COMPLIANCE CHECK FAILED: 2 categories failed
ERROR entrypoint Failed to post compliance alert: Request URL is missing an 'http://' or 'https://' protocol.
```

**Root cause:** two independent bugs in the same container: (1) the shared `mcp_audit_logger`
library isn't installed in this container's image (dependency/packaging gap — check the
Dockerfile/requirements for this service vs. wherever `mcp_audit_logger` is normally vendored/
installed for other services); (2) the compliance-alert webhook URL is being read from config
without a scheme (missing `http://`/`https://` prefix) — likely an env var that's just a bare
host:port or the code failing to normalize it.

**Fix:** (1) add `mcp_audit_logger` to this container's build (match how other containers that use it
install it); (2) either fix the env var value in `.env.lab`/compose, or normalize the URL in code
(default to `https://` if no scheme present, and fail loudly at startup rather than at alert-send
time if the URL is unusable).

**Acceptance criteria:** no `mcp_audit_logger not importable` errors on startup; a deliberately-failed
compliance check successfully posts its alert (verify via whatever the alert sink is — check logs/
mock receiver).

---

## R-8 — `mcp-proxy` metrics gauge refresh: asyncpg type mismatch

**Symptom (from `podman logs mcp-proxy`):**
```
WARNING app.services.metrics metrics: refresh_db_gauges failed (leaving gauges stale):
(sqlalchemy.dialects.postgresql.asyncpg.Error) <class 'asyncpg.exceptions.DataError'>:
invalid input for query argument $1: 24 (expected str, got int)
```

**Root cause:** a query in `app/services/metrics.py::refresh_db_gauges` passes an `int` bind
parameter where the query (or the column it targets) expects a `str` — likely a server_id or
similar UUID/varchar column being passed a raw int (row count? id?) instead of being cast/stringified
first.

**Fix:** find the `$1` parameter in `refresh_db_gauges`, correct the type (str() cast or fix the
value being passed), add a regression test if the metrics module has test coverage.

**Acceptance criteria:** no `refresh_db_gauges failed` warnings after a fresh `mcp-proxy` restart;
DB gauge metrics visibly update in Prometheus/Grafana rather than staying stale.

---

## R-9 — Promtail → Loki: continuous `400` (missing stream labels), starving several Grafana alert rules

**Symptom (from `podman logs mcp-promtail` / `mcp-loki`):**
```
level=error ... msg="write operation failed" details="error at least one label pair is required per stream"
level=error ... caller=client.go:430 msg="final error sending batch" status=400 ...
```
repeating continuously (every ~2s). Side effect confirmed in `mcp-grafana` logs: alert rules
`mcp-opa-unavailable`, `mcp-high-latency`, `mcp-high-deny-rate`, `mcp-compliance-failed`,
`mcp-critical-tool-registered` all evaluate to `NoData` (their Loki datasource query has no data to
evaluate), while `mcp-anomaly-detected` sits in a permanent `Alerting`/`Error` execution state.

**Root cause:** some scrape target in promtail's config is shipping a log stream with zero labels
(Loki requires ≥1 label per stream). Needs a look at `promtail`'s scrape_configs (likely under
`observability/promtail/` or similar) to find the job missing a `labels:` block or a relabel_config
that's stripping all labels for one source.

**Fix:** add the missing label(s) (minimally `job`/`container` per Promtail convention) to the
offending scrape config; restart `mcp-promtail`.

**Acceptance criteria:** `mcp-promtail`/`mcp-loki` logs stop showing the 400 loop; the five
previously-`NoData` Grafana alert rules start evaluating with real data (even if their actual state
ends up OK/Alerting, they should no longer be `NoData`).

---

## R-10 — Portal sign-out doesn't actually log the browser out

**Status:** unlike R-1..R-9, root cause is **not yet confirmed** — this item captures a live
investigation, not a pinned-down fix. Full writeup: `docs/spec/10-portal-logout-cookie-not-cleared.md`.

**Symptom:** clicking "Sign out" in the portal (`portalSignOut()` in `proxy/app/routers/portal.py`)
does not end the session — the same browser keeps using the old session afterward.

**Confirmed working (ruled out):** the backend logout endpoint (`POST /api/v1/auth/oidc/logout`,
`oidc_browser.py::oidc_logout`) is called and succeeds server-side — two live logout attempts both
returned nginx `200`, and `UPDATE oidc_sessions SET revoked_at = $1 WHERE session_jwt_jti = $2`
actually executed. Cookie-domain mismatch between `set_cookie`/`delete_cookie` was the first
hypothesis but is ruled out in this environment (`SESSION_COOKIE_DOMAIN='localhost'` resolves to
`domain=None` on both calls) — though it remains a **latent bug for any deployment where
`SESSION_COOKIE_DOMAIN` is set to a real value**, since `delete_cookie()` at `oidc_browser.py:742`
passes no `domain=` at all.

**Smoking gun (not yet fully explained):** after the 200 logout response, the browser keeps sending
the same `mcp_session` cookie on subsequent requests — proxy logs show repeated `SELECT revoked_at
FROM oidc_sessions WHERE session_jwt_jti = $1` for the same jti continuing after logout. The cookie
is never actually cleared client-side despite server-side revocation succeeding.
`response.delete_cookie(settings.SESSION_COOKIE_NAME)` (`oidc_browser.py:742`) passes no `secure`,
`samesite`, `httponly`, or `path` arguments, unlike the original `set_cookie` call at
`oidc_browser.py:673-680`. This attribute mismatch alone may not be sufficient to explain a browser
ignoring the deletion (deletion matching is generally name+domain+path only), but it's a real
inconsistency regardless.

**Second, likely-more-important finding:** `AuthMiddleware.dispatch`
(`proxy/app/middleware/auth.py`) gates `/api/v1/auth/oidc/logout` itself — an invalid/expired/
already-revoked cookie gets a 401 before ever reaching `oidc_logout()`'s handler, which is backwards
for a logout endpoint: **a second logout attempt (after the first revokes the session) will 401
instead of idempotently succeeding.** Check whether `/api/v1/auth/oidc/logout` belongs on the same
allowlist that already exempts `/oauth/`, `/.well-known/`, `/auth/enroll`, `/auth/callback` (see the
early-return path around `AuthMiddleware.dispatch` line 191).

**Fix — not yet applied, decisive test queued but not run:**
1. Craft a validly-signed test session JWT (matching `_issue_session_jwt`'s payload shape +
   `settings.PROXY_SECRET_KEY`) with a matching `oidc_sessions` row (`revoked_at IS NULL`), then curl
   `/api/v1/auth/oidc/logout` with that **valid** cookie and inspect the `Set-Cookie` response header
   byte-for-byte. This pins down whether `delete_cookie()` itself emits a working clear-cookie header,
   or whether something between the handler and the client (`AuthMiddleware.dispatch` reconstructing
   the response, nginx, or another middleware) strips `Set-Cookie` on the way out.
2. If the header is present and correct: the bug is front-end (`portalSignOut()`'s `.finally()`
   navigating before the cookie is applied, or a similar race) — re-examine that JS.
3. If the header is missing/malformed: check `AuthMiddleware.dispatch` for the common Starlette
   pitfall of reconstructing a `Response` from `call_next()`'s result without preserving `Set-Cookie`.
4. Regardless of root cause: make `delete_cookie()` at `oidc_browser.py:742` pass the same
   `domain`/`secure`/`samesite`/`path` as the original `set_cookie` call, and decide whether
   `/api/v1/auth/oidc/logout` should be exempted from `AuthMiddleware`'s strict-auth gate so an
   already-invalid/expired/revoked session can still hit logout cleanly and idempotently.

**Acceptance criteria:**
- After clicking "Sign out", the browser's `mcp_session` cookie is actually cleared (verified via
  browser devtools or a repeat curl with the old cookie value returning an unauthenticated response).
- A second logout call on an already-revoked session returns a clean "logged out" response, not 401.
- `delete_cookie()` passes matching `domain`/`secure`/`samesite`/`path` to `set_cookie()`.

---

## Appendix — lower-priority item noted, not assigned

**Stale acceptance-test fixtures registered with no backing container:** `echo` and the three
`echo-superseded-*` tools point at `at3-clean-mcp-fixture` / `at4-clean-mcp-fixture`, containers that
aren't part of the standing lab stack (`podman ps` confirms neither exists), so calls SSRF-block on
DNS failure. These read like leftover `tool_registry` rows from acceptance-test runs that were never
cleaned up. Decide (product-owner call, not a pure bug fix): either deregister them so the catalog
stops advertising dead tools, or spin up the fixture containers as part of the standing lab if the
`echo`/`echo-superseded-*` tools are meant to be permanently callable.
