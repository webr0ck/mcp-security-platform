# Runbook: Incident Triage (First Response)

## When to use this

Start here for any "something is wrong" report that doesn't already point at
one of the specific runbooks below — this is the fan-out point, not a deep
dive on any one subsystem.

## Step 1 — Get the big picture fast

```bash
# Aggregated health across the stack
make health
#  --- Proxy health ---      curl http://localhost:8000/health
#  --- Proxy readiness ---   curl http://localhost:8000/health/ready
#  --- Gateway health ---    curl http://localhost/health
#  --- Grafana health ---    curl http://localhost:3000/api/health

# What's actually running vs restarting/crash-looping?
podman ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" | \
  grep -E "(NAMES|mcp-|proxy|gateway|opa|grafana|loki|minio|vault|redis|ollama|step|keycloak|dex)"

# Grafana dashboards (http://localhost:3000) — start with:
#   observability/grafana/dashboards/mcp-security-overview.json  — top-level health
#   observability/grafana/dashboards/security.json               — OPA denies, auth failures
#   observability/grafana/dashboards/performance.json             — latency/throughput
#   observability/grafana/dashboards/user-activity.json           — per-client call volume
#   observability/grafana/dashboards/idp.json                     — IdP/OAuth-specific
#   observability/grafana/dashboards/debug.json                   — verbose/dev-only
#   observability/grafana/dashboards/lab-environment.json         — lab-only services

# Recent audit events — the canonical "what actually happened" source
podman exec mcp-db psql -U mcp_app -d mcp_security -c \
  "SELECT event_ts, event_type, client_id, outcome, tool_name
   FROM audit_events ORDER BY event_ts DESC LIMIT 50;"

# Loki logs (via Grafana Explore, or directly)
# observability/loki/loki.yml — check retention/config if logs seem to be missing
```

## Step 2 — Check each subsystem in order (fail-closed dependencies first)

Every tool invocation on this platform goes through a gate chain: **auth →
network → SSRF → entitlement → OPA**. A broken gate returns HTTP 200 with a
JSON-RPC error, NOT an HTTP error — a 401 is client-side; anything else
wrong shows up as a 200 with an error body. Check gates in this order,
since an earlier failure masks/explains a later-looking symptom:

1. **Proxy** — `curl -sf http://localhost:8000/health` and `/health/ready`.
   If down: `podman logs mcp-proxy --tail 200`. Note: `--reload` does NOT
   pick up bind-mounted `proxy/app/**` changes on macOS/podman — always
   `podman restart mcp-proxy` after an edit, don't assume it hot-reloaded.
2. **Vault** — `podman exec mcp-vault vault status -address=https://localhost:8200 -tls-skip-verify`.
   Sealed or unreachable Vault breaks every credential-broker path (500s on
   OIDC callback). → `docs/runbooks/vault-init-unseal.md`.
3. **OPA** — `curl -sf http://localhost:8181/v1/policies`. Crash-looping OPA
   (bundle signature/scope error) fail-closes **every** tool invocation.
   → `docs/runbooks/opa-bundle-signing.md`.
4. **Keycloak** — `curl -sf http://localhost:8080/realms/mcp/.well-known/openid-configuration`.
   Broken realm import blocks all new logins.
   → `docs/runbooks/keycloak-client-setup.md`.
5. **Redis** — `podman exec mcp-redis redis-cli ping`. Used for rate
   limiting/anomaly state; a Redis outage degrades those, check
   `admin-request-limits` fail-closed behavior if rate-limit checks start
   denying everything.
6. **DB (Postgres)** — `podman exec mcp-db pg_isready -U mcp_app -d
   mcp_security`. Everything depends on this; check connection counts and
   long-running queries if the app is up but slow:
   ```bash
   podman exec mcp-db psql -U mcp_app -d mcp_security -c \
     "SELECT pid, now()-query_start AS age, state, query FROM pg_stat_activity
      WHERE state != 'idle' ORDER BY age DESC LIMIT 10;"
   ```
7. **Scanner-worker** — `podman logs mcp-scanner-worker --tail 100`; check
   `scan_jobs` queue depth. → `docs/runbooks/scanner-failure.md`.
8. **Build-worker** (if present in this environment) — same pattern as
   scanner-worker; check its own queue table
   (`infra/db/migrations/V072__build_worker_queue.sql`) for dead-lettered
   jobs the same way.
9. **MinIO** — `podman exec mcp-minio mc admin info local` (or check
   `mcp-minio-init` container logs for WORM/Object Lock setup failures on a
   fresh deploy). Affects audit archival and compliance reports only, not
   live request path. → `docs/runbooks/audit-restore.md`.

## Step 3 — Common incident shapes → specific runbook

| Symptom | Runbook |
|---|---|
| Proxy 500s on OIDC callback / KMS unavailable | `vault-init-unseal.md` |
| Policy change has no effect / OPA crash-looping | `opa-bundle-signing.md` |
| New client/user can't log in, redirect_uri mismatch | `keycloak-client-setup.md` |
| Submission scan stuck, dead-lettered, or missing-tool error | `scanner-failure.md` |
| New git host clone fails / SSRF rejection on a legit host | `git-provider-setup.md` |
| Self-hosted server onboarding rejected as private IP | `private-cidr-allowlisting.md` |
| Quarantined tool won't release (403/422/502 on `/release`) | `quarantine-release.md` |
| Need historical audit data / prove tamper-evidence | `audit-restore.md` |

## Step 4 — Escalation / rollback guidance

- **Never** run `podman-compose down -v` or otherwise wipe the `postgres-data`
  or `vault-data` volumes to "get a clean start" — this repo's lab DB is
  accreted, not fresh-bootable (multiple migration/role bugs surface on a
  from-scratch boot), and wiping Vault's data volume orphans the broker KEK
  irrecoverably (see `vault-init-unseal.md`). If you are tempted to do this,
  stop and escalate instead.
- **Rollback a bad policy bundle**: revert `policies/rego/*.rego` in git,
  `make sign-policy-bundle`, `podman restart mcp-opa` — see
  `opa-bundle-signing.md`.
- **Rollback a bad proxy deploy**: redeploy the previous image tag; the
  proxy is stateless aside from its DB/Vault/OPA dependencies, so a
  straight image rollback is safe.
- **Incident scenario drills** — this repo ships four scripted incident
  scenarios for practicing exactly this kind of triage:
  ```bash
  bash lab/incidents/01-stolen-sa-token/trigger.sh
  bash lab/incidents/02-overprivileged-user/trigger.sh
  bash lab/incidents/03-token-exchange-abuse/trigger.sh
  bash lab/incidents/04-m365-mail-exfil/trigger.sh
  ```
  Corresponding Wazuh detection rules: `deployments/poc/wazuh/rules/mcp-audit-rules.xml`
  (rules 100600-100603). Grafana: "Four-Auth Trace" dashboard (PRD-0002).
- If nothing in this table matches, start from `audit_events` (Step 1) to
  reconstruct the actual sequence of calls/denials before guessing at a fix —
  the gate-chain-returns-200 behavior means the real error is almost always
  in the JSON-RPC error body or the audit trail, not the HTTP status code.

## Prevention / Related

- Run `make -f Makefile.lab lab-acceptance` (or the narrower
  `make test-lab-functional`) after any fix, before declaring an incident
  resolved — a broken gate returning 200 is exactly the kind of regression
  that passes a shallow smoke test.
- Keep this table's runbook list in sync as new failure modes get their own
  runbook written.
