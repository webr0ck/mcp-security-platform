# PRD-0006 — MCP Console, LLM×mcp-checker, step-ca in lab, Policy/SIEM docs

- **Status:** DESIGN v2 — revised after 3-critic (Codex=rejected, logic=rejected, security=needs_work).
  v2 corrects a **verified-false premise in R-2** (the logic critic caught it: step-ca already runs in
  the lab and `GATEWAY_SHARED_SECRET` is already set — the real blocker is the mTLS-free lab nginx
  conf) and makes R-1's score-fusion **monotonic-by-construction** (structural `max()` floor only; the
  LLM-prompt-injection-of-scan-text idea is dropped as non-monotonic + a prompt-injection surface).
- **Date:** 2026-07-05
- **Author:** platform team
- **Scope:** (R-1) fold mcp-checker code-scan results into the registration-time Ollama risk score
  + document what the check does; (R-2) run step-ca in the lab and exercise the mTLS agent-identity
  path; (R-3) document the policy engine + detections (config files, update mechanism, Wazuh
  dependency) — no admin-UI management required, description only; (R-4) generic SIEM via syslog,
  documented in README + ARCHITECTURE; (R-5) the **MCP Console** admin UI imported from the Claude
  Design project.
- **Non-goals:** rego editing via UI (stays file-edit + `make sign-policy-bundle`); asymmetric bundle
  signing; replacing Wazuh; a full SIEM connector marketplace.
- **Precedents:** PRD-0005 admin surfaces (`admin_llm.py` already ships the Ollama config the user
  asked for); the vendored mcp_checker (PRD-0005 R-1 scanner); `mcp-audit-logger` single emit point.

## Blockers / dependencies

- **R-5 MCP Console** depends on importing the Claude Design file `MCP Console.dc.html`
  (project `5b5ec562-…`). DesignSync needs an interactive **`/design-login`** (the user's claude.ai
  authorization) — not runnable headlessly. **R-5 is BLOCKED until that authorization is granted**;
  R-1..R-4 are independent and proceed now.

---

## R-1 — LLM manifest scorer × mcp-checker code scan

### What the Ollama check actually does (documentation deliverable)
`auditor.py::run_llm_analysis` runs **only at tool registration / re-audit** (never on invoke —
verified: `run_audit` callers are all in `tools.py` register/patch/rerun/discovery). It sends the
tool's **name, description, parameter descriptions, and JSON schema** to Ollama and asks for a
0–100 `risk_score` plus `prompt_injection_detected`, `excessive_scope_detected`,
`suspicious_parameter_names`. This is combined with a **static manifest analysis**
(`run_static_analysis`) via `STATIC_WEIGHT`/`LLM_WEIGHT`; an injection flag boosts to critical; a
score over threshold quarantines the tool. **It scores the declared manifest, not the code.**

### Problem
The manifest scorer is blind to what the mcp-checker submission scan already found in the **actual
repo code**. The link exists in the schema — `tool_registry.server_id` FK (V023/V031) ties a
discovered tool to its submission's `server_registry.scan_report` (V044) — but `run_audit` never
reads it (`auditor.py` has zero `scan_report` references today).

### Design (monotonic-by-construction — 3-critic fixes F-1/F-2/F-3)
- **Structural score floor only.** After the existing combined score is computed, apply
  `combined_score = max(combined_score, floor)` — implemented **identically to the existing
  prompt-injection escalation** at `auditor.py:322-324` (`max(combined_score, CRITICAL_THRESHOLD)`).
  `floor` is derived **structurally** from the presence of a mcp_checker **block-tier** finding
  (malicious_doc_ast, `*_attack_patterns`, crypto_stealer, memory_poisoning, silent_exfil_pattern,
  obfuscation_scan) OR `scan_status='blocked'`. Because it is a one-directional `max()`, it **can only
  raise** the score — no monotonicity claim rests on the non-deterministic LLM output.
- **The LLM-prompt-context idea (v1 item 1) is DROPPED.** Feeding attacker-authored scan-finding text
  into the LLM prompt is (a) non-monotonic (llm_score is weighted 0.6, can move either way) and (b)
  reopens the exact prompt-injection surface the auditor defends against (DET-F8). Not worth it.
- **Trigger keyed off `scan_status` + `server_id`, not scan_report presence** (F-3: scan_report is
  `NOT NULL DEFAULT '[]'`, never absent). A tool registered directly (`POST /tools`, `server_id IS
  NULL`, no submission) has no scan → **manifest-only, unchanged** (correct fail-safe). Only a
  server-linked tool whose `scan_status='blocked'` or whose scan_report carries a block-tier finding
  gets floored.
- **Staleness signal (F-3).** Add `scanned_at` + `commit_sha` to the scan (new columns on
  `server_registry`, written by `submission_scanner`). At re-audit, if the floor fires, record the
  `scanned_at`/`commit_sha` on the audit so a reviewer can see the flooring scan may predate a repo
  fix and trigger a rescan. The floor still fires (conservative — over-flag is the safe direction).
- **Admin config already shipped** (PRD-0005 R-1 LLM Provider tab). This PRD adds the "what the check
  does" documentation (above) to that tab + spec.
- **Exit / blast radius:** one-directional `max()` — cannot weaken the gate. Worst case a stale
  block-tier scan over-flags a since-fixed tool; the `scanned_at`/`commit_sha` on the audit surfaces
  it and a rescan clears it. Never lowers a score.

## R-2 — step-ca in the lab + mTLS agent-identity test  ✅ DONE

**Status:** Implemented + verified (8/8 smoke). The lab nginx now verifies step-ca client certs on
`/api/v1/tools/`: `mcp-proxy-lab.conf` gains `ssl_client_certificate` + `ssl_verify_client optional`,
a CN-extraction + path-scope map (`00-mtls-map.conf` — the CRS nginx 1.30.1 lacks `$ssl_client_s_dn_cn`
so it regexes CN from `$ssl_client_s_dn`), the real `X-Gateway-Secret` via a gitignored include, and
the 401-on-`!SUCCESS` gate. `lab/tests/mtls_agent_identity.sh` sets up (CA extract + secret gen + mint
agent cert, all gitignored) and asserts: OIDC unbroken (307), no-cert `/api/v1/tools/` → 401,
agent-cert → 403 with the proxy resolving `agent:{ca}:agent-lab-01` (audited, fail-closed). E2E
lifecycle re-verified (12/12) — the gateway change didn't break the submission flow.

### Problem (CORRECTED by 3-critic — v1 premise was verified-false)
step-ca **already runs in the lab** (`mcp-step-ca` container up now; `Makefile.lab` `LAB_COMPOSE`
merges `-f docker-compose.yml` which defines the service) and `GATEWAY_SHARED_SECRET` **is already
set** (`.env.lab:42`). So `auth.py::_is_trusted_proxy` does **not** disable CN auth. The **actual**
reason the mTLS agent-identity path (`agent:{MTLS_CA_ID}:{cn}`) is never exercised in the lab is that
the lab mounts a deliberately **mTLS-free nginx conf**: `lab/nginx/conf.d/mcp-proxy-lab.conf:33`
sets `ssl_verify_client off` and `:62` forces `X-Client-Cert-CN ""`. No client cert is verified, so
no CN is ever forwarded.

### Design (fix the actual root cause: the lab nginx conf)
- **Enable client-cert verification in the LAB nginx conf**, replicating the production gateway
  pattern **exactly** (security-critic F: name the exact lines, don't half-copy):
  - Mount the step-ca **root CA** into the gateway and add `ssl_client_certificate <ca.crt>;` +
    `ssl_verify_client optional;` (optional, **not** `optional_no_ca` — must be CA-verified).
  - Add the path-scoped `map $ssl_client_s_dn_cn $client_cert_cn_safe { … }` and forward
    `X-Client-Cert-CN $client_cert_cn_safe` **only on `/api/v1/tools/`** (matches
    `gateway/nginx/nginx.conf:54-57`), and always **overwrite** it elsewhere so a client cannot inject
    it (matches `gateway/nginx/conf.d/mcp-proxy.conf:67`).
  - Forward the real `X-Gateway-Secret` (already in `.env.lab`), and add the 401-on-`!SUCCESS` gate on
    the mTLS location (matches `mcp-proxy.conf:92-95`). **Do not** copy header-forwarding without the
    path-scoping + verify gate — that would be a spoofing regression.
- **Issue a lab agent client cert** from the already-running step-ca (24h TTL, INV-010).
- **Smoke test** (`lab/tests/`): present the agent cert through the gateway → assert the proxy
  resolves an `agent:{ca}:{cn}` principal, an unentitled agent is denied (fail-closed), and a request
  **without** a cert to a non-tools path still works (existing OIDC lab flows unbroken).
- step-ca already boots, so there is no new bootstrap-idempotency risk. Additive: a new lab nginx
  conf variant + a cert; the existing OIDC path is untouched.
- **Exit / blast radius:** lab-only; 24h cert TTL bounds a leaked lab cert; the mTLS location is
  path-scoped so non-tools flows are unaffected.

## R-3 — Policy engine & detections: documentation (no UI management)

### Decision
The user confirmed **no need to manage policy through the UI** — description only. So this is a
**documentation deliverable** (spec `03-policy-and-detections.md` + ARCHITECTURE §6), stating:
- **Config files & what each does:** `policies/rego/authz.rego` (deny-by-default entitlement/RBAC/
  meta-tool gate), `anomaly.rego`, `tool_risk.rego`; `policies/semgrep.yml` (SAST gate);
  the vendored `proxy/vendor/mcp_checker/policies/*` (submission SAST); Wazuh
  `deployments/poc/wazuh/rules/*.xml` + decoders (SIEM detections).
- **How it's changed/reloaded:** dev = OPA `--watch` auto-reload on `.rego` edit; prod = edit rego →
  **`make sign-policy-bundle`** → restart OPA (editing rego without re-signing is a silent no-op —
  call this out as a footgun). `routers/policy.py` is **read-only** (lists loaded rules for admin/
  auditor); there is intentionally no write endpoint.
- **The few runtime-tunable knobs** that ARE DB-backed (not rego): per-client rate-limit / anomaly
  sensitivity (`admin_limits.py`), and now LLM config (`admin_llm.py`). Document that these are the
  only live-tunable controls; everything else is git + bundle-sign.

### Wazuh dependency (documentation)
- Wazuh is **POC-only** (`compose.poc.yml`), **not** the lab or base runtime. The taint-floor
  detections (`deployments/poc/wazuh/rules/mcp-taint-floor.xml`, rules 100001–100003) consume the
  proxy's **stdout audit JSON** via a **Filebeat** sidecar → Wazuh manager (5044), plus a syslog
  (UDP 514) path and a local decoder. There is a `lab-wazuh` container but the detection rules run in
  the POC topology. Document that Wazuh is an *optional detection consumer* of the audit stream, not
  a hard runtime dependency, and that the taint-floor itself is dark unless `TAINT_FLOOR_ENABLED`.

## R-4 — Generic SIEM via syslog (documented)

### Decision
The user is fine with **syslog for now**. Today audit events are emitted as **stdout JSON** from the
single `mcp-audit-logger` emit point, consumed by Promtail→Loki (lab) and Filebeat→Wazuh (POC).
There is **no generic export/webhook**.

### Design (minimal, documented)
- Document the **existing** integration path in README + ARCHITECTURE: "any SIEM that can tail
  container stdout JSON, or receive syslog, consumes the audit stream — the schema is
  `mcp-audit-logger/schema.py`; point your collector (Filebeat/Fluent Bit/Vector/rsyslog) at the
  proxy's stdout or the syslog forwarder." No new code required for syslog: a sidecar/collector maps
  stdout→syslog. This is the "simple way to integrate any SIEM" for now.
- **Roadmap note:** a first-class in-proxy syslog/HTTP-CEF sink (configurable in the Console) is
  deferred; the stdout-JSON contract is the stable integration seam.

## R-5 — MCP Console (admin UI) — DESIGN IMPORTED, ready to build

**Design imported** (`/design-login` granted): `docs/design/mcp-console/MCP-Console.html` (84 KB,
dark-themed SPA mockup). It covers the same functional domains as the live portal: Dashboard
(recent detections, registered tools, SBOM stats), Servers & Tools, SBOM (signed/missing/components,
View JSON), Submissions (Approve / Request changes / Reject, server details, operational contract),
Access & Limits (rate, anomaly sensitivity, manage access, client-id/allowed-tools/tags/max-risk,
roles, revoke), Credentials (OAuth authorization, enrollment), Catalog / Submit-a-server, plus
"View as" role-switching, a Keycloak-connection panel (reconfigure / test / save), and principal/
session/sign-out. It is a **reskin of the existing admin surface**, not new capability.

### The architectural fork (must decide before building)
The repo ships **two UIs**: the **live server-rendered HTMX portal** (`proxy/app/routers/portal.py`,
what users actually use + what the acceptance tests target) and a **prebuilt React `ui/`** (bundles
only). The console can be built as either:
- **(A) Reskin the live portal** — restyle `portal.py`'s fragments to the console design, wiring the
  same JSON APIs (all already exist: `/api/v1/admin/*`, `/api/v1/submissions`, `/api/v1/tools`, …).
  Lowest risk, immediately live, no new build pipeline, keeps acceptance tests working.
- **(B) Build the React `ui/`** into a real console app against the same APIs. Cleaner long-term
  frontend, but a larger lift and a second surface to keep in sync.

### Build plan (after the fork is chosen)
Dispatch a **team of agents** per domain (dashboard, servers/tools, submissions, access/limits,
credentials, SBOM, catalog/submit), 3-critic the wiring decisions (auth, RBAC-gated nav, the
"view as" role switch must NOT bypass server-side RBAC), implement, then a **red-team pass** (can a
non-admin reach admin fragments? does "view as" grant real access or only change the view? are the
Keycloak-reconfigure and OAuth panels write-gated?). This is a multi-phase UI build tracked as its
own effort.

---

## Implementation order (after critic sign-off)
1. R-3 + R-4 (documentation — fast, no risk) → 2. R-1 (LLM×mcp-checker) → 3. R-2 (step-ca lab) →
4. R-5 (Console, once `/design-login` is granted). Full test + **red-team** pass at the end
(`sandbox/tests/red_team/` + the submission red-team fixtures).
