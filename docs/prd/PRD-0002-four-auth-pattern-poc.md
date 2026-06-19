# PRD — Four-Auth-Pattern MCP Lab POC (traceable credential models, end-to-end)

**Version:** 1.0.0 (**APPROVED** — exits draft; 4 × 3-critic rounds folded in)
**Date:** 2026-06-18
**Owner:** product-owner / Alexander
**Repo:** `~/Code/mcp-security-platform`
**Companion docs:** `docs/ARCHITECTURE.md`, `docs/PRD-delegated-downstream-auth.md`, `LAB.md`, `Vault/KB/mcp-security-platform/local-lab-podman.md`
**Critic gate:** R1 → REJECTED; R2 → REJECTED (security fail-opens) + 2×needs_work; R3 → impl APPROVED, logic+security needs_work; **R4 (2026-06-18) → APPROVED (all 3 lenses; impl feasibility 5/5)**. All folded in (§10). **Carry-forward to implementation (non-blocking, §14).**

---

## 1. Problem & opportunity

The platform already enforces auth, RBAC, OPA, and credential injection for MCP tool calls. What it does **not** yet do is present a **complete, side-by-side, demonstrable set of the canonical upstream-credential models** an enterprise MCP gateway must broker — and prove, in a SIEM, that each is **attributable during an incident**.

A reviewer (FAANG panel, UK GTV endorser, conference audience) should watch four structurally different auth patterns run through one gateway and then, given an alert, **pivot from SIEM detection → human user → credential model → exact tool call** for every one — and understand *why some patterns lose user attribution upstream and some preserve it*.

**Goal:** finish four canonical, **broker-injectable** integrations, auto-provision them so the lab comes up green in two commands, emit a **uniform, case-labelled audit trace** into Grafana/Loki + Wazuh, and ship four scripted incident scenarios that each prove the trace pivot.

### Non-goals
- Not production (`INSTALL.md`). Lab posture stays relaxed except where a fix keeps a *teaching claim* true (§6).
- Not Jira. Jira-as-the-same-IDP-service is too heavy to provision in-lab; case 4 uses a **lightweight custom resource service** on the same Keycloak realm that exercises the identical pattern.
- Not "finalize four things that already exist." §3 accounts honestly — **most of this is net-new build.**

---

## 2. The four canonical cases (modes = exact `InjectionMode` enum in `dispatcher.py`)

**Hard requirement (user):** every case is **broker-injectable** — the credential is injected by the proxy into the upstream request (header / exchanged token), *not* read from the MCP server's own env. This rules out the current third-party `injection_mode='none'` env-token shortcut for Grafana/NetBox.

| # | Case (the pattern it teaches) | Upstream system | Injection mode | IdP topology | Upstream attribution | Secret at rest |
|---|---|---|---|---|---|---|
| **1** | **Second IdP (machine identity)** | Microsoft Graph (custom M365 MCP, broker-injected); `AZURE_MODE=real` live Entra or `mock` local emulator | `entra_client_credentials` | **Different IdP** (Entra ≠ gateway Keycloak) | **Lost** — app / service principal | Entra client secret |
| **2** | **Service account (shared static key)** | Grafana (real, in-stack) via a **header-injecting** Grafana MCP shim | `service` (broker-injected shared SA bearer) | none (API key) | **Lost** — one shared SA | Long-lived static SA token |
| **3** | **Per-user stored token (BYO secret)** | NetBox (real, in-stack) via **new** header-injecting NetBox MCP `server.py` | `user` (per-KC-subject token, AES-256-GCM encrypted, injected) | none (API token) | **Preserved** — alice→alice | Per-user long-lived token, encrypted |
| **4** | **Same IdP as the gateway (federated identity, no stored secret)** | **New lightweight `lab-tickets`** OAuth2 resource-server MCP (Jira-substitute) on the **same Keycloak realm** | `kc_token_exchange` (RFC 8693, within-realm; broker exchanges alice's gateway token for a `lab-tickets`-audience token) | **Same IdP** (gateway Keycloak) | **Preserved** — alice→alice, **`sub==caller` asserted in-code (S-5)** | **None** — ephemeral exchanged token |

> **Case-1 / S-1 clarity (logic critic):** app-only `entra_client_credentials` is case 1's *declared, intended* design (a 2nd-IdP machine identity). S-1 forbids *silent degradation into app-only* only for tools registered as **delegated/per-user** (cases 3–4) — it does not contradict case 1.

### The teaching contrast (the whole point)
Four orthogonal dimensions vary cleanly:
- **IdP topology:** case 1 = *second/foreign* IdP (Entra); case 4 = *same* IdP (the gateway's Keycloak); cases 2–3 = no IdP (raw key/token).
- **Attribution:** 1 & 2 **lose** the human upstream (machine/shared identity) — **attribution exists only at the gateway audit layer**; 3 & 4 **preserve** the human end-to-end.
- **Secret at rest:** app secret (1) → static shared key (2) → per-user stored token (3) → **none** (4, ephemeral exchanged token).
- **Injection mode:** `entra_client_credentials` → `service` → `user` → `kc_token_exchange` — one of each, all broker-injected.

> **Claim discipline (security critic):** the case-4 "no stored secret / identity preserved" claim is admissible **only because we own the resource server** and assert `sub==caller` on the exchanged token (S-5). It is backed by an acceptance test (A-3), not a narrative.

---

## 3. Reality accounting — exists vs net-new (verified 2026-06-18)

| Component | State today | Work |
|---|---|---|
| Credential broker injection-mode handlers (`service`/`user`/`kc_token_exchange`/`entra_client_credentials`) | ✅ handlers exist + fail-closed (`dispatcher.py`) | reuse |
| **Case 4 token-exchange path — DORMANT, not "reuse"** | ⚠️ code path exists but is fully off: `--features=token-exchange` **not set** at KC boot; `KC_TOKEN_EXCHANGE_ENABLED=False` (`config.py:216`) → `exchange_token()` returns `None` before calling KC; **no `sub==caller` validation** in `exchange_token()` | **4 net-new wiring steps + in-code assertion** (S-5/S-6); gated behind a P0 spike (§9) |
| Custom M365/Graph MCP (app-only/delegated) | ✅ exists (`lab/mcp-servers/m365`); **but tool row is seeded `entra_user_token` (delegated), not `entra_client_credentials`** | reuse app-only path; **re-seed tool row to `entra_client_credentials`**; broker-inject |
| `AZURE_MODE=mock` Graph/Entra emulator | ❌ does not exist | **build = 3 coordinated sub-builds**: (a) `client_credentials` grant + Graph-audience token in `mock-idp` (today only does auth_code/device_code, `aud=mcp-proxy`); (b) a Graph stub answering `/me`,`/messages`,`/users`; (c) make the M365 server's token URL (hardcoded `login.microsoftonline.com`) + Graph base URL **env-configurable** |
| Grafana **header-consuming** MCP server | ❌ today = third-party `grafana/mcp-grafana` image reading `GRAFANA_SERVICE_ACCOUNT_TOKEN` env (`injection_mode='none'`); **no `lab/mcp-servers/grafana/` dir exists** | **build a net-new MCP server** (not a "shim" over the env image) that consumes the broker-injected `Authorization` header and forwards to the Grafana API; ships a contract test |
| NetBox MCP `server.py` | ❌ **only a `Dockerfile`** | **build** (reads injected header, `user` mode) |
| `lab-tickets` same-IDP resource service + MCP | ❌ does not exist | **build** (OAuth2 protected resource on realm; validates `aud=lab-tickets` + `sub`; is the in-app half of S-5) |
| KC token-exchange feature + scoped permission + `lab-tickets` client | ❌ feature flag off; realm has 6 clients, no `lab-tickets`; **no fine-grained token-exchange permission policy anywhere** | **enable `--features=token-exchange` at boot; set `KC_TOKEN_EXCHANGE_ENABLED=true`; add `lab-tickets` client; ship a scoped exchange permission policy (S-6)** |
| Wazuh full SIEM (indexer+dashboard) | ⚠️ `compose.wazuh.yml` = manager only; indexer/dashboard in `compose.poc.yml` at **4.7.5** vs manager **4.9.1** | **add indexer+dashboard, align to 4.9.x, separate profile** |
| Detection rules | ✅ 8 exist | extend with 4 scenario rules |
| Grafana dashboards | ✅ exist | add "Incident Trace" dashboard |
| Incident triggers | ❌ none | **build 4 scripts** |
| `smoke_four_cases.sh` bring-up smoke harness | ❌ does not exist (only `lab-smoke.sh`/`lab-setup.sh`) | **build** (P0 pass bar = 3/4) |
| M365 tool-row mode | ⚠️ credential row already `entra_client_credentials` (`seed.py:680`); **only the tool row is `entra_user_token`** (`tools.sql:68`) | **one-line `tools.sql` change** (easier than implied) |

**Vikunja and Gitea are out of scope** (superseded: NetBox = per-user, `lab-tickets` = same-IDP). Net-new build is the majority of this PRD — framed honestly, this is a build.

---

## 4. Auto-provisioning (the two-command bring-up contract)

```bash
make -f Makefile.lab lab-up      # core stack: 4 cases green (AZURE_MODE=mock default), no external creds
make -f Makefile.lab wazuh-up    # full Wazuh SIEM profile (incident demo)
make -f Makefile.lab incidents   # optional: list/run the 4 scripted scenarios
```

Per-case provisioning (idempotent; `lab/seeder/seed.py` + compose + `realm-mcp.json` import):

- **Case 1 (Graph / 2nd IdP):** compose service for custom M365 MCP; `.env.lab` `AZURE_MODE` (`mock` default). Mock: mock-IdP issues the app token, Graph stub answers `/me`,`/messages`. Real: operator fills `AZURE_TENANT_ID/CLIENT_ID/CLIENT_SECRET`. Tool row `injection_mode='entra_client_credentials'`. **S-1: app-only is the declared mode here, not a fallback** — no delegated tool may silently degrade into it.
- **Case 2 (Grafana / service):** seeder provisions a Grafana service account + token (Grafana provisioning API); token stored in the **broker** (not server env); Grafana MCP shim reads the broker-injected header; tool row `injection_mode='service'`.
- **Case 3 (NetBox / per-user):** seeder creates NetBox users alice/bob/carol, generates a per-user API token each, stores each encrypted under the KC subject; NetBox MCP `server.py` reads the injected header; tool row `injection_mode='user'`.
- **Case 4 (lab-tickets / same IdP):** add `lab-tickets` confidential client + token-exchange permission to the realm; `lab-tickets` resource server validates `aud=lab-tickets` + `sub`; broker exchanges the caller's gateway token; tool row `injection_mode='kc_token_exchange'`. Seed 3 demo tickets per user.

**§4 acceptance (P0):** `make lab-reset && lab-up` on a machine with **no external credentials** → **cases 1–3 `status=active`, `lab/scripts/smoke_four_cases.sh` returns 3/4** (the P0 pass bar; case 4 goes active only after P1 / A-1b — 3/4 is not a regression). `AZURE_MODE=real` is opt-in, never required for green. (`smoke_four_cases.sh` is itself net-new — see §3.)

---

## 5. Observability & the incident-trace contract

### 5.1 Uniform trace schema (every tool call, every case)
Standardise the existing audit fields so one Grafana panel + one Wazuh decoder cover all four:
```
ts, trace_id, case_id(1-4), gateway_user_sub, gateway_user_name, gateway_role,
tool_id, injection_mode, upstream_system, upstream_principal,
attribution_preserved(bool), idp_topology(same|second|none), decision(allow|deny),
opa_rule, latency_ms
```
`attribution_preserved` (false for 1–2, true for 3–4) and `idp_topology` are computed at audit time — these are the fields the dashboard pivots on and a reviewer checks against the slides.

### 5.2 What each case looks like in the SIEM
- **Case 1/2:** `gateway_user_sub=alice` but `upstream_principal=<app|shared-sa>`, `attribution_preserved=false`. Upstream (Graph/Grafana) log shows only the machine identity → **the attribution gap, dramatized.**
- **Case 3/4:** `upstream_principal=alice`, `attribution_preserved=true`; NetBox/`lab-tickets` logs independently corroborate the human (case 4 additionally proves `sub==caller`).

### 5.3 Grafana "Incident Trace" dashboard
Input a `trace_id`/`alert_id` → resolves **alert → gateway_user → injection_mode/credential → tool_call → upstream_principal**, with `attribution_preserved` red/green and `idp_topology` shown. Loki datasource; built on existing provisioning.

### 5.4 Wazuh
Full SIEM as a **separate profile** (`make wazuh-up`): manager + indexer + dashboard, **all pinned to 4.9.x** (fixes the 4.9.1/4.7.5 split). Decoder for the trace schema + the 4 scenario rules; native Wazuh hunting UI demonstrates tracing alongside Grafana.

---

## 6. Security fixes required to keep teaching claims true (security critic)

| ID | Fix | Why |
|---|---|---|
| S-1 | `REQUIRE_DELEGATED=true` default for delegated/per-user tools; app-only is opt-in per tool | Stops user→app silent identity downgrade (live fail-open today) that would falsify case-3/4 attribution |
| S-2 | OIDC `aud` validation **fail-closed whenever token-exchange is enabled, regardless of `ENVIRONMENT`** — and the value must be **correct + single**, not merely non-blank | **Round-2 finding:** today refuse-start only fires for `ENVIRONMENT ∈ {production,staging}`; the lab runs `development` (blank `aud` → `verify_aud=False`, warning only). Case 4 enables token-exchange in that exact profile → audience confusion. Fix: a new config gate — `KC_TOKEN_EXCHANGE_ENABLED=true` forces `verify_aud=True` even in development and **requires `OIDC_AUDIENCE` to equal the expected proxy audience and to be a single value (reject blank, reject comma/space-list multi-audience)**, else refuse-start. **Round-3:** tests A-5b cover *both* blank *and* wrong-but-set/multi-audience → refuse-start or proven `verify_aud` rejection. |
| S-3 | Mock-IdP / mock-Azure **never** the issuer in a shipped/demo profile; keep `ENVIRONMENT!=development` JWT-role-strip | Mock issuers mint self-asserted roles → escalation if trusted |
| S-4 | **Pin image digests** (M365 base, Grafana, NetBox, Wazuh 4.9.x indexer+dashboard, KC, Grafana-shim base) + ship the trust-base list (A-9) | Supply-chain: unvetted credential-handling deps, several net-new |
| S-5 | **Runtime assertion inside `_inject_kc_token_exchange`/`exchange_token`** (not just a downstream check): (i) **signature-verify the exchanged token against KC JWKS *before* trusting any claim** (use the existing `discover_jwks_uri`; PyJWT already imported as `jwt`); (ii) assert `sub == caller`, `aud == lab-tickets`; (iii) assert the RFC 8693 `act` chain has **actor == `mcp-proxy` and exactly one hop** (deeper nesting ⇒ unintended re-exchange ⇒ reject); raise `CredentialInjectionError` on any mismatch. The assertion must run on **every injection including Redis cache hits**, not only on fresh mint. `lab-tickets` resource server re-validates as defence-in-depth. | **Round-2/3 finding:** `exchange_token()` returns the token undecoded → confused-deputy unmitigated *in code*; a decode-without-signature-verify would be forgeable. The "identity preserved / no stored secret" claim is admissible only with this in-code, signature-verified assertion. Cited test A-3b. |
| S-6 | **Scoped token-exchange permission, two layers:** (a) **KC realm policy** — ship a concrete `realm-mcp.json` diff adding a KC-24 fine-grained `token-exchange` permission on the **target `lab-tickets` client's `authorizationSettings`** (resource=client, scope=token-exchange, client-policy granting `mcp-proxy`) — *not* on `mcp-proxy` itself; (b) **proxy-side allowlist** — `_inject_kc_token_exchange` asserts `tool_record['kc_token_audience'] ∈ {lab-tickets}` **before** calling `exchange_token`, and `requested_token_type` is pinned to `access_token`, so a malicious/buggy DB row can't widen the mint even if the realm policy regresses. | **Round-2/3 finding:** realm-level `--features=token-exchange` + privileged `mcp-proxy` client + DB-controlled `kc_token_audience` = the proxy could mint *any* realm audience. KC 24 places the permission on the **target** client (impl-critic correction). Negative test A-3c proves a non-`lab-tickets` audience exchange is **denied at both layers**. |

No `docs/SECURITY_NONNEGATABLES.md` invariant (deny-by-default OPA, no fail-open injection, audit completeness, encrypted-at-rest) may be weakened. Broker dispatch stays fail-closed; **S-2/S-5/S-6 move the case-4 security from narrative into the code path and the realm policy** — this is the crux of the round-2 rejection and the gate for re-submission.

---

## 7. Scripted incident scenarios

Each ships a trigger (`lab/scripts/incidents/<name>.sh`), a Wazuh rule (`detections/<name>.yml`), and a Grafana trace deep-link. Acceptance = the trace pivot resolves correctly.

| Scenario | Case | What it does | What the SIEM shows |
|---|---|---|---|
| `stolen-sa-token` | 2 | Replays the shared Grafana SA token from an unexpected caller | Fires; `attribution_preserved=false` — **only the gateway log identifies the human** |
| `over-privileged-user` | 3 | bob calls a NetBox tool reading data outside his role | OPA/role anomaly; trace cleanly attributes bob; NetBox log corroborates |
| `token-exchange-confusion` | 4 | A `lab-tickets`-audience token presented back to the gateway (audience confusion attempt) | S-2 denies fail-closed; trace shows the rejected audience + `sub` |
| `m365-mail-exfil` | 1 | App-only Graph reads bulk mail (mock/real) | Volume anomaly; `upstream_principal=app`, `idp_topology=second` — **attribution gap**, and S-1 blocks a delegated call degrading into it |

---

## 8. Acceptance criteria (done = tested)

| ID | Pri | Criterion |
|---|---|---|
| A-1 | P0 | `make lab-reset && lab-up`, no external creds → **cases 1–3 active, smoke 3/4 green** (`AZURE_MODE=mock`); the case-4 enablement spike (§9) has **passed**. (4/4 green is A-1b, P1, when case 4 is built.) |
| A-2 | P0 | Each case emits §5.1 schema with correct `injection_mode`, `upstream_principal`, `attribution_preserved`, `idp_topology` |
| A-3 | P0/P1 | Cases 1–2 → `attribution_preserved=false`; 3–4 → `true`, each backed by an upstream-log test (S-5 defence-in-depth half) |
| A-3b | P1 | **In-code** `exchange_token()` assertion test: a forged exchanged token with `sub≠caller` or `aud≠lab-tickets` → `CredentialInjectionError` (S-5) |
| A-3c | P1 | **Negative** scoping test: `mcp-proxy` attempting to exchange for `aud=grafana` (or any non-`lab-tickets`) → **denied** by the realm policy (S-6) |
| A-4 | P0 | Every built case is **broker-injected** (no `injection_mode='none'` env-token path); test proves the proxy injects the credential |
| A-5 | P0 | S-1 verified: delegated tool with missing user token is **denied** not app-fallback |
| A-5b | P1 | S-2 verified: booting the case-4 (token-exchange) profile with blank `OIDC_AUDIENCE` → **refuse-start**, even with `ENVIRONMENT=development` |
| A-6 | P1 | `make wazuh-up` → full SIEM (4.9.x) green; decoder parses schema; Wazuh search resolves a `trace_id` |
| A-7 | P1 | Grafana Incident-Trace dashboard pivots alert→user→credential→tool-call for all 4 |
| A-8 | P1 | All 4 incident scripts run; each fires its detection and resolves its trace |
| A-9 | P1 | Third-party images pinned by digest; trust-base list in `docs/`; `AZURE_MODE=real` overlay documented + smoke-tested once |
| A-10 | P2 | KB defence notes authored (§13) |

---

## 9. Phased delivery (critic-recommended: prove 2 green before 3/4)

- **P0 — Cases 1, 2, 3 green + observability spine + case-4 enablement spike.**
  - Custom M365 broker-injected (`entra_client_credentials`, re-seeded) + `AZURE_MODE=mock` (3 sub-builds); net-new Grafana header-consuming MCP server; NetBox `server.py`; uniform trace schema; S-1/S-3/S-4 + A-4.
  - **Case-4 enablement spike (≤1-day timebox, gates all case-4 build):** prove that with `--features=token-exchange` + scoped S-6 policy + `KC_TOKEN_EXCHANGE_ENABLED=true`, the broker can exchange a caller token for `aud=lab-tickets` AND the S-5 signature-verified `sub==caller`/`aud`/`act` assertion fires on a forged token AND S-2 refuse-start works in `development`. **Concrete spike deliverable:** the exact KC-24 `authorizationSettings` JSON block on the **`lab-tickets`** target client (the permission lives on the target client, not `mcp-proxy`). If the spike fails its timebox → trigger the §12 fallback (genuine no-exchange forward).
  - Exit: A-1, A-2, A-4, A-5, **spike passed**.
- **P1 — Case 4 (`lab-tickets` resource server + token-exchange, with S-2/S-5/S-6 in code) + full Wazuh + Incident-Trace dashboard + 4 scenarios.** Exit: A-1b, A-3, A-3b, A-3c, A-5b, A-6..A-9.
- **P2 — Polish, KB notes, `AZURE_MODE=real` validation, third 3-critic + publish-gate.** Exit: A-10 + APPROVED.

---

## 10. Critic ledger (1 × 3-critic 2026-06-18 → REJECTED) — dispositions

| Finding | Disposition |
|---|---|
| B-1: Gitea/NetBox APIs reject KC JWTs; token-exchange-to-their-API invalid | **Accepted** — same-IDP showcase moved to a custom `lab-tickets` resource server we control (valid kc_token_exchange target); Gitea dropped |
| B-2: NetBox MCP has no `server.py`; Gitea adapter is static token | **Accepted** — NetBox server.py is net-new (§3); Gitea out of scope |
| B-3: `AZURE_MODE=mock` absent; "finalize" overstates | **Accepted** — §3 reality table; reframed as build |
| B-4: full Wazuh won't fit 6GB; 4.9.1/4.7.5 split | **Accepted** — separate `wazuh-up` profile, pin 4.9.x (§5.4) |
| B-5: broker mode labels conflated | **Accepted** — §2 uses exact enum values, one per case |
| B-6: `REQUIRE_DELEGATED` unset → app-only fail-open | **Accepted** — S-1 |
| B-7: blank `aud` fail-open | **Accepted** — S-2 (now load-bearing: case 4 enables token-exchange) |
| B-8: "zero secret/identity preserved" unverifiable | **Accepted** — admissible only via owned resource server + S-5 assertion |
| B-9: no failure/exit/bear case | **Accepted** — §12 |
| B-10: supply-chain unacknowledged | **Accepted** — S-4 |
| **New (user direction)**: Grafana/NetBox must be **injectable**, not env-token | **Folded in** — A-4; net-new Grafana MCP server + NetBox server.py |

### Round 2 (2026-06-18 → REJECTED on security) — dispositions
| Finding | Disposition |
|---|---|
| R2-1 (sec): S-2 audience refuse-start only fires in prod/staging, not the `development` lab profile where case 4 runs → fail-open | **Accepted** — S-2 rewritten: `KC_TOKEN_EXCHANGE_ENABLED=true` forces non-blank `aud` + `verify_aud=True` regardless of `ENVIRONMENT`; test A-5b |
| R2-2 (sec): no in-code `sub==caller` assertion; `exchange_token()` returns token undecoded → confused-deputy | **Accepted** — S-5 now an in-code assertion in `_inject_kc_token_exchange`/`exchange_token` (decode + `sub`/`aud`/`act` checks); test A-3b |
| R2-3 (sec): realm-level token-exchange + privileged proxy client + DB-controlled audience = unscoped audience minting | **Accepted** — S-6 scoped permission policy (realm diff) + negative test A-3c |
| R2-4 (impl): §3 labels case-4 "reuse" but path is dormant (feature flag, config flag, no client, no policy) | **Accepted** — §3 row rewritten "DORMANT"; spike gated in §9 |
| R2-5 (impl): Grafana "shim" is a net-new header-consuming MCP server | **Accepted** — §3/§9 relabelled "net-new MCP server", contract test |
| R2-6 (impl): `AZURE_MODE=mock` is 3 coordinated builds + tool-row mode change | **Accepted** — §3 row enumerates the 3 sub-builds + re-seed |
| R2-7 (impl): P0 4/4-green is hostage to the preview token-exchange feature | **Accepted** — A-1 re-scoped to 3/4 + spike-passed; 4/4 is A-1b/P1 |
| R2-8 (logic): §12 fallback names `oauth_user_token` (an alias for the exchange) as a passthrough | **Accepted** — §12 corrected to a genuine no-exchange forward |
| R2-9 (logic): case-1/S-1 could read as contradictory | **Accepted** — clarifying note added under §2 |

### Round 3 (2026-06-18 → impl APPROVED, logic+security needs_work) — dispositions
| Finding | Disposition |
|---|---|
| R3-1 (logic): stale `4/4` in §4 acceptance vs re-scoped A-1 (3/4) | **Accepted** — §4 acceptance corrected to 3/4 / P0 bar |
| R3-2 (logic): "A-1..A-9" ambiguous re A-1b | **Accepted** — §12 exit now "A-1, A-1b, A-2..A-9" |
| R3-3 (sec): S-2 gates non-blank, not *correct/single* audience | **Accepted** — S-2 requires exact single audience; A-5b covers wrong-but-set/multi |
| R3-4 (sec): S-5 omits signature-verification → decode forgeable | **Accepted** — S-5 now signature-verifies vs KC JWKS *before* claim assert; defines `act` PASS (actor=`mcp-proxy`, 1 hop); runs on cache hits |
| R3-5 (sec): S-6 sole enforcement in realm policy | **Accepted** — S-6 adds proxy-side audience allowlist + pins `requested_token_type` |
| R3-6 (impl): KC-24 token-exchange permission lives on **target** client, not `mcp-proxy` | **Accepted** — S-6(a) corrected; spike deliverable = `lab-tickets` `authorizationSettings` block |
| R3-7 (impl): `smoke_four_cases.sh` net-new + m365 re-seed is one-line | **Accepted** — both added to §3 |
| R3-8 (sec): §12 fallback could re-broaden audience | **Accepted** — §12 constraint added (single-audience, no mapper widening) |

### Round 4 (2026-06-18 → APPROVED, all 3 lenses) — confirmatory
All R3 spec-tightening verified against code: S-2 dev-profile fail-open is real & the fix is load-bearing; S-5 closes the confused-deputy in the code path (cache key `sha256(subject_token):audience` is caller-bound → no TOCTOU); S-6 two-layer scoping verified; PyJWT + `discover_jwks_uri()` + pinnable `requested_token_type` all exist; m365 re-seed is a verified one-line change. **Draft cleared → v1.0.0.** Two non-blocking residuals carried to §14.

---

## 14. Carry-forward to implementation (non-blocking, from R4)
- **RG-1:** the `lab-tickets` resource server validates `aud=lab-tickets` + `sub`; **also assert `azp==mcp-proxy` (and `iss`)** so its defence-in-depth half is independently enforced, not solely proxy-dependent. (P1 hardening.)
- **RG-2:** S-5's per-injection assertion must **re-decode + JWKS-signature-verify on every Redis cache hit** (the cached blob stores no pre-computed claims) — writing-plans must ensure this is not "optimized" into a trust-the-cache path.
- **Spike watch-item:** confirm KC emits the RFC 8693 `act` claim on *within-realm* exchange (S-5 iii depends on it); if absent, fall back to asserting `sub==caller`+`aud`+signature only and record the gap.

---

## 11. Decision log (locked by user 2026-06-18)
1. Upstreams: **real local software**; Graph = real Entra **with `mock` fallback**.
2. **Case 1 = M365/Graph as the SECOND IdP and nothing else** (no per-user M365); broker-injected `entra_client_credentials`.
3. **Grafana = service account, NetBox = per-user** — both **broker-injectable** (custom/shim servers, not env-token).
4. **Case 4 = one service on the SAME IdP as the gateway** — Jira ideal but too heavy → custom lightweight `lab-tickets` resource server via `kc_token_exchange`.
5. Wazuh = **full SIEM, separate profile**, pinned 4.9.x.
6. Vikunja, Gitea: **out of scope.**

## 12. Failure modes, exit condition, bear case
- **Primary failure mode:** KC within-realm token-exchange (`--features=token-exchange`, preview in KC 24) doesn't behave for the `lab-tickets` audience → case 4 can't go green. **Mitigation:** P1 spike validates the exchange before building the resource server; fallback is to forward the caller's gateway token directly if its audience already covers `lab-tickets` (no exchange), at the cost of the "exchange" teaching point.
- **Secondary:** the Grafana header-injecting shim adds a hop the third-party image didn't need → latency/format drift. **Mitigation:** thin pass-through shim, contract test against Grafana API.
- **Exit / sunset:** complete when **A-1, A-1b, A-2..A-9** pass and a 3-critic (no security `rejected`) + `publish-gate` clear it; retired when superseded by a production reference (`INSTALL.md`) or folded into the main demo. Not an indefinitely-maintained surface.
- **Bear case (quantified):** if the case-4 token-exchange spike fails its ≤1-day timebox, descope case 4 to a **genuine no-exchange forward** — pass the caller's existing gateway token unmodified via a header-forward path (a `none`/header-forward mode), the `lab-tickets` resource server validating that token directly. **Constraint (round-3 security):** this fallback must **not** re-broaden the proxy's audience mapper to mint `lab-tickets` for ordinary callers, and the caller token must remain **single-audience** — else the descope quietly re-opens the audience confusion S-2/S-6 close. **NB (round-2 logic):** the fallback is *not* `oauth_user_token` — that enum is an **alias for `kc_token_exchange`** and performs the same exchange. Observable descope: the `token-exchange-confusion` scenario becomes inapplicable; case-4 teaching downgrades from "federated exchange, no stored secret" to "same-IdP direct-token forward." Trigger: spike exceeds timebox.

## 13. Learning gate (workspace rule)
Defence notes (acceptance = 90-second pitch + diagram from memory + 3 hostile Qs):
- `Vault/KB/mcp-security-platform/credential-injection-models.md` — the four modes, IdP-topology × attribution × secret trade-offs, when each is correct.
- `Vault/KB/mcp-security-platform/incident-tracing-mcp.md` — the trace schema + how an analyst pivots alert→user→credential→tool-call, and why cases 1–2 are harder.
