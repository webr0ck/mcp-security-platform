# PRD-0005 — Admin Configuration Surfaces (LLM, Git Provider, Public Servers, SBOM)

- **Status:** DESIGN v2 — revised after 3-critic pass (Codex=rejected, security=rejected,
  logic=needs_work). v2 closes every blocking finding below. R-5 (SBOM-at-submission) was
  added after the critic pass and is lower-risk (read-only static analysis); it did not go
  through the 3-critic round.
- **Date:** 2026-07-05
- **Author:** platform team
- **Scope:** Admin-manageable config for (a) the LLM/AI provider, (b) a corporate Bitbucket git
  service account alongside GitHub, (c) making the self-service MCP reachable by all
  authenticated users, plus (d) a Codex-driven E2E QA harness and (e) SBOM collection at
  submission time.
- **Non-goals:** replacing GitHub; multi-tenant LLM routing; per-user LLM keys; a generic
  settings KV store (each surface keeps its own purpose-built table).

## 3-critic findings this revision resolves

| # | Finding (critic) | Resolution in v2 |
|---|---|---|
| F-1 | Secret storage is NOT free reuse — `admin_credentials` is tool-bound (`ON CONFLICT (tool_id, service)`, `owner_type='service'`, `user_sub='__service__'`); a platform config secret has no `tool_id` (logic + security + codex) | R-1 now specifies a **new** `platform_secrets` table + a thin store that reuses **only** the KEK/AES-256-GCM primitive (`credential_broker/approaches/approach_a.py`), not the tool-bound upsert. §SI-1 rewritten. |
| F-2 | LLM token fail-open: best-effort → no-auth can silently downgrade an authenticated endpoint; a 401/403 is not reclassified as `llm_unavailable`, so `REQUIRE_LLM_AUDIT` prod fail-closed may not trip (security + codex) | New **SI-6**: any LLM auth-failure (401/403 or token-decrypt failure) is treated identically to "LLM unreachable" → in prod (`REQUIRE_LLM_AUDIT=true`) returns 503. No unauthenticated retry accepted on 200. |
| F-3 | Git-clone SSRF: the clone path is **not** routed through the egress proxy (squid allowlist = M365/Graph only, verified); exact-host-match is app-layer only; an internal/metadata host gets cloned with service-account creds (security) | R-2 now requires **write-time host validation**: reject configured hosts resolving to loopback/link-local/`169.254.169.254`/metadata ranges; **DNS-pin** (resolve once, clone by pinned IP) to stop rebinding; explicit documented risk-acceptance for RFC1918 corporate hosts + operator allowlist. |
| F-4 | `public_to_authenticated` write-op exclusion had no enforcement mechanism (security + codex) | R-3 now gates on the **existing** `server_registry.has_write_ops` column (verified present) with a DB-level `CHECK (NOT (public_to_authenticated AND has_write_ops))` + resolver gate; public is honored only for read-only, approved, non-quarantined servers. |
| F-5 | Bitbucket URL model likely wrong for Data Center (`/scm/PROJECT/repo.git`) (codex) | R-2 regex set now covers Bitbucket Data Center (`/scm/<proj>/<repo>.git`, `/<proj>/repos/<repo>`) and Cloud (`/<workspace>/<repo>`). |
| F-6 | R-4 not deterministic; wrong reference to "R-1's mcp_checker" (codex) | R-4 rewritten with explicit assertions; the scanner is ARCHITECTURE §5.5, not R-1. |
| F-7 | No exit/sunset condition; no quantified bear case (logic) | Added per-surface **Exit** + **Blast radius** lines. |
| F-8 | R-3 cited the prior global-grant rejection without its rationale (logic) | R-3 now states the original objection and argues against it explicitly. |

---

## Shared design invariants

- **SI-1 Secrets never land in a plaintext column/env dump.** Platform secrets (LLM token,
  git service-account token) are stored in a **new** `platform_secrets` table as
  `nonce(12) || AES-256-GCM(ciphertext+tag)`, encrypted with the broker KEK derived for a
  fixed, documented platform key-domain (info string `"mcp-platform-secret-v1:" || name`),
  reusing `approach_a`'s crypto only. This is **new plumbing**, not a reuse of the tool-bound
  `admin_credentials` upsert. The KEK master comes from Vault exactly as for user credentials
  (spec §2.1); the platform key-domain is a distinct, documented derivation (does not stretch
  the per-user INV-013 model — it is explicitly a non-user domain).
- **SI-2 Fail-closed on read.** Absent config row ⇒ existing env default. Expected secret with
  broker/Vault unreachable ⇒ dependent feature fails closed (see SI-6 for the LLM specifics).
- **SI-3 Admin-gated + audited.** `_require_admin`; every mutation → `emit_admin_config_event`.
- **SI-4 Prod guardrails intact.** An override cannot disable a prod-forced guardrail
  (`REQUIRE_LLM_AUDIT`, https-only `VAULT_ADDR`, deny-by-default OPA). Validated at write time.
- **SI-5 Clean-start safe.** Migrations replay via `lab-init`; no new secret-on-disk.
- **SI-6 LLM auth-failure == unavailable (NEW).** In `auditor.py`, a token-decrypt failure OR a
  401/403 from the LLM endpoint is raised as `LLMAuditUnavailableError` (same class the existing
  `REQUIRE_LLM_AUDIT` gate already catches), never silently retried unauthenticated. Local
  no-token ollama is unaffected (no token configured ⇒ no auth expected ⇒ not an auth-failure).

---

## R-1 — LLM configuration admin panel  ✅ DONE

**Status:** Implemented + verified (V054 `platform_secrets` + `llm_config`; `platform_secrets.py`
reusing only approach_a crypto; `llm_config.py` env+DB overlay; `auditor.py` SI-6 wiring;
`admin_llm.py` GET/PUT/token/test; portal LLM tab). Verified via live API: config override persists,
token stored encrypted through the live Vault KEK and never echoed, `/test` probe hits ollama, delete
reverts. 9 auditor tests pass incl. 3 new SI-6 (token-unobtainable → llm_unavailable with no HTTP
call; token→Bearer; no-token→no header).

**Problem.** LLM config is env-only (`OLLAMA_*` in `config.py`, consumed in `auditor.py`,
no auth header). No way to point at a token-protected endpoint without a redeploy.

**Design.**
- Table `llm_config` (V053), singleton (`id SMALLINT PK DEFAULT 1 CHECK (id=1)`): `base_url`,
  `model`, `timeout_seconds`, `enabled`, `updated_by`, `updated_at`. Non-secret. Absent ⇒ env.
- Token in `platform_secrets` under name `llm-api` (SI-1), **not** `credential_store`.
- `services/llm_config.py`: `effective()` merges env + row (30s cache); `api_token()` decrypts
  `llm-api` on demand. `auditor.py` uses these; sets `Authorization: Bearer` iff a token exists.
  **SI-6 governs failure**: decrypt/401/403 ⇒ `LLMAuditUnavailableError`.
- Endpoints `routers/admin_llm.py`: `GET/PUT /api/v1/admin/llm`, `PUT /api/v1/admin/llm/token`
  (write-only), `POST /api/v1/admin/llm/test` (bounded probe; never echoes token).
- UI "LLM" admin tab. Write-time: prod rejects non-loopback `http://` base_url (SI-4).
- **Exit:** delete `llm_config` row + `llm-api` secret ⇒ reverts to env-var ollama, no code change.
- **Blast radius:** one platform LLM identity; a leaked token affects only the configured
  endpoint. Auditor runs at **registration only**, never on invoke — no data-plane exposure.

## R-2 — Corporate Bitbucket service account (alongside GitHub)  ✅ DONE

**Status:** Implemented + verified (V055 `git_providers`; `git_providers.py` provider match +
SSRF host validation; scanner refactored provider-aware; `admin_git.py`; portal Git Providers tab;
submit-time validator relaxed to structural https). Verified via API: internal host rejected without
`allow_private` (400), metadata host rejected even with it (400), internal host allowed with the ack,
token encrypt round-trip, and a full GitHub submission still clones+scans (3 findings, 2 SBOM
components → awaiting_review). 8 unit tests (URL shapes + IP classification + fail-closed DNS).

**Problem.** `submission_scanner.py` is GitHub-hardcoded; clone path is unproxied (egress
squid allowlist covers only M365/Graph — verified), so a new configurable host is a potential
SSRF/confused-deputy primitive.

**Design.**
- `GitProvider = {"github","bitbucket"}`. Per-provider **exact-host** allowlist:
  - github: existing `_GITHUB_URL_RE`.
  - bitbucket (Data Center + Cloud): `^https://<host>/(scm/[\w.-]+/[\w.-]+\.git|[\w.-]+/repos/[\w.-]+|[\w.-]+/[\w.-]+)(\.git)?/?$`, `<host>` from config.
- Table `git_providers` (V054): `provider PK`, `enabled`, `host`, `clone_account`, `updated_by`,
  `updated_at`. Secret in `platform_secrets` under `git-<provider>` (SI-1).
- **SSRF controls (F-3):** at write time, resolve `host`; **reject** if it maps to
  loopback / link-local / `169.254.0.0/16` (cloud metadata) / other deny ranges. If the host is
  RFC1918 (corporate Bitbucket typically is), require an explicit `allow_private=true` admin
  acknowledgement stored on the row + a WARN audit event. At clone time, **DNS-pin**: resolve
  once, pass the pinned IP with `--config http.<host>.extraHeader` host pinning (or clone by IP
  with SNI host) to defeat DNS-rebinding between validation and clone. Transport hardening
  (`protocol.allow=never` except https, `--` guard, shallow, tmpfs) unchanged.
- Provider is **inferred from URL host** (no new submitter input; unknown host ⇒ reject).
- Endpoints `routers/admin_git.py`; UI "Git Providers" tab.
- **Exit:** `enabled=false` on the bitbucket row ⇒ only github submissions accepted, as today.
- **Blast radius:** worst case an admin-configured internal host is cloned with the git service
  account's read token; contained by (a) metadata-range block, (b) DNS-pin, (c) read-only token,
  (d) the clone running in a tmpfs sandbox with no inbound path to the proxy.

## R-3 — Self-service reachable by all authenticated users (scoped, write-safe)  ✅ DONE

**Status:** Implemented + verified (V053, `entitlement.py` resolver gate + discovery parity,
`server_registry.py` toggle endpoint, portal toggle UI, 3 unit tests). Verified: ungranted
principal granted `public_server`; quarantine denies; write-op blocked by DB CHECK + 409; discovery
parity. Also fixed a **pre-existing latent bug** — `list_entitled_servers` selected a non-existent
`entitlement.role` column, so the catalog listing (`GET /api/v1/servers`) and detail endpoint
returned empty/404 for everyone; now uses the `'user'` literal (matches `check_entitlement`).

**Problem.** Entitlement is per-principal fail-closed (verified: `entitlement.py` has no
"everyone" path and no admin bypass). Only alice + lab apikey are granted self-service. A prior
**broad global-grant was rejected** — the objection (as understood) was that *any* unentitled
authenticated access erodes the deny-by-default invariant and makes the audit trail lie about who
was authorized. R-3 must answer that objection, not just narrow blast radius.

**Design.**
- Column `public_to_authenticated BOOL DEFAULT false` on `server_registry` (V055), with
  **`CHECK (NOT (public_to_authenticated AND has_write_ops))`** — a write-capable server can
  **never** be flagged public (F-4; uses the existing `has_write_ops` column, verified present).
- Resolver grants access **iff**: caller is an authenticated principal **AND** the server row is
  `status='approved'` (quarantine/suspended already filtered first — F-4/Q-6 ordering preserved)
  **AND** `public_to_authenticated=true` **AND** `has_write_ops=false`. Not a wildcard, not a
  role bypass — a per-row, read-only, opt-in property.
- **Answering the original objection:** deny-by-default is preserved because access is still
  explicitly granted per-row by an admin action (flipping the flag is an audited mutation); the
  audit trail does **not** lie — a public-server invoke is logged with
  `entitlement_reason='public_server'`, distinguishable from an explicit grant. The rejected
  global-grant removed per-server admin intent entirely; this keeps it.
- Only `lab-self-service` is seeded public. Anonymous callers remain denied (auth still required).
- Endpoints: a toggle in the existing MCP Servers admin tab (guarded; `CHECK` also enforces at DB).
- **Exit:** set flag false ⇒ server reverts to explicit-grant-only.
- **Blast radius:** at most (N authenticated principals) gain **read-only** invoke on exactly the
  servers an admin flags; today that is 1 server (self-service). A mis-flip cannot expose write
  ops (DB CHECK) or quarantined servers (status gate).

## R-4 — Codex-driven E2E QA harness

**Design.** Codex CLI (session at `~/Code/test-api-server`), auth via `codex mcp login
mcp-gateway` (interactive browser copy-paste — the one **manual** prerequisite). Flow: read
`GET /api/v1/design-assist` → answer wizard prompts → generate a **benign** MCP server → push to a
repo the git service account can read → `POST /api/v1/submissions` + submit → the **submission
scanner** (ARCHITECTURE §5.5) runs → a **separate reviewer** identity (carol, `security_reviewer`
— SoD, never the submitter) approves. **Deterministic assertions:** (1) scan reaches
`scan_status='passed'`; (2) status transitions `draft→scan_pending→…→awaiting_review→approved`;
(3) a **deliberately-vulnerable variant** is blocked or flagged by mcp_checker (asserts the R-5/
scanner path). Non-goal: headless CI (blocked by interactive login) — this is a scripted manual
acceptance run under `lab/tests/`.
- **Exit / Blast radius:** test-only; no production surface.

## R-5 — SBOM collected at submission (for the security analyst)  [added post-critic]

**Problem.** The review card shows "SBOM: not yet provisioned" — the signed per-tool CycloneDX
SBOM only exists post-approval (INV-006), so the analyst reviewing a **submission** sees no
component inventory. The scanner already parses declared deps into
`server_registry.sbom_components` (`parse_sbom_components`) but the submission review card does
not surface it.

**Design (read-only, low-risk).**
1. **Surface now:** render `sbom_components` on the submission review card
   (`fragment_admin_submissions`) — component name/version/purl table, grouped by ecosystem, so
   the analyst has the declared-dependency inventory immediately after submission.
2. **Richer SBOM (follow-on):** generate a CycloneDX SBOM during the scan via **syft** (add to
   the scanner image, same isolated-tool pattern as semgrep). Store as a scan artifact; fail
   **soft** (SBOM is analyst context, not a gate — a syft failure must not block or fail the
   scan, matching the existing `parse_sbom_components` soft-fail contract). If syft is absent,
   fall back to the textual `sbom_components` already collected.
- **Exit:** SBOM rendering is additive display; removing it changes nothing in the gate.
- **Blast radius:** none — read-only static parse of an already-cloned repo; no new trust boundary.

---

## Implementation order (after design sign-off)
1. **R-5 step 1** (surface existing sbom_components — trivial, directly requested, zero-risk) →
2. **R-3** (write-op-gated public flag) → 3. **R-1** (LLM config + platform_secrets) →
4. **R-2** (Bitbucket + SSRF controls) → 5. **R-5 step 2** (syft) → 6. **R-4** (QA harness).
Each lands with its migration, admin router/fragment, a self-check/test, and doc updates in
`ARCHITECTURE.md` + the relevant `docs/spec/*` section.
