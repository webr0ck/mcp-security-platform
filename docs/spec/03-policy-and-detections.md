# Policy Engine & Detections Specification

**Spec ID:** SPEC-03 · **Status:** matches code at HEAD (`4dfa7b5`)

This document specifies, normatively, the runtime authorization pipeline, the OPA
integration contract, prompt-injection detection, trust envelopes, the taint
floor, response/registration-time controls, anomaly scoring, and the
detections-as-code layer of the MCP Security Platform. It is written so a
re-implementer in any language can reproduce the security behaviour without
reading the Python. Requirement levels use RFC 2119 keywords (**MUST**,
**SHOULD**, **MAY**). Every requirement carries a *Reference implementation:*
pointer to the code that realizes it at HEAD. Controls that are not enforced
today are marked **(roadmap)**, consistent with the README
[Enforced-vs-Roadmap table](../../README.md#enforced-today-vs-roadmap), which
remains authoritative for per-control status.

Honesty markers used below match the README's candor: trust verification is
**passive** (logs, never blocks); anomaly scoring is a **static heuristic**
(trivially evaded by renaming); the transparency log is an explicit **stub**.

---

## 1. Invocation pipeline (normative order)

Every tool call — from the REST path (`POST /api/v1/tools/{id}/invoke`) **and**
the MCP path (`/mcp` → `tools/call`) — **MUST** funnel through a single
invocation chokepoint. A re-implementation **MUST NOT** provide any second code
path that reaches a backend MCP server without traversing this pipeline.

*Reference implementation:* `proxy/app/services/invocation.py::invoke_tool` is
the single chokepoint; both `routers/tools.py` (REST) and
`routers/mcp_server.py` (`/mcp`) call it.

The pipeline stages **MUST** execute in this order. Each stage is fail-closed:
an error at a stage denies the call (or 503s), never allows it.

| # | Stage | Rule | Reference |
|---|---|---|---|
| 1 | **Identity** | Caller identity resolved *before* app logic; unauthenticated ⇒ 401 (INV-009). Identity = `request.state.client_id`. | `middleware/auth.py` |
| 2 | **RBAC** | Platform role resolved from `role_assignments` (latest-event-wins, append-only). | `middleware/auth.py::_load_roles`, `middleware/rbac.py` |
| 3 | **Quarantine / status gate (INV-005)** | Tool `status ∈ {disabled, quarantined, deprecated}` ⇒ deny **pre-policy, pre-OPA**, with **no admin exception**. | `invocation.py` Step 1 |
| 3a | Debug/maintenance gate | Server in `debug_mode` ⇒ only `owner_sub` + `maintainers` may invoke; no role bypass; DB error ⇒ fail-closed deny. | `invocation.py` Step 1.1 |
| 3b | Scan-freshness gate | If `SCAN_FRESHNESS_ENFORCED`, stale/never-scanned server ⇒ deny (audited). Default warn-only. | `invocation.py` Step 1.2 |
| 4 | **Entitlement (discovery==invoke)** | Server-linked tool ⇒ caller **MUST** be entitled to that `server_id` via the same resolver used for discovery; **no role exception** (admin included). Unlinked tools skip this. | `invocation.py` Step 1.5, `services/entitlement.py::enforce_tool_entitlement` |
| 5 | **Taint floor** | Biba-style integrity floor (see §5); fail-closed; only active when `TAINT_FLOOR_ENABLED`. | `invocation.py` Step 1.6, `services/taint_floor.py` |
| 6 | **Anomaly heuristic (advisory input)** | Static score computed and threaded into OPA input; a failure defaults the score to `0.0` and **MUST NOT** block. | `invocation.py` Step 2, `services/anomaly.py` |
| 6a | Structural anomaly recent-calls fetch | `recent_calls` read from Redis window for OPA structural rules; Redis failure ⇒ **503** (INV-004 parity — an empty list would silently bypass structural deny rules). | `invocation.py` Step 2.3 |
| 7 | **Profile lookup** | `mcp_profiles` row (if any) injected into OPA input; DB error + cache miss ⇒ **503** (INV-015, fail-closed — never an empty/unrestricted profile). | `invocation.py` Step 2.5, `_lookup_profile_with_cache` |
| 8 | **OPA policy (INV-003/004)** | Deny-by-default; unreachable/non-200/`null` result ⇒ **503**; see §2. | `invocation.py` Step 3, `services/policy.py` |
| 9 | **SSRF re-validation** | Upstream URL re-checked at call time; see §7. | `invocation.py` Step 3b, `services/ssrf.py` |
| 10 | **Credential injection** | Broker resolves & injects per-identity token; client/backend never see a stored secret; failure ⇒ audited deny. | `invocation.py` Step 3c-pre, `credential_broker/dispatcher.py` |
| 11 | **DNS-rebind revalidation + pinned transport** | Resolve, validate against registered allowlist, pin the IP for the TCP connect; anomaly ⇒ deny/503. | `invocation.py` Step 3c, `services/pinned_transport.py`, `services/server_onboarding.py` |
| 12 | **Invoke backend** | Forward JSON-RPC to the isolated backend over the pinned transport; response body capped at 4 MiB. | `invocation.py` Step 4 |
| 13 | **Write-before-forward taint** | If the source server is untrusted, taint the principal **before** returning and **before** the response screen. | `invocation.py` post-Step 6, `services/taint_store.py` |
| 14 | **Response injection screen** | Screen the tool result for indirect prompt injection (§6). | `invocation.py` Step 6a, `services/response_filter.py` |
| 15 | **Synchronous audit** | An audit event is emitted **before** the response at every deny point and on the success/error path (INV-001; see SPEC-04). | `invocation.py` `_emit_audit_event` |

**Ordering invariants a re-implementation MUST preserve:**

- Quarantine (stage 3) is **before** anomaly, taint, and OPA, and has no admin
  exception.
- The anomaly heuristic (stage 6) is an **advisory input to OPA**, not an
  independent gate. The mandatory anomaly control is the **structural** Rego
  rule set fed by `recent_calls` (stage 6a), which is fail-closed.
- Credential injection (stage 10) happens **after** an OPA allow, so a denied
  call never triggers credential resolution or outbound DNS.
- The write-before-forward taint (stage 13) is **before** the response screen
  (stage 14) so a block-on-match early return can never skip the taint write.

---

## 2. OPA integration contract

*Reference implementation:* `policies/rego/authz.rego` (package `mcp.authz`),
`proxy/app/services/policy.py::evaluate_policy`.

### 2.1 Input document

The proxy **MUST** POST a single `{"input": {...}}` document to
`/v1/data/mcp/authz/allow`-equivalent and read back `{allow, reasons}`. The input
is the product of identity × tool × params × roles × grants:

| Field | Type | Meaning |
|---|---|---|
| `client_id` | string | resolved caller identity |
| `client_roles` | [string] | platform roles held by caller |
| `tool_id` / `tool_name` / `tool_status` / `tool_risk_level` | string | target tool |
| `tool_server_id` | string | owning server UUID (`""` if unlinked) |
| `owned_server_ids` | [string] | servers where caller is owner/manager — **computed by the proxy from `server_role_grant`, never taken from the request body** |
| `owner_max_risk_level` | string | admin-set ceiling for owned servers (default `"medium"`) |
| `params` | object | tool arguments (for pattern matching) |
| `anomaly_score` / `anomaly_cutoff` | number | advisory score + per-client cutoff (default `0.85`) |
| `is_testing` | bool | admin test bypass of anomaly only |
| `profile` | object | `{enabled, allowed_functions}` from `mcp_profiles` |
| `tool_function_name` | string | JSON-RPC `params.name` (function-level profile gate) |
| `recent_calls` | [{tool_name, timestamp}] | Redis window for structural anomaly rules |

*Reference implementation:* `invocation.py` `opa_input` dict (Step 3).

### 2.2 Decision semantics

- **Deny-by-default (INV-003):** `default allow := false`. A re-implementation
  **MUST NOT** add any wildcard allow or fallthrough. *Ref:* `authz.rego:29`.
- **Explicit deny set:** `deny` is a set of reason strings; `allow` requires
  `count(deny) == 0` **and** the positive predicates (`tool_is_active`,
  `client_has_invoke_permission`, `risk_level_within_threshold`,
  `not anomaly_threshold_exceeded`). Deny reasons are returned to the caller and
  recorded in the audit event. *Ref:* `authz.rego:58-64`, `reasons := deny`.
- **Fail-closed (INV-004):** any connection error, timeout, non-200, or invalid
  JSON from OPA **MUST** raise → HTTP **503 `OPA_UNAVAILABLE`**. A `{"result":
  null}` or `{"result": {}}` (startup race, bundle not yet loaded) **MUST**
  normalise to deny (`allow=false`). *Ref:* `policy.py:71-113`.
- **Deny reasons (non-exhaustive):** `tool_quarantined`, `tool_deprecated`,
  `client_not_authorized_for_tool`, `risk_level_exceeds_threshold`,
  `anomaly_threshold_exceeded`, `suspicious_parameter_pattern`,
  `suspicious_path_argument`, `suspicious_url_scheme`,
  `meta_tool_role_not_authorized`, `mcp_disabled_for_profile`,
  `function_not_allowed_for_profile`, plus the structural anomaly reasons in §8.

### 2.3 Signed bundles (INV-012) — default

Signed OPA bundles **MUST** be the default posture. `docker-compose.yml` runs OPA
with `--verification-key`; `make up` auto-signs; `make security-check` enforces
it via `scripts/check_signed_default.sh`. *Ref:* README Policy row; ARCHITECTURE
§6.

### 2.4 Grants via data API (not bundle-owned)

- Client grants are **DB-authoritative** (`client_grants` table) and pushed to
  OPA's data API at `PUT /v1/data/mcp_grants` — a path deliberately **outside**
  the signed `mcp` bundle root (see `.manifest`) so grants update at runtime
  without a bundle re-sign. *Ref:* `services/opa_data_sync.py`, `authz.rego`
  grants-path note (lines 32-51).
- The push **MUST** be fail-closed: on every grant mutation the proxy pushes to
  OPA **before** committing, and a push failure **MUST** return 503 / roll back.
  A **startup push** and a **60s reconcile loop** keep OPA in sync. *Ref:*
  `opa_data_sync.py::push_grants`, `start_reconcile_loop`; `routers/admin_grants.py`.
- Grant object shape per client: `{allowed_tools[], allowed_tags[],
  max_risk_level}`. A grant object missing `max_risk_level` falls through to
  deny (no fail-open default). *Ref:* `authz.rego:238-269`,
  `opa_data_sync.py::build_grants_data`.
- **RBAC `role_assignments` is NOT pushed to OPA** — it is a separate table
  consumed by middleware. A re-implementation **MUST** keep RBAC (who you are)
  and grants (what tools you may call) as distinct data planes. *Ref:*
  `authz.rego` note; ARCHITECTURE §6.

### 2.5 Platform meta-tools

Built-in `/mcp` meta-tools (`platform_info`, `security_pulse_summary`,
`list_registered_tools`, `enrollment_status`) have no `tool_registry` row and no
grant object. They are authorized **by role** via
`platform_meta_tool_roles` in `authz.rego`, evaluated under the **real caller
identity** (not a hardcoded `platform_admin`). The Rego map **MUST** mirror the
`_roles` set on each entry in `routers/mcp_server.py::_TOOLS`; a mismatch is a
bug. A registry tool registered with a reserved meta-tool name cannot inherit the
bypass because the meta marker (`input.is_platform_meta`) is only set on the
inline meta dispatch, never on the registry invoke path. *Ref:* `authz.rego:283-318`.

---

## 3. Prompt-injection detection

### 3.1 Single source of truth (normative consistency mechanism)

There is exactly **one** canonical injection-phrase list. It **MUST** be mirrored
into three enforcement points, and a test **MUST** enforce that they stay
identical:

1. `proxy/app/services/injection_patterns.py::INJECTION_PHRASES` — the canonical Python list.
2. `policies/rego/data.json` → `data.mcp.injection_phrases` — read by `authz.rego`
   (`matches_prompt_injection`) and `tool_risk.rego`
   (`description_prompt_injection`, `param_description_injection`).
3. `proxy/app/services/response_filter.py` — the response-screen regex set that
   covers the same phrases.

*Consistency requirement (normative):* the sync between the Python list and
`data.json` **MUST** be guarded by a test that fails CI on divergence.
*Reference implementation:*
`proxy/tests/unit/test_injection_patterns.py::test_python_list_and_data_json_list_are_identical`
asserts `INJECTION_PHRASES == data["mcp"]["injection_phrases"]` (same elements,
same order). A re-implementation **MUST** provide an equivalent guard.

### 3.2 Pattern categories

The canonical list (currently 28 phrases, lowercase substring match) groups into:

- **Role / instruction override:** `act as`, `disregard`, `do not follow`,
  `forget your`, `ignore all prior`, `ignore previous`, `jailbreak`,
  `override instructions`, `you are now`.
- **Persona / identity replacement:** `as an ai`, `new identity`,
  `persona override`, `pretend you are`, `roleplay as`, `your new role is`,
  `your persona is`, `your role is`.
- **LLM template / instruction markers:** `[inst]`, `### instructions:`,
  `### system:`, `system:`.
- **Hidden-instruction markers:** `<!--`, `<instructions>`, `<prompt>`, `<system>`.
- **Exfil verbs:** `base64`, `call the exfiltrate`, `call the send`,
  `call the upload`.

*Reference implementation:* `injection_patterns.py:40-79`, `data.json:3-33`.

### 3.3 Where injection detection fires

- **On invocation params:** `authz.rego` `deny contains
  "suspicious_parameter_pattern"` for any string leaf of `input.params` matching a
  canonical phrase; plus `suspicious_path_argument` (traversal / `~/.ssh` / `/etc/passwd`…)
  and `suspicious_url_scheme` (`file://`, `javascript:`, `data:`…). *Ref:*
  `authz.rego:115-154`.
- **On tool manifest (registration):** `tool_risk.rego` flags
  `description_prompt_injection` (top-level) and `param_description_injection`
  (per-parameter descriptions). *Ref:* `tool_risk.rego:35-50`.
- **On tool responses:** `response_filter.py` (§6).

---

## 4. Trust envelopes (RFC-0001)

> **Status: passive today.** The labeler signs every result, but the
> verifier/observer **only log** a verdict — they **never block**. Do not treat
> envelope verification as an access-control boundary in this build.

### 4.1 Labeling (Layer A — authoritative)

- When `TRUST_ENVELOPE_ENABLED`, the labeler **MUST** sign **every** tool result.
  The signature is **ES256 / JWS** (hardcoded `ec.ECDSA(SHA-256)`, never dispatched
  from `sig.alg`) over a **JCS/RFC 8785-canonicalized** signed-input covering:
  the trust `label`, a `content_hash` (`sha256:` of JCS-canonical
  `{content, structuredContent}`), a random `nonce`, `signed_at`, and the call
  identity (`result_id`, `tool_name`, `server_id`). The envelope carries the
  `x5c` cert chain (leaf + sub-CA). *Ref:* `services/trust_labeler.py:90-145`.
- The envelope is placed in `CallToolResult._meta` under key
  `io.mcp-security-platform/trust-envelope/v0.1`. *Ref:* `trust_labeler.py:23,205`.
- **Signing failure MUST NOT raise** — the `_meta` envelope is omitted and
  enforcement (the taint floor) is unaffected (W3.5). *Ref:*
  `trust_labeler.py:56-65`.
- The trust `label` maps SEP-1913 integrity rank → source name:
  `0 untrustedPublic, 1 trustedPublic, 2 internal, 3 user, 4 system`; an
  out-of-range tier clamps to 0. *Ref:* `trust_labeler.py:25-31,103`.

### 4.2 Verification (passive)

- An **independent** verifier (a process that did not sign) **MUST** be able to
  verify: envelope presence, `MAX_ENVELOPE_AGE` (≤600 s) and clock skew (≤60 s),
  chain to a **pinned sub-CA SPKI anchor** (no system trust store, point-in-time
  at `signed_at`), EKU = the labeler OID (`1.3.6.1.4.1.99999.1.1`) with
  `anyExtendedKeyUsage` rejected, ES256 signature, and content-hash
  recomputation. Any failure ⇒ `VerifierVerdict(accepted=False,
  integrity_rank=0)` (fail-closed). *Ref:* `services/trust_verifier.py`.
- The **observer** consumes the verdict and **only logs** it — it **MUST NOT**
  block or raise (advisory, demonstrations only). *Ref:*
  `services/trust_observer.py::observe_result`.

### 4.3 Layer B (MIME wrapper) — advisory, off by default

- Layer B wraps untrusted (`trust_tier < 2`) text content items in a MIME-style
  advisory boundary with a per-item `secrets.token_hex(8)` nonce. It is
  **UNSIGNED, ADVISORY, DISABLED by default** (`LAYER_B_ENABLED=false`), and
  **never a security boundary**. When enabled it is applied **before** Layer A
  signing so the signed `content_hash` covers the wrapped text. *Ref:*
  `services/layer_b.py`, `trust_labeler.py::build_envelope_result:162-206`.

---

## 5. Taint floor (Biba-style integrity)

*Reference implementation:* `proxy/app/services/taint_floor.py`,
`services/taint_store.py`, `invocation.py` Step 1.6 + write-before-forward.

- **Integrity ranks (SEP-1913):** `untrustedPublic 0, trustedPublic 1,
  internal 2, user 3, system 4`. The POC collapses these to **binary
  integrity**: rank `≥ 2` ⇒ trusted (1); `< 2`, unknown, `NULL`, or
  out-of-range ⇒ **0, fail-closed**. *Ref:* `taint_floor.py:32-38`.
- **Per-tool floor:** each tool has a `required_integrity` floor (default 1 when
  unset). A credential-injecting tool's floor is bumped to `≥1` (it can never be
  a low sink); the effective injection mode is computed fail-closed in both
  directions (tool mode **or** server default injecting ⇒ treated as injecting).
  *Ref:* `taint_floor.py:46-72`.
- **Decision rule:** a session is *tainted* once it ingests any result with
  binary integrity 0. `taint_floor_decision(tainted, required_integrity)` **MUST**
  deny iff `tainted AND required_integrity >= 1`. *Ref:* `taint_floor.py:75-83`.
- **Fail-closed store (INV-015):** the taint bit is stored in Redis under a
  distinct `mcp_taint:` namespace. A **read** error / unavailable store ⇒ treat
  as **tainted** (deny high sinks); a **write** failure ⇒ raise `TaintStoreError`
  ⇒ the in-flight request fails closed (500). This is the deliberate **inverse**
  of the fail-open `mcp_session:` cache. *Ref:* `taint_store.py`.
- **Keyed per authenticated principal (LOGIC-005):** the store keys on
  `client_id` (the stable logical identity, e.g. `alice@corp`), **not** on
  `principal_id` (which encodes the auth method). This prevents taint evasion by
  switching from an OIDC JWT to an API key for the same account. *Ref:*
  `taint_store.py:44-52`, `invocation.py` comments at Step 1.6 / write-before-forward.
- **Write-before-forward:** if the source server is untrusted, the principal is
  tainted **before** the result is returned and **before** the response screen,
  so a block early-return cannot skip the taint write (appsec M-1). *Ref:*
  `invocation.py` write-before-forward block.
- **Deny reason / SIEM:** a taint-floor deny is audited (INV-001) with
  `taint_floor:required_integrity=N` and detected by Wazuh rules 100001-100003
  (`deployments/poc/wazuh/rules/mcp-taint-floor.xml`). The whole floor is dark
  unless `TAINT_FLOOR_ENABLED`.

> **POC scope:** binary taint only; a graded lattice and a real session model are
> **(roadmap)**.

---

## 6. Response filtering (indirect injection screen)

*Reference implementation:* `proxy/app/services/response_filter.py`,
`invocation.py` Step 6a.

- Every backend tool result **MUST** be screened for indirect prompt-injection
  patterns **before** it is returned to the client (perimeter controls cannot
  see tool responses — the LLM ingests them as content; OWASP LLM01 / CROSS-001).
- The screen uses a regex library covering the same categories as §3 (role
  override, persona/identity, exfil-via-function-call, hidden-instruction
  markers, LLM template tokens). A match **MUST** emit a synchronous audit event
  with `outcome="error"` and reason `RESPONSE_FILTER_INJECTION` **regardless of
  block mode**. *Ref:* `invocation.py:1058-1076`.
- **Blocking is the default** (`RESPONSE_FILTER_BLOCK=true`): a matching response
  is replaced with a sanitised `-32603` error carrying the `audit_id`. Set the
  env var false for detect-only (log + audit, allow through). *Ref:*
  `response_filter.py:28`, `invocation.py:1077-1086`.

> **Discrepancy note (see end):** the "10-category PII/secret redaction" is a
> distinct control applied to the **audit/log stream** (SPEC-04 §INV-002), **not**
> to the response body returned to the caller. `response_filter.py` performs
> injection screening only.

---

## 7. SSRF protection

*Reference implementation:* `proxy/app/services/ssrf.py`,
`services/pinned_transport.py`, `services/server_onboarding.py`.

- **Two enforcement points, both fail-closed:** SSRF validation runs at
  **onboarding** (`POST /api/v1/admin/servers/{id}/approve`) **and** at
  **invoke** (Step 3b) — registration-time validation alone is insufficient
  because `upstream_url` can be PATCHed after approval. *Ref:* `ssrf.py:1-14`,
  `invocation.py` Step 3b.
- `validate_server_url` **MUST**: require an explicit scheme (`https`, or `http`
  only for localhost/internal container hostnames in dev); reject credentials in
  the URL; block private/loopback/link-local/CGNAT IPv4, ULA/link-local/loopback
  IPv6, and **cloud-metadata** endpoints (`169.254.169.254`, `fd00:ec2::/32`);
  and re-check **IPv4 embedded in IPv6 transition forms** (mapped/6to4/Teredo/
  NAT64/v4-compatible) so a globally-routable wrapper cannot smuggle an internal
  target. Deny-by-default for any non-global IPv6. *Ref:* `ssrf.py:27-188`.
- **DNS-rebind / TOCTOU defense (IP-pinned transport):** at invoke time the proxy
  resolves the host, validates the resolved IP against the registered allowlist,
  then pins that IP for the TCP connect via `PinnedIPTransport` while preserving
  the original hostname in the `Host` header and TLS SNI. The OS resolver is
  **MUST NOT** be consulted again between validation and connect. A revalidation
  failure ⇒ audited deny / 503. *Ref:* `pinned_transport.py`, `invocation.py`
  Step 3c.

---

## 8. Registration-time controls

*Reference implementation:* `proxy/app/services/sbom.py`, `services/auditor.py`,
`policies/rego/tool_risk.rego`.

### 8.1 SBOM (INV-006)

- Every registered tool **MUST** have a **CycloneDX 1.5** SBOM, **HMAC-SHA-256
  signed** (`SBOM_SIGNING_KEY`), stored in `sbom_records.signature` (NOT NULL).
  A tool **MUST NOT** reach `active` status without a valid signature (DB
  constraint + INV-006). *Ref:* `sbom.py:33-158`.
- SPDX output is **(roadmap)** (`SPDX_SPEC_VERSION` constant exists but is not
  emitted). *Ref:* `sbom.py:31`, README SBOM row.

### 8.2 Tool-manifest audit (advisory)

- Registration runs a **two-part** risk audit: a deterministic **OPA static**
  score (`tool_risk.rego`, weighted 0.4) plus an **Ollama LLM** semantic score
  (weighted 0.6). The LLM part is **advisory** — it influences `risk_score` /
  `risk_level` but does not unilaterally block. *Ref:* `auditor.py:30-32,212-307`.
- **Fail-closed on LLM unavailability:** if Ollama is unreachable the score
  re-weights to **1.0 × static** (no silent downgrade to 0.4×). In production,
  `REQUIRE_LLM_AUDIT=true` makes registration return **503** and insert **no**
  `tool_registry` row, rather than run degraded. *Ref:* `auditor.py:70-83,286-301`.
- `tool_risk.rego` static flags and weights (e.g. `description_prompt_injection`
  40, `shell_execution` 35, `filesystem_unrestricted` 25, `credential_parameter`
  30, `no_source_repo` 10) map a flag set → 0-100 score → `low/medium/high/critical`.
  *Ref:* `tool_risk.rego:28-143`.
- **Invocations are not affected** by the LLM auditor — it runs at registration
  only. *Ref:* ARCHITECTURE §5.4.

---

## 9. Anomaly scoring (honest specification)

> **Status: static heuristic, not a learned model.** Scoring is static
> keyword/tool-name sliding-window matching. **The literal tool-name rules are
> trivially evaded by renaming a tool.** There is no per-client statistical
> baseline. A learned baseline is **(roadmap)**.

*Reference implementation:* `proxy/app/services/anomaly.py`,
`policies/rego/anomaly.rego`.

- The per-call score (0.0-1.0) comes from a Redis **sliding window** of recent
  tool names for the client, matched against fixed keyword sets:
  `web_search → ≥3 file_read` (~0.7-0.95), `auth → data_export` (0.80), and
  `>10 calls/window` rapid-fire (≤0.90). Score ≥ 0.85 writes an `anomaly_alerts`
  row (write-behind, non-blocking). *Ref:* `anomaly.py:37-155`.
- The score feeds **OPA input** (`anomaly_score`); `authz.rego` denies with
  `anomaly_threshold_exceeded` when `score > anomaly_cutoff` (default 0.85),
  except for admin `is_testing`. *Ref:* `authz.rego:271-277,110-113`.
- **Structural rules (mandatory, fail-closed):** separately, `anomaly.rego`
  provides `structural_deny_reasons` evaluated inside the same authz query from
  `input.recent_calls`: `exfiltration_chain_detected`
  (`web_search ≥2` then `file_read ≥5`), `bulk_file_read_spike` (>10 file calls),
  `credential_access_then_exec`. These are **hard deny reasons**, not advisory —
  and the `recent_calls` fetch is fail-closed (§1 stage 6a). *Ref:*
  `anomaly.rego:39-99`, `authz.rego:388-404`.
- The former write-only `anomaly_baselines` writer was removed (6.4) because it
  implied a model that did not exist; the table remains unpopulated for a future
  learned baseline. *Ref:* `anomaly.py:13-19,226-230`.

---

## 10. Detections-as-code (Sigma over the audit stream)

The platform ships Sigma rules that run over the **structured audit event
stream** (`logsource: product mcp-security-platform, service audit`). A
re-implementation **MUST** keep the audit event schema (SPEC-04) stable enough
that these rules still match — specifically the fields `event_type`, `outcome`,
`deny_reasons`/`opa_reasons`, `anomaly_score`, `client_id`, `tool_name`.

*Reference implementation:* `detections/*.yml` (8 rules), `detections/README.md`.

All 8 rules share `logsource: {product: mcp-security-platform, service: audit}`,
`author: MCP Security Platform`, and reference `agentthreatrule.org/en/spec`. No
rule uses a `category`. Conditions below are verbatim from the YAML.

| # | Rule (`detections/*.yml`) | Condition | Level | Structured tags |
|---|---|---|---|---|
| 1 | `mcp-tool-invocation-denied` | `event_type=TOOL_INVOCATION` AND `outcome=deny` | medium | `attack.discovery`, `owasp.llm.05`, ATLAS `AML.T0043` |
| 2 | `mcp-policy-probe-burst` | `TOOL_INVOCATION` + `deny`, `count(client_id) by client_id >= 5` in `60s` | high | `attack.credential_access`, `attack.t1110`, `owasp.llm.01`, `AML.T0016` |
| 3 | `mcp-high-anomaly-score` | `TOOL_INVOCATION` + `outcome=allow` + `anomaly_score|gt: 0.85` | high | `attack.exfiltration`, `owasp.llm.02`, `AML.T0025` |
| 4 | `mcp-credential-change` | `event_type ∈ {CREDENTIAL_UPLOADED, CREDENTIAL_REVOKED, CREDENTIAL_MODE_CHANGED, API_KEY_CREATED, API_KEY_REVOKED}` | medium | `attack.persistence`, `attack.t1098`, `owasp.llm.09`, `AML.T0020` |
| 5 | `mcp-quarantined-tool-access` | `TOOL_INVOCATION` + `deny` + `deny_reasons|contains|i: 'TOOL_QUARANTINED'` | **critical** | `attack.execution`, `owasp.llm.06`, `AML.T0043` |
| 6 | `mcp-slow-exfiltration` (experimental) | `TOOL_INVOCATION` + `allow`, `count(tool_name) by client_id, tool_name >= 30` in `1h` | medium | `attack.exfiltration`, `owasp.llm.02`, `AML.T0025` |
| 7 | `mcp-tool-lifecycle-event` | `event_type ∈ {TOOL_REGISTERED, TOOL_STATUS_CHANGED, TOOL_DELETED}` | medium | `attack.persistence`, `attack.t1554`, `owasp.llm.03`, `AML.T0019` |
| 8 | `mcp-high-anomaly-denied` | `TOOL_INVOCATION` + `deny` + `anomaly_score|gt: 0.85` | high | `attack.exfiltration`, `owasp.llm.02`, `AML.T0025` |

Rules 3 and 8 are complements (allow vs deny at the 0.85 threshold, which matches
`authz.rego`'s block threshold). Rule 5's uppercase `TOOL_QUARANTINED` is the
authoritative emitted deny-reason string (`routers/tools.py`); a re-implementation
**MUST** preserve that literal.

**ATR taxonomy mapping (honest note):** the structured `tags` use **MITRE ATT&CK**
(`attack.*`, `attack.tXXXX`), **OWASP LLM Top-10** (`owasp.llm.0X`), and **MITRE
ATLAS** (`mitre_atlas.AML.TXXXX`). The **ATR** (Agent Threat Rules,
`agentthreatrule.org/en/spec`) mapping lives in each rule's free-text
`description` (e.g. "credential hijacking", "unsafe tool execution", "slow data
harvesting", "tool supply chain compromise"), **not** in structured tags. Rules
are hand-authored Sigma; LogQL equivalents are hand-maintained in
`observability/loki/rules/mcp_alerts.yml`. *Ref:* `detections/README.md`.

---

## 11. Discrepancies found

Recorded per the engineering standard (a claim without backing code is a bug):

1. **"Response filtering: 10-category PII/secret redaction on responses"** — the
   10-category redaction (`observability/mcp-audit-logger/.../redaction.py`) is
   applied to the **audit/log stream** (INV-002), **not** to tool response
   bodies. `response_filter.py` screens responses for **injection only**. The two
   are separate controls; this spec documents them separately (§6, SPEC-04).
2. **RFC-0001 / PRD-0001 documents are not in the repo.** Trust-envelope and
   taint-floor code cites `RFC-0001 §N` / `PRD-0001 MN` throughout, but no
   `docs/rfc/RFC-0001*` file exists at HEAD; the citations are code-comment
   anchors only. `transparency_log.py` cites **RFC-0002 §5.4** and is an explicit
   stub (see SPEC-04).
