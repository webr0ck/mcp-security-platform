# PRD-0001 — Signed Trust-Envelope POC

| | |
|---|---|
| **Status** | Draft v0.3 (post-`/3-critic` round 2; scope = proxy-enforce + shim-verify) |
| **Owner** | Alexander Romanov |
| **Date** | 2026-06-13 |
| **Implements** | [RFC-0001 v0.3.2](../rfc/RFC-0001-mcp-signed-trust-envelope.md) (appsec approved-to-implement) |
| **Type** | POC — closed ecosystem, binary integrity, **proxy-enforced** |

---

## 1. Summary & goal

Demonstrate RFC-0001 as **two honestly-separated controls**:

- **The control (blocks the action):** the **proxy** runs a binary Biba **taint floor** driven by
  `server_registry.trust_tier` (a trusted in-boundary DB lookup), **blocks** a high-sensitivity
  call from a contaminated session, and emits the authoritative **INV-001 audit** — exactly where
  RFC §8.1 places it. This is in-proxy, in the audited trust boundary; no crypto in the block path.
- **The contribution (portable signed provenance):** the proxy **also signs** each result into a
  trust envelope, and an **independent verifier ("shim")** — a process that did *not* produce the
  envelope — **verifies** it (D4/D5/D6), demonstrating that a non-producer can validate the label.
  This is what makes the scheme more than in-runtime taint tracking (CaMeL/FIDES): the label is
  *portable and signed*, verifiable across a boundary.

**Honest scope (round-2 finding):** in a single-org, single-sub-CA, co-located POC the verifier is
**process-separated, not trust-separated** — true cross-trust value appears only at federation
(RFC §15 future). The POC therefore proves: **(a) audited in-boundary enforcement that blocks an
action**, and **(b) a signed envelope an independent verifier validates / rejects-on-forgery**. It
does **not** claim cross-boundary trust; it claims the *mechanism* that federation would use.

The POC succeeds only if **D1/D2 visibly block an action with a proxy-side audit row**, AND the
independent verifier **rejects a tampered/forged envelope** (D4/D5).

## 2. Architecture & trust model

```
agent ──▶ gateway/WAF ──▶ [PROXY] ──▶ upstream MCP server
                            │  • taint floor (trust_tier) → BLOCK high sink (the control)
                            │  • _emit_audit_event (INV-001, ALLOW+DENY)
                            │  • signs result → trust envelope (the contribution)
                            ▼
                    signed CallToolResult
                            ▼
              [INDEPENDENT VERIFIER / "shim"] — passive: verifies envelope (D4/D5/D6)
                            │  NOT on the enforcement path; demonstrates producer≠verifier
                            ▼  emits a verification verdict (logged); does not block
                          agent
```

- **Proxy = enforcer + auditor + labeler.** Enforcement and audit stay inside the proxy boundary
  where INV-001/004/005/011 already hold. The taint floor reads `required_integrity` and
  `trust_tier` directly from the DB — **trusted, no unsigned catalog dependency.**
- **Verifier ("shim") = independent consumer, demonstration only.** It verifies the signed envelope
  to prove a non-producer can validate it; it **does not block** and is **not** a security
  chokepoint, so a bypass of it is *not* a fail-open (the proxy already enforced + audited).
  Realized as a **verifier module + a passive inline observer** — not a second gateway.
- **What the signature is / is not:** it attests **provenance** (which registered server produced
  this result, at what trust tier, over these exact bytes), **never content benignity.**

## 3. Success criteria (done-means-tested)

DONE when **all** pass in CI (`make test-all`) + a demo script.

| ID | Acceptance | Proven by |
|---|---|---|
| **D1** | Web-search result (injected exfil), server `trust_tier=0` → session tainted → agent's next `salesforce.read`/`email.send` **BLOCKED in the proxy + INV-001 audit row**; upstream never called (no cred injection). | **Proxy** |
| **D2** | Email-summary result (injected `drop table`) → `db.drop` **BLOCKED** in tainted session. | **Proxy** |
| **D3** | Clean (`internal`/`user`/`system`-only) session → high-sink **ALLOWED**. FP measured over a fixed corpus with a **falsifiable** definition (§5 W5.3). | **Proxy** |
| **D4** | Tampered `content[]` under a valid label → verifier hash/sig **FAILS** → rejected. | **Verifier** |
| **D5** | Malicious server signs `source=internal` with its **own** machine cert → verifier **rejects** (no labeler EKU / not under sub-CA). | **Verifier** |
| **D6** | Envelope read after leaf expiry but `signed_at` within validity → **accepted**; outside → rejected. | **Verifier** |
| **D8** | Clean `internal`-only session, unclassified (default-floor) tool → **ALLOWED** (rule equivalence, RFC §4.3). | **Proxy** |
| **F-1…F-8** | Appsec footgun matrix (RFC §17) pass as `[TAMPER]`/`@pytest.mark.security` in the **verifier** suite. | **Verifier** |

**Invariant gates green:** INV-001 (proxy audit ALLOW+DENY), INV-003, INV-004, INV-005, INV-011,
INV-015. `make security-check` + `opa check --strict` pass.

## 4. Personas
- **Security engineer (demo)** — sees the proxy block a call + the audit row; sees the independent
  verifier reject a forged envelope.
- **Platform admin (classifier)** — sets `trust_tier` per server, `required_integrity` per tool.
- **Agent** — unmodified.

## 5. Epics, work items & acceptance

### E1 — Schema & classification *(unblocks all)*
- **W1.1** Migration **`V038__trust_envelope.sql`** (after V037):
  `tool_registry.required_integrity SMALLINT NOT NULL DEFAULT 1` (deny-on-unknown, RFC §4.4),
  `tool_registry.sensitivity_label TEXT`; `server_registry.trust_tier SMALLINT NOT NULL DEFAULT 0`,
  `server_registry.trust_tier_label TEXT`; explicit `GRANT`/`REVOKE` (INV-011).
- **W1.2** **Credential-injection gate (corrected):** force `required_integrity ≥ 1` for any tool
  whose **effective** injection mode `≠ 'none'`, where effective =
  `COALESCE(tool_registry.injection_mode, server_registry.default_injection_mode)` (injection_mode
  exists on **both** — `tool_registry` V010 and `server_registry.default_injection_mode` V032).
  Implement as a **trigger / app-rule** (not a cross-table CHECK), **re-evaluated when a server's
  `default_injection_mode` changes.**
- **W1.3** Admin classification: extend `routers/server_registry.py` approve to set `trust_tier`;
  `PATCH /api/v1/admin/tools/{tool_id}` for `required_integrity`; **demo seed script** (so the
  registry is classified — without it the deny-on-unknown default blocks everything).
  `make classify-server` / `make classify-tool`.
- **AC:** unclassified tool → `required_integrity=1`; unclassified server → `trust_tier=0`;
  injection-mode tool forced `≥1` over the COALESCE'd mode; migration applies + rolls back. Tested.

### E2 — Proxy enforcement *(the control — ships D1/D2/D3/D8 with NO crypto)*
- **W2.1** Fail-closed **taint store** keyed on **`request.state.principal_id`**
  (`auth.py:286-288` — exists for mTLS/API-key/OIDC). INV-015: read error ⇒ tainted; expiry ⇒
  re-derive tainted; **separate namespace** from the fail-open `mcp_session:*` cache
  (`invocation.py:899-935`). Backend: Redis new namespace **or** Postgres (Open Q3; if Postgres,
  add to INV-011 allowlist).
- **W2.2** **Write-before-forward:** an untrusted (`trust_tier=0` / rank-0) result durably sets the
  taint bit **before** the result is forwarded; write failure ⇒ request 500.
- **W2.3** **Taint-floor gate** in `invocation.py`, order **INV-005 quarantine(268) → taint-floor
  → INV-004 OPA(441)**, *before* credential injection(606-649) and upstream(651) — so a blocked
  call never injects creds. Rule: `tainted and tool.required_integrity ≥ 1 → DENY`. `integrity_rank`
  is **never NULL** — `COALESCE(trust_tier, 0)` at resolution (a tool whose server row is gone ⇒
  rank 0). Taint-store error ⇒ **503**, never ALLOW.
- **W2.4** **Audit ALLOW + DENY** via proxy-side `_emit_audit_event` (`invocation.py:~1016`),
  capturing taint state at decision time — a dedicated DENY emit paralleling the OPA-deny block
  (INV-001; not delegated anywhere).
- **AC:** D1/D2 deny + audit; D3/D8 allow; store-blip ⇒ tainted; quarantine still precedes; **no
  crypto required for this epic.** Integration-tested.

### E3 — Labeler & signing *(the contribution — produces the envelope)*
- **W3.1** PKI (step-ca): dedicated **sub-CA** with bare-domain `nameConstraints` (appsec R-2);
  **labeler leaf** + labeler EKU OID, ~15-min TTL.
- **W3.2** **Renewal sidecar** holding the provisioner credential (not the proxy), **atomic cert
  swap** (write-temp + rename) + a dual-cert overlap window so rotation never half-writes (round-2).
- **W3.3** Deps: add `json-canonicalize` (RFC 8785); prune stale `ecdsa`/`python-jose` orphan
  (appsec R-1). Use a **distinctly-named JCS helper**; do **not** reuse `canonical_audit_json`
  (it's `json.dumps(sort_keys)` and lives in the separate `observability/mcp-audit-logger` package
  — lower collision risk than feared, but keep them distinct).
- **W3.4** Sign at the **router's final result assembly** — `mcp_server.py` has **two** return
  shapes (dispatch `_ok` ~718 **and** the meta/wrapper `json.dumps` path ~893) plus `tools.py`
  REST; instrument **each** (or add one response-serialization seam). Attach the §5 envelope to the
  returned `_meta`, signing the exact bytes returned. `content_hash` = SHA-256 over
  **JCS({content, structuredContent})**, `_meta` excluded; `/mcp` has no `structuredContent` →
  **both signer and verifier MUST emit the key explicitly as `null`** (never omit it — the
  most-likely day-1 hash-mismatch). `sig.value` = base64url(DER ECDSA); ES256 hardcoded;
  `BLOCK_ON_MATCH=True` precondition **checked against live config at sign time** (refuse to sign if
  false), so a screen_response-passed body is replaced before signing.
- **W3.5 (decoupled from enforcement):** if signing fails (rotation gap), the proxy **still
  enforces + audits** (E2 is DB-driven, independent of the envelope) and simply emits **no
  envelope** for that result — no enforcement FP storm. The envelope is a provenance artifact, not
  an enforcement input.
- **AC:** envelope survives to the client on both `/mcp` shapes + REST; blocked bodies never signed;
  hash excludes `_meta`; signing failure does not affect E2. Unit-tested.

### E4 — Independent verifier ("shim") *(demonstrates producer≠verifier — D4/D5/D6)*
- **W4.1** Verifier module: **SPKI-anchor `Store([sub_ca])`** (system store off), point-in-time
  `.time(signed_at)`, `nameConstraints`, **parsed-OID labeler EKU** (reject `anyExtendedKeyUsage`),
  `MAX_ENVELOPE_AGE` **first**, x5c chain rebuilt, ES256 hardcoded, JCS hash recompute.
  **Primitive choice is an appsec open item:** `cryptography.x509.verification.PolicyBuilder` is
  TLS-oriented (server/client EKU) — forcing a private labeler OID may require manual chain
  building; **the chosen approach MUST pass a second `appsec-reviewer` pass** (RFC §17). Since the
  verifier is *not* the enforcement boundary, a bug here fails the demo, not the control.
- **W4.2** **Passive inline observer** (not a gateway): consumes results, verifies, logs a verdict.
  Demonstrates D4/D5/D6 without MCP-transport-proxy plumbing or blocking.
- **AC:** F-1…F-8 + D4/D5/D6 pass; appsec sign-off on the verifier code.

### E5 — Demo & tests
- **W5.1** D1–D8 + F-1–F-8 tests; **taint-write-durability race** test (kill store between
  write-before-forward and next sink read → assert **DENY**).
- **W5.2** Demo script: proxy blocks D1 (audit row shown) + verifier rejects a forged envelope (D5).
- **W5.3** **D3 FP, falsifiable (round-2 fix):** corpus of N=100 sessions; **inject 5 deliberately
  MIS-classified servers** (a genuinely-clean source wrongly given `trust_tier=0`); FP = a
  *correctly-classified* clean session denied a high sink; **hard pass: FP=0 on correctly-classified
  clean sessions** while the mis-classified ones are *expected* denies (proves the floor reacts to
  classification, not noise). Fault-injection (store-blip) tests are **excluded** from the FP metric.
- **AC:** `make test-all` green; demo blocks D1 + rejects D5.

### E6 — Docs
- **W6.1** `docs/runbook.md` (proxy taint floor; labeler + sidecar; verifier), README
  Enforced-vs-Roadmap row (honest: POC / proxy-enforced / signed-envelope-verified-by-independent-
  observer / cross-trust deferred), RFC cross-links.

## 6. Milestones

| M | Deliverable | Depends on | Demonstrates |
|---|---|---|---|
| **M1** | E1 schema + classification | — | — |
| **M2** | **E2 proxy enforcement** | M1 | **D1/D2/D3/D8 — the control, no crypto** |
| **M3** | E3 labeler/signing + PKI + sidecar | M1 | envelope produced |
| **M4** | E4 verifier + E5 demo/tests | M2, M3 | D4/D5/D6 — the contribution |

Critical path **M1 → M2 → M3 → M4**. **The blockable control (M2) lands before any PKI** — the POC
can show a blocked action end-to-end before crypto exists, de-risking the demo.

## 7. Non-goals
Cross-boundary/federated trust (the POC verifier is process- not trust-separated); shim-as-enforcer
(enforcement is in-proxy); C-precise per-value taint; confidentiality/BLP axis; HSM; stock-client
conformance; multi-block/streamed results.

## 8. Risks & mitigations
- **R-a Over-block:** deny-on-unknown over-blocks unclassified high-sinks → W5.3 falsifiable FP gate
  + classification (W1.3) relief valve.
- **R-b INV-001 boundary:** enforcement + audit stay **in the proxy** (E2/W2.4) — the v0.2 boundary
  regression is reverted.
- **R-c Sign-point / two return shapes:** instrument every `mcp_server.py` return shape + REST
  (W3.4); test envelope survival on each.
- **R-d JCS `null` mismatch:** signer + verifier both emit the key as explicit `null`; F-8 guards.
- **R-e injection_mode COALESCE:** trigger over effective mode, re-eval on server change (W1.2).
- **R-f PolicyBuilder wrong primitive:** appsec open item; verifier not on enforcement path so a bug
  fails the demo not the control (W4.1).
- **R-g Sidecar rotation gap:** atomic swap + overlap (W3.2); signing failure can't FP-storm because
  enforcement is decoupled (W3.5).
- **R-h Demo unseeded:** seed script in M1 (W1.3).

## 9. Definition of Done
- [ ] D1–D8 + F-1–F-8 green in `make test-all`; demo blocks D1 (proxy) + rejects D5 (verifier).
- [ ] INV-001/003/004/005/011/015 green; `make security-check` + `opa check --strict` pass.
- [ ] E4 verifier passed a second `appsec-reviewer` review.
- [ ] D3 FP=0 on correctly-classified clean sessions.
- [ ] Docs updated; every new claim cites file:line.

## 10. Open questions
1. Labeler EKU OID — IANA PEN / arc for `<PEN>`? (Blocks E3/E4.)
2. Demo upstreams — real sandboxes or mock MCP servers seeded with injections?
3. Taint store backend — Redis (new fail-closed namespace) vs Postgres (durability + INV-011 GRANT).
4. Verifier primitive — `PolicyBuilder` (fighting TLS EKU semantics) vs manual chain-build on
   `cryptography`? (appsec to rule.)
5. Confirm `10min < 15min − 2·60s` window defaults; pin the `cryptography` version claim (repo pins
   44.0.3; RFC §17 said "47").
