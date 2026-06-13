# SHIP v0.1 — minimal, honest public release (Path A)

> Decided 2026-05-30 after a Claude+Codex dual-review (`Brain/Vault/00_AI/__dual_review__/2026-05-30_mcp-security-platform.md`).
> **Frame: reference implementation / work-in-progress** — publish the verified subset honestly; label the rest roadmap.
> Audited findings CB-001…CB-011 are fixed; the over-claims to remove are *coverage* claims, not unfixed vulns.
> Brand: `purplehootie` (bylined Alexander Romanov). Repo: `github.com/purplehootie/mcp-security-platform`.

## Phase 1 — Doc truth-reconciliation  (THE gate)            [semi-auto]
- [x] README leads with **"Reference implementation / WIP"** + an **Enforced-today vs Roadmap** table:
      - **Enforced today:** OPA on REST `/api/v1/tools/{id}/invoke`; F-001 network isolation (proven); credential-broker crypto (CB-001…011); synchronous audit on REST invocation + enrollment.
      - **Roadmap / NOT yet:** `/mcp` built-ins through OPA/audit; credential broker wired at startup; signed-policy-by-default; per-tool rate limiting; OIDC login; SPDX SBOM; Helm/K8s; learned anomaly baseline.
- [x] Delete unsourced "92% of MCP servers vulnerable" stat + the competitor comparison table.
- [x] SBOM route: now returns 501 for `format=spdx` (was silently serving CycloneDX); dead SPDX constant removed. ✅ Was: stop accepting `format=spdx` (return 501 or drop) — it currently returns CycloneDX while claiming SPDX.
- [x] Replace stale `ARCHITECTURE.md` v1 → ARCHITECTURE-v2; link the dual-review.
- [x] **DONE** — `scripts/ship-check.sh` (+ `make ship-check`): docs-honesty gate (fails on retired over-claims/brand leaks in README), secret scan, `docker compose config` smoke, isolation demo. Passing as of 2026-05-30.

## Phase 2 — Minimal, honest v0.1                            [smoke-test auto]
- [ ] **Fix nginx `conf.d/default.conf`** — remove or render the unresolved `PROXY_SSL_CONFIG` template + drop TLS 1.2 (else `docker compose up` may not start; contradicts "TLS 1.3 only"). Blocker for "one working command".
- [ ] LICENSE (MIT).
- [ ] `make security-check` green (trufflehog secret scan + rego lint + OPA deny-default + F-001 isolation).
- [ ] **ONE working command:** verify `docker compose up` clean on a fresh checkout.   **AUTO** smoke.
- [ ] **ONE reproducible demo:** the F-001 isolation proof (`scripts/check_network_isolation.py`) — real, verified, honest, and on-message for the blog.

## Phase 3 — Publish                                          [auto]
- [ ] Register `purplehootie.com` + GitHub `purplehootie` (verified AVAILABLE 2026-05-30).
- [ ] **AUTO** pre-push secret scan → `gh repo create purplehootie/mcp-security-platform --public --source=. --push` → `git tag v0.1 && git push --tags`.

## Phase 4 — Blog (the end)                                   [mostly done]
- [ ] Apply blog tweak: "identity from the session, not a spoofable header" → "identity from the mTLS session as provided by the gateway" (the app currently trusts the gateway-set header — see dual-review).
- [ ] Publish `2026-06-07_mcp-gateway-blog-draft.md` on purplehootie.com; link the repo (+ optionally this dual-review as proof of honest engineering).
- [ ] Distribute: 20 targeted shares (O2 KR2).

## Automatable in one script (`scripts/ship-check.sh`)
1. docs-honesty grep gate (Phase 1) · 2. trufflehog/secret scan · 3. `docker compose up` smoke + isolation demo · 4. fail-closed. Run before every push.

---

## DONE — Security fixes (branch `security-fixes-2026-06-04`, 2026-06-13)

All six blocking security findings from the 2026-06-12 in-session review are committed. Doc-sync and roadmap update committed in the same session.

| ID | Severity | Fix | Commit |
|----|----------|-----|--------|
| **S1** | HIGH | IPv4-mapped IPv6 SSRF bypass + embedded-v4 decode (mapped/6to4/Teredo/NAT64/v4-compat) in `services/ssrf.py` | `fde3d62` |
| **S2** | MEDIUM | Meta-tool audit fail-closed (INV-001 gap): `emit_internal_tool_event` routes through `_emit_audit_event`; `AuditEmissionError` → 500 | `05b7201` |
| **S7** | MEDIUM | KMS master-secret 256-bit floor: `_decode_master_secret` rejects `<32 bytes`, fail-closed at fetch time | `05b7201` |
| **S3** | HIGH | Approval healthcheck TOCTOU/DNS-rebind SSRF pin: `PinnedIPTransport` threaded into healthcheck adapters; IP pinned before connect | `611a8ea` + `382b6ef` |
| **S6** | MEDIUM | Scoped rate-limiter fail-closed on Redis error: pre-auth paths (`/oauth/register`, unauthenticated `/mcp`) fail-closed; authenticated traffic uses local fallback; no global self-DoS | `b94697a` |
| **S4** | HIGH (PARTIAL) | Gateway secret scoped to proxy only; alertmanager-config-renderer / minio-init / compliance-checker no longer receive `.env`; F-001 gate extended to cover `env_file` scope | `b7c0641` |

---

## DONE — PRD-0001 M3: Labeler / PKI / Signing (E3) — 2026-06-13

Trust envelope signer fully implemented. Commits: `2ec2660` (JCS dep), `461e52f` (TrustLabeler), `2a2f1ab` (PKI scripts), `d4eec27` (pki perms fix), `0f45e71` (config), `09b9719` (router wiring), `c08a8b1` (compose sidecar), `2bd1d88` (lint).

| Component | Deliverable | Commit |
|---|---|---|
| W3.3 | `jcs` (RFC 8785) dep + `jcs.py` helpers | `2ec2660` |
| W3.4 core | `TrustLabeler` class — cert cache, ES256/JCS envelope, `sign_result()` → `None` on failure (W3.5) | `461e52f` |
| W3.1 | `infra/pki/init-labeler-pki.py` — sub-CA (nameConstraints=`platform.internal`) + leaf (EKU OID `1.3.6.1.4.1.99999.1.1`, 15-min TTL) | `2a2f1ab` |
| W3.2 | `infra/pki/renew-labeler-leaf.py` — atomic swap every 12 min | `2a2f1ab` |
| Security | `_atomic_write` enforces `0o600` + `0o700` dir (appsec HIGH findings) | `d4eec27` |
| W3.4 config | `TRUST_ENVELOPE_ENABLED`, `LABELER_CERT_PATH` etc. in `config.py`; startup init in `main.py` | `0f45e71` |
| W3.4 wire | Signing at mcp_server.py Shape A + Shape B + tools.py REST; trust meta injected into invocation.py result | `09b9719` |
| W3.2 infra | `labeler-data` volume + `labeler-renewal` sidecar (compose profile `trust-envelope`) + `make labeler-init` | `c08a8b1` |

19 new tests. F-001 gate passes. OPA strict passes. Ruff clean on new files.

---

## NEXT

Priority order:

1. **PRD-0001 M4: Independent verifier ("shim") + demo suite (E4/E5)**
   - D1–D8 verifier deliverables
   - F-1–F-8 test coverage
   - Full trust-envelope POC end-to-end

3. **DA-1: Staging proof-run (INV-012 honesty)**
   - Stand up a staging stack and prove OPA rejects an unsigned/tampered bundle, OR downgrade INV-012 from "ENFORCED" to "mechanism present, runtime-rejection untested."
   - `scripts/check_signed_default.sh` is a static grep — relabel as structural/static check, not runtime assertion.

4. **DA-2: `response_filter.py` advisory label**
   - Label as detection-grade/advisory, not a security control.
   - Fix `BLOCK_ON_MATCH` doc/comment contradiction.

5. **DA-3: Threat model scope — authenticated-agent-as-adversary**
   - State out-of-scope in `ARCHITECTURE-v2.md §6`.
   - Verify `authz.rego platform_meta_tool_roles` stays tight.

**Why this order:** Security fixes are non-negotiables — blocking for any public release. M3/M4 implement the RFC-0001 trust envelope POC (the value-add feature; the whole point of the platform). DA items are doc/honesty work with no code risk but high credibility value for the public release.

---

## DEFERRED

- **S5 (kms envelope AAD for app-only secrets)** — LOW. The `kms.py:envelope_encrypt/decrypt` helpers pass `AAD=None` (used by the app-only-secret / `entra_client_credentials` regime). The live `approach_a` broker path is NOT affected — it already binds full AAD. S5 is deferred until the app-only-secret regime is in active use. Tracked in `credential_broker/kms.py` docstring and `SECURITY_NONNEGATABLES.md §INV-013 SR-5`.
- **C-precise per-value taint (conformant harness)** — RFC-0001 §8.2 future work. No code or test exists today.
- **Confidentiality / BLP exfiltration axis** — RFC-0001 §15 future work. Out of scope for v0.1.
- **Federated trust roots** — RFC-0001 §15 future work. Out of scope for v0.1.
