# Article 4 truth-fixes — CHANGES (branch `feat/trust-envelope-consumer`)

The 3-critic (Codex) REJECTED Article 4 for code-verified overclaims. This branch makes the
contested claims TRUE with runnable proof. **No commits — left for the user to review + commit.**

Interpreter note: the proxy pytest suite needs `opentelemetry` (a pre-existing conftest import).
I installed `opentelemetry-api opentelemetry-sdk opentelemetry-exporter-otlp-proto-grpc` into
`proxy/.venv` so tests run. Run tests with `proxy/.venv/bin/python -m pytest ...`.

---

## WI-1 — Taint floor: notify-only vs full-enforce, BOTH real + tested + comparable

**Before:** taint floor was NOTIFY-ONLY since 2026-07-18 (PRD-0010 Phase 0). `invocation.py`
Step 1.6 never blocked; the old `TaintFloorDenyError` hard-deny was dead-but-router-wired.
Article 4's "403 / deterministic origin-based denial locally / Operationally proven" was false.

**Change (mode selector — both modes real):**
- `proxy/app/core/config.py`: new `TAINT_FLOOR_MODE: str = "notify"` (`notify|enforce`).
- `proxy/app/services/taint_floor.py`: new pure helper `resolve_taint_action(decision, mode)`
  + sentinels `TAINT_ACTION_BLOCK`/`TAINT_ACTION_NOTIFY`. `deny`+`enforce`→block; `deny`+anything
  else→notify (an unknown mode NEVER silently starts denying a dark-launched control; the
  security fail-closed lives in the *decision*, deny-on-unknown-taint).
- `proxy/app/services/invocation.py` Step 1.6: branches on the resolved action. **Enforce** ⇒
  audit `outcome="deny"` (INV-001) then raise the existing `TaintFloorDenyError` — which the
  routers (`mcp_server.py` ×2, `tools.py`) ALREADY map to a 403 / JSON-RPC `-32003` error, so
  **zero router changes**. **Notify** ⇒ unchanged allow-with-disclaimer (`outcome="allow"`,
  `notices=[...]`, empty `deny_reasons`).

**Tests (all pass):**
- `proxy/tests/unit/test_taint_floor.py` — `resolve_taint_action` truth table incl. unknown-mode
  degrades to notify. (23 passed)
- `proxy/tests/unit/services/test_invocation_taint_notices.py::test_taint_enforce_mode_denies_and_audits_deny`
  — end-to-end: enforce mode raises `TaintFloorDenyError` + emits an `outcome="deny"` audit with a
  `taint_floor` reason. The existing notify test (#3) still passes — the two are the honest
  side-by-side comparison the article can cite.
- Pre-existing (NOT mine): 3 DB-plumbing tests in that file fail on a SQLAlchemy-version
  `_instantiate_plugins` unpack error — confirmed failing on clean HEAD via `git stash`.

## WI-3 — Full reason coverage (deny-on-any-rejected)

**Before:** ENFORCE denied only 4 reasons (`signature_invalid|no_envelope|chain_validation_failed|
content_hash_mismatch`); stale/EKU-rejected/malformed-timestamp/empty-x5c/etc. were still advisory.

**Change:** `proxy/app/routers/mcp_server.py` — extracted a named, testable predicate
`trust_enforce_denies(enforce_enabled, verdict) = enforce_enabled and not verdict.accepted` and
replaced the `startswith(allowlist)` condition with it. `VerifierVerdict` is exhaustively
fail-closed, so `not accepted` is the complete, drift-proof deny set.

**Test:** `proxy/tests/rfc0002/test_substrate_rfc0001.py` — WI-3 cases build a REAL stale envelope
and a REAL EKU-rejected envelope via the shipped verifier, and prove (a) the OLD 4-reason allowlist
would NOT have denied them (`_old_enforce_would_deny(...) is False`), and (b) the NEW predicate DOES
(`trust_enforce_denies(True, verdict) is True`) — a non-vacuous behavior change. Plus: an accepted
verdict is never denied; enforce-off never denies. (18 passed, 1 skipped)

**REST invoke path** (`proxy/app/routers/tools.py` ~1612): scoped-in-comments as **signer-only** —
it labels the result and returns it; it deliberately does not run the observer/enforce verify (that
would only re-check the gateway's OWN just-minted signature — see WI-4). "Full reason coverage" is a
property of the ENFORCE verify seam (dispatch path), which the comment states.

## WI-4 — Enforce-semantics decision + reconciliation (the crisp text the article cites)

Documented in code at the enforce seam (`proxy/app/routers/mcp_server.py`, above the observer block):

> The gateway signs the result and then, under ENFORCE, verifies THAT SAME freshly-signed envelope
> before returning. Because it verifies its own signature over bytes it just produced, this seam
> CANNOT detect a downstream man-in-the-middle that tampers AFTER the result leaves the gateway.
> What ENFORCE here DOES guarantee: the gateway never emits a result it cannot self-verify (a
> malformed/absent/forged envelope or `content_hash_mismatch` arising before/at signing fails
> closed). End-to-end integrity against a wire MITM is the INDEPENDENT CONSUMER's job
> (mcp-envelope-harness `TrustGate` verifying against a pinned anchor). **The article must not
> conflate the two:** gateway ENFORCE = "don't emit a result we can't self-verify"; consumer verify
> = "don't trust a result that was altered in transit". `content_hash_mismatch` DOES deny (via WI-3).

## Sanity

- `proxy/.venv/bin/python scripts/demo_trust_envelope.py` → ALL DEMOS PASSED (3/3).
- `proxy/.venv/bin/python -m pytest tests/unit/test_taint_floor.py tests/rfc0002/test_substrate_rfc0001.py tests/integration/test_taint_floor_invoke.py` → green.

## Files changed (platform)

- `proxy/app/core/config.py` — `TAINT_FLOOR_MODE`
- `proxy/app/services/taint_floor.py` — `resolve_taint_action` + sentinels
- `proxy/app/services/invocation.py` — Step 1.6 mode branch (enforce deny / notify)
- `proxy/app/routers/mcp_server.py` — `trust_enforce_denies` predicate + WI-4 decision comment
- `proxy/app/routers/tools.py` — REST-path signer-only scope comment
- `proxy/tests/unit/test_taint_floor.py` — `resolve_taint_action` tests
- `proxy/tests/unit/services/test_invocation_taint_notices.py` — enforce e2e test + stub update
- `proxy/tests/rfc0002/test_substrate_rfc0001.py` — WI-3 stale/EKU deny tests

WI-2 (fast-agent real conformance) is in the **mcp-envelope-harness** repo — see its
`docs/ROADMAP.md` Loop 5.
