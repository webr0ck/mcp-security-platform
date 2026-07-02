# RFC-0002 verification suite

Full plan & rationale: [`docs/rfc/RFC-0002-verification-plan.md`](../../../docs/rfc/RFC-0002-verification-plan.md).

**Run it:**

```bash
./scripts/run_rfc0002_verification.sh            # from repo root; offline-first, auto-detects a live proxy
./scripts/run_rfc0002_verification.sh --offline  # no live probe
```

**Three layers** (by pytest marker):

- `oracle` — pure RFC-0002 §4–§6 decision logic (`spec_oracle.py`) vs the paper's Appendix B vectors and Appendix C threats. No gateway. **Green today.**
- `substrate` — the real implemented RFC-0001 `TrustLabeler`/`TrustVerifier`/taint floor. No containers. **Green today.**
- `conformance` / `live` — RFC-0002 §4–§6 integrated into the gateway, and end-to-end against a running proxy. **Skip** with an actionable "implement X" message until built / a proxy is up.

Baseline (offline): `51 passed, 11 skipped`. Skips are the implementation backlog + live-absent, never failures.

> Why the skips instead of red tests? RFC-0002 §4 (content classification), §5 (federation), and §6 (AI provenance) are **not implemented in the gateway yet** — only the §3.2 signed-envelope substrate is. The suite refuses to test APIs that don't exist; each skip names exactly the module/config to build to make it pass.
