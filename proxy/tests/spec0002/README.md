# SPEC-0002 verification suite

The specification under test: [SPEC-0002](https://github.com/webr0ck/security-specs/blob/main/specs/0002-mcp-content-classification-federated-trust-ai-provenance.md).

**Run it:**

```bash
./scripts/run_spec0002_verification.sh            # from repo root; offline-first, auto-detects a live proxy
./scripts/run_spec0002_verification.sh --offline  # no live probe
```

**Three layers** (by pytest marker):

- `oracle` — pure SPEC-0002 §5–§7 decision logic (`spec_oracle.py`) vs the paper's Appendix B vectors and Appendix C threats. No gateway. **Green today.**
- `substrate` — the real implemented SPEC-0001 `TrustLabeler`/`TrustVerifier`/taint floor. No containers. **Green today.**
- `conformance` / `live` — SPEC-0002 §5–§7 integrated into the gateway, and end-to-end against a running proxy. **Skip** with an actionable "implement X" message until built / a proxy is up.

Baseline (offline): `51 passed, 11 skipped`. Skips are the implementation backlog + live-absent, never failures.

> Why the skips instead of red tests? SPEC-0002 §5 (content classification), §6 (federation), and §7 (AI provenance) are **not implemented in the gateway yet** — only the §4.2 signed-envelope substrate is. The suite refuses to test APIs that don't exist; each skip names exactly the module/config to build to make it pass.
