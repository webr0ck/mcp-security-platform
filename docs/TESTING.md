# Testing

How to run and reason about the test suite. The security posture is only as trustworthy as the tests
that gate it, so the rule is: **every enforced control has a test, and the CI gate fails closed.**

The normative test **program** — what tests any re-implementation must build, and the
invariant-to-test acceptance matrix — is [`docs/spec/07-testing-and-qa.md`](spec/07-testing-and-qa.md).
This file is the operator's quick reference for the current suite.

## Test layout

```
proxy/tests/
  unit/         # no external services — the bulk of coverage (fast, deterministic)
  integration/  # require a running stack (marked `-m integration`)
  security/     # invariant / sandbox-escape / tamper regression tests
  rfc0002/      # trust-envelope oracle-parity + red-team regression
  performance/  # throughput tests (make test-perf)
sandbox/tests/red_team/   # containerized adversarial harness (network/credential/fs isolation)
lab/tests/                # lab functional gate-chain (functional_test.py) + lab MCP server tests
ui/e2e/                   # Playwright portal + acceptance specs
```

Markers (`proxy/pyproject.toml`): `unit` (no deps), `integration` (needs services).

## Running locally (no containers)

The unit suite needs no running stack — just the proxy's Python deps:

```bash
cd proxy
python3 -m pytest tests/unit -q                 # full unit suite (fast)
python3 -m pytest tests/unit/test_p1_verified_identity.py -q   # a single file
python3 -m pytest tests/unit tests/security -q  # unit + security invariants
```

## Running via the stack (containers)

Integration and OAuth-flow tests need the stack up (see [LAB.md](../LAB.md) / [INSTALL.md](../INSTALL.md)):

```bash
make test              # everything, inside the proxy container
make test-unit         # unit only
make test-integration  # integration (-m integration; needs services)
make test-oauth        # full OAuth/ROPC flow (needs Keycloak reachable)
```

The headline end-to-end gate chain runs from the **host** (not inside the proxy container),
against the lab's published ports:

```bash
make test-lab-functional   # lab/tests/functional_test.py — the headline chain test
```

## The security gate

```bash
make security-check
```

This is the invariant gate wired into CI. It **fails closed** — a missing scanner (trufflehog/opa)
is a failure, not a skip. It checks: INV-002 redaction tests, INV-003 `default allow =
false` in `policies/rego/`, INV-008 secret scanning (trufflehog), rego lint (`opa check`),
F-001 network isolation (`scripts/check_network_isolation.py` across all five compose tiers),
F-002 signed-bundle-by-default (`scripts/check_signed_default.sh`), the Loki label check, and
semgrep. See [ARCHITECTURE.md §10](ARCHITECTURE.md#10-security-invariants) for the full invariant
list and [spec/07 §2.3](spec/07-testing-and-qa.md) for the gate-by-gate breakdown.

## What "done" means for a change

A change is complete only when: code merged, a regression test is in the blocking suite, the docs
match code, and `make security-check` is green. A doc claim without backing code is treated as a bug.
