# Testing

How to run and reason about the test suite. The security posture is only as trustworthy as the tests
that gate it, so the rule is: **every enforced control has a test, and the CI gate fails closed.**

## Test layout

```
proxy/tests/
  unit/         # no external services — the bulk of coverage (fast, deterministic)
  integration/  # require a running stack (marked `-m integration`)
  security/     # invariant / sandbox-escape / tamper regression tests
  rfc0002/      # trust-envelope oracle-parity + red-team regression
sandbox/tests/red_team/   # containerized adversarial harness (network/credential/fs isolation)
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
make test-lab-functional   # end-to-end gate chain against the lab (the headline chain test)
```

## The security gate

```bash
make security-check
```

This is the invariant gate wired into CI. It **fails closed** — a missing scanner (trufflehog/opa)
is a failure, not a skip. It checks, among others: INV-002 redaction tests, INV-003 `default allow =
false` in `policies/rego/`, F-001 network isolation (`scripts/check_network_isolation.py` across all
compose tiers), and F-002 signed-bundle-by-default (`scripts/check_signed_default.sh`). See
[ARCHITECTURE.md §10](ARCHITECTURE.md#10-security-invariants) for the full invariant list.

## What "done" means for a change

A change is complete only when: code merged, a regression test is in the blocking suite, the docs
match code, and `make security-check` is green. A doc claim without backing code is treated as a bug.
