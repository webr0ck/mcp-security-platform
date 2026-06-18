# WAIVER-002 — lab-seeder Receives Full `.env` (S4 gateway-secret-scope exception)

**Status:** ACCEPTED
**Date:** 2026-06-18
**Reviewer:** appsec review (pre-publish hardening pass)
**Waiver owner:** platform team
**Review trigger:** F-001 isolation gate (S4 sub-check) flagged `lab-seeder` during the publish audit

---

## What is waived

The S4 sub-check in `scripts/check_network_isolation.py` asserts that only services in
`_GATEWAY_SECRET_ALLOWED_SERVICES` may receive the full `.env` (which carries
`GATEWAY_SHARED_SECRET`). Every other service must scope its env explicitly via `environment:` keys.

This waiver adds **`lab-seeder`** (in `podman-compose.lab.yml`) to that allow-list. The seeder
declares `env_file: [.env, .env.lab]` and therefore receives `GATEWAY_SHARED_SECRET` even though
it never reads it.

## Why this is accepted

1. **Lab-only, never in a production tier.** `lab-seeder` exists solely in `podman-compose.lab.yml`.
   It is absent from `docker-compose.yml`, `compose.engine.yml`, and `compose.standard.yml`. No
   production deployment ships it.

2. **Run-once bootstrap, not a request-path service.** It seeds the DB, Vault master secret, and
   lab IdP/service accounts, then exits (`restart: "no"`). It terminates no TLS and serves no traffic.

3. **It does not use the secret.** `lab/seeder/seed.py` reads DB, Vault, Keycloak, and lab-service
   variables (verified by source grep); `GATEWAY_SHARED_SECRET` is never referenced. There is no code
   path that could leak or misuse it.

4. **Broad env is inherent to a seeder.** Scoping its ~20 variables into an explicit `environment:`
   block adds maintenance burden and drift risk for zero security gain, given (1)–(3).

## Conditions for re-evaluation

Revisit this waiver if:
- `lab-seeder` is ever added to a non-lab compose tier.
- The seeder is changed into a long-running service or gains a network listener.
- `lab/seeder/seed.py` begins reading `GATEWAY_SHARED_SECRET`.

## Affected code

- `podman-compose.lab.yml` — `lab-seeder.env_file: [.env, .env.lab]`.
- `scripts/check_network_isolation.py` — `_GATEWAY_SECRET_ALLOWED_SERVICES` includes `lab-seeder`.
- `lab/seeder/seed.py` — confirmed not to reference `GATEWAY_SHARED_SECRET`.
