# Contributing

Thanks for your interest in the MCP Security Platform. This is a solo-maintained, open-source
reference implementation — contributions, issues, and ideas are welcome.

## Ground rules

- **It's a reference implementation, not a product.** Changes should keep the docs honest: if you
  add or wire a control, update the **Enforced today vs Roadmap** table in the [README](README.md)
  so it stays matched to the code. Over-claiming is treated as a bug.
- **Security invariants are non-negotiable.** See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).
  Don't introduce a fail-open path. Deny-by-default and fail-closed are the defaults everywhere.
- **No secrets in commits.** `.env*` files are gitignored; only `*.example` placeholders are tracked.

## Development setup

The lab is the easiest place to develop against a full stack. It runs on **Podman** (the
production tiers run on **Docker** — see [LAB.md](LAB.md) and [INSTALL.md](INSTALL.md)).

```bash
cp .env.lab.example .env.lab
make -f Makefile.lab lab-up
make dev-up            # hot reload + debug ports
```

## Before you open a PR

```bash
make lint              # ruff
make test              # unit + integration
make security-check    # secret scan + rego lint + OPA deny-default + F-001 isolation gate
```

- Keep changes focused; one logical change per PR.
- Add or update tests for behaviour you change (unit under `proxy/tests/unit`, integration under
  `proxy/tests/integration`, isolation/red-team under `sandbox/tests`).
- Update relevant docs in the same PR.
- Use clear, conventional commit messages (`feat(...)`, `fix(...)`, `docs(...)`, `chore(...)`).

## Reporting security issues

**Do not** open a public issue for a vulnerability. Follow [`SECURITY.md`](SECURITY.md).

## Code of Conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md). By participating you agree to
uphold it.
