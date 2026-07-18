# Repository Guidelines

## Project Structure & Module Organization

`proxy/app/` contains the Python 3.12 FastAPI enforcement service; its unit, integration, security, and performance tests live under `proxy/tests/`. OPA/Rego authorization rules are in `policies/rego/`, while `gateway/` holds Nginx and ModSecurity configuration. Use `lab/` and `podman-compose.lab.yml` for the self-contained Podman environment. Supporting components live in `observability/`, `scanner_worker/`, `build_worker/`, and `mcp-servers/`; deployment material is under `deployments/`, `infra/`, and `helm/`. The React/Vite frontend is in `ui/`, with Playwright tests in `ui/e2e/`. Operational helpers belong in `scripts/`.

## Build, Test, and Development Commands

- `make dev-up` / `make dev-down`: start or stop the development Compose stack with hot reload.
- `make test-unit`: run proxy unit tests inside the running proxy container; `make test` runs the full proxy suite.
- `make lint`: run Ruff checks, Ruff format verification, and strict mypy checks.
- `make security-check`: enforce secret-scan, Rego, deny-by-default, and network-isolation invariants.
- `make -f Makefile.lab lab-up` followed by `make -f Makefile.lab lab-smoke`: build, seed, and verify the Podman lab.
- `cd ui && npm ci && npm run build` or `npm run e2e`: build the frontend or run Playwright.

## Coding Style & Naming Conventions

Use four-space indentation in Python, type annotations, `snake_case` for modules/functions, and `PascalCase` for classes. Ruff targets Python 3.12 with a 100-character line limit; format with `ruff format`. Keep TypeScript consistent with the existing two-space, no-semicolon style, and name React components in `PascalCase`. Preserve fail-closed behavior: unavailable policy, identity, or credential dependencies must deny requests.

## Testing Guidelines

Use pytest files named `test_*.py` and mark tests `unit`, `integration`, `security`, or `performance` as appropriate. Add focused unit coverage for logic changes and integration or `sandbox/tests/red_team/` coverage for cross-service/security behavior. CI requires at least 80% unit coverage and rejects unexplained `pytest.skip()` calls. Rego changes should include corresponding `*_test.rego` cases.

## Commit & Pull Request Guidelines

Prefer the repository’s conventional style: `feat(scope): ...`, `fix(lab): ...`, `test(acceptance): ...`, `docs: ...`, or `chore: ...`. Keep each PR to one logical change, explain security and operational impact, link related issues, and include tests plus relevant documentation updates. If control behavior changes, update README’s **Enforced today vs Roadmap** table. Never commit secrets; track only placeholder `*.example` configuration. Report vulnerabilities through `SECURITY.md`, not public issues.
