# MCP Security Platform

A full-stack, open-source security reference implementation for the [Model Context Protocol](https://modelcontextprotocol.io/) (MCP) ecosystem: a hardened ingress gateway, a semantic security proxy, a credential broker, and a compliance-grade observability stack.

> ⚠️ **Status & honesty notice (2026-05-16).** This README historically over-described the system. The **authoritative, reality-checked** documents are:
> - [`docs/REVIEW-2026-05-16.md`](docs/REVIEW-2026-05-16.md) — security findings + claimed-vs-actual audit
> - [`docs/ARCHITECTURE-v2.md`](docs/ARCHITECTURE-v2.md) — reality-annotated architecture (supersedes the stale `ARCHITECTURE.md` v1)
> - [`docs/ROADMAP.md`](docs/ROADMAP.md) — **status dashboard: what's done vs next**
> - [`docs/DEV-TEST-PROCESS.md`](docs/DEV-TEST-PROCESS.md) — change/test gates
>
> Treat any feature claim below as **"see ARCHITECTURE-v2 for verified status"** until Phase 1 (truth reconciliation) completes.

## Status — done vs next

**✅ Done (Phase 0 — security unblock, verified):**
- Credential-broker identity collapse fixed (CB-001) — identity from the authenticated session, not a spoofable header; server-side nonce + PKCE OAuth.
- Vault master-key TLS enforced (CB-002); HKDF KEK (CB-007); synchronous credential audit (CB-004); DB grant fix (CB-005); adapter error-leak fixed (CB-010).
- **F-001 network isolation — implemented and proven on the live lab** (a non-dialed sidecar can no longer reach `proxy:8000`; proxy stays healthy).
- OPA signed-bundle mechanism delivered (F-002); 79 unit + 9 in-process MCP-client tests pass; `make security-check` gained an F-001 isolation gate.

**⏳ Next (Phase 1 — truth reconciliation, no code risk):**
- Replace stale `ARCHITECTURE.md` v1; remove/relabel **not-built** features (SPDX SBOM, outbound Jira, Helm/K8s, OIDC, per-tool rate limiting, learned anomaly baseline).
- Fix broken CI/test cross-references (the integration job currently fails on missing fixtures).
- Document the credential broker in API/RBAC/SECURITY docs.

**🔜 Then:** Phase 2 hardening (CB-008, INV-007 verify, pre-commit secret hook, F-002 staging enforcement) → Phase 3 features.

Independent third-party MCP-ecosystem vulnerability statistics are intentionally **not cited here** pending a verifiable source (previously an unsourced claim — see ROADMAP P1.3).

## What This Is

Three integrated security layers that work together:

**Layer 1 — Hardened Nginx Gateway**
TLS 1.3 termination, mTLS client certificate enforcement for AI agents, per-endpoint rate limiting, WAF (ModSecurity + OWASP CRS) with MCP JSON-RPC custom rules, and structured JSON access logs.

**Layer 2 — MCP Security Proxy (FastAPI)**
Intercepts all MCP JSON-RPC calls. Enforces identity (mTLS or API key). Runs LLM-assisted Tool Manifest Auditing (Ollama), generates CycloneDX SBOMs per tool, detects anomalous invocation sequences, and evaluates OPA/Rego policies for every tool call.

**Layer 3 — Observability Stack**
Compliance-grade audit logging (SHA-256 per-event, credential auto-redaction), Loki + Grafana dashboards, Alertmanager alerts, MinIO WORM log archival (90-day Object Lock retention), and daily automated compliance checks across 10 PII/credential pattern categories.

## Differentiators vs. Competing Tools

_Removed: the prior comparison table referenced competitors that could not be verified and scored this project favourably on every row with no sourcing. A sourced comparison will be reinstated only if backed by verifiable references (ROADMAP P1.3). For what this platform actually implements vs. only documents, see [`docs/ARCHITECTURE-v2.md`](docs/ARCHITECTURE-v2.md)._

## Quick Start

```bash
# 1. Clone and set up environment
git clone https://github.com/your-org/mcp-security-platform
cd mcp-security-platform
cp .env.example .env
# Edit .env — fill in required secrets (see .env.example comments)

# 2. Start all services
make up

# 3. Pull the Ollama model for risk scoring
make pull-model

# 4. Verify health
make health
```

The proxy API is available at `https://localhost/api/v1` (via gateway).
Grafana dashboards at `http://localhost:3000` (dev) or via gateway proxy (prod).
API documentation at `https://localhost/docs` (development mode only).

## Development

```bash
# Start with hot reload and debug ports
make dev-up

# Run tests
make test

# Lint
make lint

# Security invariant checks
make security-check

# Open a shell in the proxy container
make proxy-shell

# psql session
make db-shell
```

## Architecture

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the full system design including:
- Component diagram
- Service boundary definitions
- Trust boundaries and security zones
- Critical data flows (invocation, registration, compliance)
- Threat model (6 threat scenarios)
- Integration points (OIDC, Jira, Artifactory)

## API Reference

See [docs/API.md](docs/API.md) for the complete REST API specification.

## RBAC

See [docs/RBAC.md](docs/RBAC.md) for the role model (admin, agent, auditor, readonly) and permission matrix.

## Security Non-Negotiables

See [docs/SECURITY_NONNEGATABLES.md](docs/SECURITY_NONNEGATABLES.md) for invariants that can never be violated.

## ADRs

- [ADR-001: Language and Framework Choices](docs/ADR/001-language-choices.md)

## Project Structure

```
mcp-security-platform/
├── gateway/                 # Nginx config, step-ca scripts, ModSecurity rules
│   ├── nginx/
│   ├── modsecurity/
│   └── step-ca/
├── proxy/                   # FastAPI application (Layer 2)
│   ├── app/
│   │   ├── main.py
│   │   ├── core/            # Config, database, Redis, security utils
│   │   ├── routers/         # API route handlers
│   │   ├── services/        # Auditor, SBOM, anomaly, policy, invocation
│   │   ├── models/          # SQLAlchemy + Pydantic models
│   │   └── middleware/      # Auth, audit, RBAC middleware
│   ├── tests/
│   │   ├── unit/
│   │   └── integration/
│   ├── Dockerfile
│   └── pyproject.toml
├── observability/           # Layer 3
│   ├── mcp-audit-logger/    # Python library: schema, redaction, hasher
│   ├── loki/                # Loki + Promtail configuration
│   ├── grafana/             # Dashboards and provisioning
│   └── compliance-checker/  # Daily compliance cron job
├── policies/
│   └── rego/                # OPA Rego policy files
├── infra/
│   ├── db/
│   │   └── migrations/      # V001, V002, V003 SQL migrations
│   └── scripts/             # MinIO setup, DB role init
├── helm/                    # Kubernetes Helm chart stubs
├── docs/
│   ├── ARCHITECTURE.md
│   ├── API.md
│   ├── RBAC.md
│   ├── SECURITY_NONNEGATABLES.md
│   └── ADR/
│       └── 001-language-choices.md
├── docker-compose.yml
├── docker-compose.dev.yml
├── .env.example
├── .gitignore
└── Makefile
```

## Technology Stack

| Component | Technology |
|-----------|-----------|
| Gateway | Nginx 1.25 + ModSecurity v3 + OWASP CRS |
| Internal CA | Smallstep step-ca |
| Proxy | Python 3.12, FastAPI, Pydantic v2 |
| Policy engine | OPA 0.63+ (sidecar) |
| Local LLM | Ollama (llama3.2 default) |
| Database | PostgreSQL 16 |
| Cache / sessions | Redis 7 |
| SBOM format | CycloneDX 1.5 + SPDX 2.3 |
| Log aggregation | Loki 3.0 + Promtail |
| Log archive | MinIO (Object Lock / WORM) |
| Dashboards | Grafana OSS 11 |
| Alerting | Prometheus Alertmanager |

## License

Apache 2.0. See [LICENSE](LICENSE).
