# MCP Security Platform

A full-stack, open-source security reference implementation for the [Model Context Protocol](https://modelcontextprotocol.io/) (MCP) ecosystem.

92% of MCP servers currently have security vulnerabilities. Only 20% pass basic security criteria. This platform is the missing hardened reference implementation.

## What This Is

Three integrated security layers that work together:

**Layer 1 — Hardened Nginx Gateway**
TLS 1.3 termination, mTLS client certificate enforcement for AI agents, per-endpoint rate limiting, WAF (ModSecurity + OWASP CRS) with MCP JSON-RPC custom rules, and structured JSON access logs.

**Layer 2 — MCP Security Proxy (FastAPI)**
Intercepts all MCP JSON-RPC calls. Enforces identity (mTLS or API key). Runs LLM-assisted Tool Manifest Auditing (Ollama), generates CycloneDX SBOMs per tool, detects anomalous invocation sequences, and evaluates OPA/Rego policies for every tool call.

**Layer 3 — Observability Stack**
Compliance-grade audit logging (SHA-256 per-event, credential auto-redaction), Loki + Grafana dashboards, Alertmanager alerts, MinIO WORM log archival (90-day Object Lock retention), and daily automated compliance checks across 10 PII/credential pattern categories.

## Differentiators vs. Competing Tools

| Feature | This Platform | Lilith-zero | MCP Spine | Burrow | Vectimus |
|---------|:---:|:---:|:---:|:---:|:---:|
| Full 3-layer stack | Y | N | N | N | N |
| SBOM generation (CycloneDX) | Y | N | N | N | N |
| LLM-assisted tool risk scoring | Y | N | N | N | N |
| OPA/Rego policy engine | Y | N | N | N | Y (Cedar) |
| WORM compliance logging | Y | N | N | N | N |
| Anomaly detection | Y | N | N | Y | N |

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
