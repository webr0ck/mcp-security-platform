# ADR-001: Language and Framework Choices

Status: Accepted
Date: 2026-04-21
Authors: System Architect
Deciders: Core team

---

## Context

The MCP Security Platform requires decisions on the programming language, web framework, policy engine, observability stack, and local AI inference runtime. These choices must satisfy:

1. Strong async I/O for high-concurrency proxy workloads
2. First-class integration with LLM inference (Ollama) for Tool Manifest Auditing
3. Policy evaluation that is decoupled from application code and version-controlled as data
4. Observability tooling with WORM-compatible log retention for compliance
5. A single `docker compose up` deployability requirement
6. Open-source with permissive licenses (MIT/Apache-2.0)

The main competing tools in the April 2026 landscape — Lilith-zero (Rust), MCP Spine, Burrow, mcp-sec-audit, Vectimus — are each single-concern tools. This platform's differentiator is full-stack integration and the SBOM + LLM-scored audit layer.

---

## Decision 1: Python 3.12 + FastAPI for the Security Proxy

**Chosen:** Python 3.12 with FastAPI (Pydantic v2)

**Alternatives considered:**

| Option | Pros | Cons |
|--------|------|------|
| Rust (Actix-web / Axum) | Extremely fast, memory safe | Slower development velocity; Ollama integration requires HTTP client; no Pydantic-equivalent for schema validation at this maturity |
| Go (Fiber / Gin) | Fast, strong stdlib | Weaker ML/AI library ecosystem; Pydantic v2 validation is uniquely suited to MCP schema validation |
| Node.js (Fastify) | Large ecosystem | GIL-free advantage lost; Python ML ecosystem not available |
| Python 3.12 + FastAPI | Async-native, Pydantic v2 (Rust-based core), mature LLM libraries, excellent OpenAPI auto-generation | Slower than Rust/Go for CPU-bound workloads |

**Rationale:** The proxy is I/O bound (waiting on OPA, Ollama, PostgreSQL, upstream MCP servers). Python 3.12's asyncio + FastAPI handles this efficiently. Pydantic v2 (with its Rust core) gives us compile-time-like schema validation for MCP JSON-RPC payloads. The Ollama Python library and the CycloneDX Python library (`cyclonedx-python-lib`) are mature. This dramatically reduces SBOM generation complexity compared to implementing in Go or Rust.

**Risk mitigation:** CPU-bound operations (LLM scoring, SBOM signing) are delegated to Ollama and background tasks respectively. The proxy core path (auth + OPA check + forward) is I/O bound and performs well under Python asyncio.

---

## Decision 2: Nginx 1.25 with ModSecurity v3 for the Gateway

**Chosen:** Nginx 1.25 with ModSecurity v3 + OWASP Core Rule Set (CRS)

**Alternatives considered:**

| Option | Pros | Cons |
|--------|------|------|
| Envoy | Advanced L7 features, WASM filters | Higher complexity; ModSecurity integration experimental |
| Caddy | Auto-TLS, simple config | No ModSecurity support; WAF requires custom plugins |
| HAProxy | Excellent L4 performance | Limited L7 WAF options |
| Nginx + ModSecurity v3 | Production-proven, active CRS community, JSON-RPC custom rules achievable | ModSecurity v3 Nginx connector requires compilation |

**Rationale:** Nginx is the most operationally familiar ingress for security deployments. ModSecurity v3 with OWASP CRS provides immediately applicable WAF rules, with the ability to add custom rules for MCP JSON-RPC payload patterns (the `REQUEST-905-COMMON-EXCEPTIONS.conf` mechanism). The structured JSON access log format integrates natively with Promtail without a log parser plugin.

---

## Decision 3: step-ca (Smallstep) for the Internal CA

**Chosen:** Smallstep step-ca

**Alternatives considered:**

| Option | Pros | Cons |
|--------|------|------|
| OpenSSL (manual scripts) | No dependency | Manual renewal; no OCSP; error-prone |
| Vault PKI Secrets Engine | Excellent OCSP/CRL | Requires full Vault deployment |
| cert-manager (K8s) | Cloud-native | Kubernetes dependency; not available for Docker Compose |
| step-ca | ACME-compatible, short-lived cert automation, Docker-native | Less enterprise-familiar than Vault |

**Rationale:** step-ca runs as a single container, supports ACME and JWK provisioners, and automates 24-hour cert rotation for AI agent clients. This eliminates the operational burden of long-lived cert management. It is a natural fit for the Docker Compose deployment model and is Kubernetes-compatible via cert-manager integration in production.

---

## Decision 4: OPA (Open Policy Agent) as a Sidecar

**Chosen:** OPA 0.63+ as a sidecar container, evaluated over HTTP

**Alternatives considered:**

| Option | Pros | Cons |
|--------|------|------|
| Casbin (embedded) | Simple, no network hop | Policy-as-code library only; Rego ecosystem much richer; library coupling |
| Cedar (AWS) | Strongly typed, used by Vectimus | Smaller community; Python SDK less mature |
| OPA embedded (rego Python lib) | No network hop | Library coupling to Python runtime; policy updates require proxy restart |
| OPA sidecar | Clean separation; policy reloads without proxy restart; rich Rego ecosystem; opa-bundle signing | Extra network hop (sub-millisecond on Docker network); one more container |

**Rationale:** The sidecar pattern allows OPA Rego policies to be updated, signed, and deployed independently of the proxy application. This is critical for security operations: a policy change must not require a proxy deployment. OPA's bundle signing feature (`POLICY_SIGNING_KEY`) satisfies the threat model requirement that tampered policies are rejected. The network overhead is negligible on a Docker bridge network.

---

## Decision 5: Ollama for Local LLM Risk Scoring

**Chosen:** Ollama with locally hosted model (default: `llama3.2`)

**Alternatives considered:**

| Option | Pros | Cons |
|--------|------|------|
| OpenAI API | High quality, no GPU needed | External API dependency; data leaves platform; cost; unavailable air-gapped |
| Hugging Face Transformers (direct) | Full control | High memory footprint; inference server management burden |
| Anthropic Claude API | Excellent security analysis | Same external API concerns; not open-source-friendly |
| Ollama | Local/air-gapped, swappable models, Docker-native, REST API | Requires GPU or tolerates slow CPU inference; model quality below GPT-4 class |

**Rationale:** The platform's security context requires that tool schemas are never sent to external services. Ollama's local inference is a hard architectural requirement, not a cost decision. The risk scoring is advisory (influences UI risk level; does not unilaterally block tools), so model quality is a bounded concern. Models are swappable without code changes via `OLLAMA_MODEL` env var.

---

## Decision 6: Loki + Promtail + Grafana for Observability

**Chosen:** Grafana Loki + Promtail + Grafana OSS + Alertmanager

**Alternatives considered:**

| Option | Pros | Cons |
|--------|------|------|
| ELK Stack (Elasticsearch + Logstash + Kibana) | Powerful full-text search | High resource requirements; complex; SSPL license concerns |
| Splunk | Enterprise-grade | Commercial; not open-source |
| OpenTelemetry + Jaeger | Full distributed tracing | Primarily traces, not logs; more complex for compliance log patterns |
| Loki + Promtail + Grafana | Lightweight; Grafana native; LogQL adequate for audit queries; Docker-native | Less powerful full-text search than Elasticsearch |

**Rationale:** The Loki stack runs in under 1GB RAM, integrates natively with Grafana (one UI for logs + dashboards + alerts), and supports label-based log routing that maps naturally to MCP audit event fields (`client_id`, `tool_name`, `outcome`). Alertmanager integrates directly. For WORM compliance archival, MinIO Object Lock handles the retention requirement that Loki itself does not provide.

---

## Decision 7: PostgreSQL 16 as the Application Database

**Chosen:** PostgreSQL 16

**Alternatives considered:**

| Option | Pros | Cons |
|--------|------|------|
| SQLite | Zero-config | Not production-suitable for concurrent writers; no JSONB |
| MySQL 8 | Widely familiar | JSONB support weaker than PostgreSQL; row-level locking model less suitable |
| MongoDB | Flexible schema | No strong ACID guarantees needed for write-heavy audit index |
| PostgreSQL 16 | ACID, UUID PKs, JSONB, row-level security, mature Python drivers | Slightly more complex to operate than SQLite |

**Rationale:** PostgreSQL's JSONB type is used for `tool_registry.schema`, `tool_registry.metadata`, and `audit_events.parameters_hash_map`. UUID primary keys provide globally unique identifiers without coordination. pg_notify can be used for real-time anomaly baseline updates. Row-level security (RLS) is available as a future defense-in-depth layer.

---

## Decision 8: CycloneDX 1.5 as Primary SBOM Format

**Chosen:** CycloneDX 1.5 (primary), SPDX 2.3 (secondary, generated on demand)

**Rationale:** CycloneDX 1.5 includes first-class support for machine-readable vulnerability data and service components, making it better suited to the MCP tool-as-component model than SPDX. SPDX 2.3 is offered as a secondary format for organizations with SPDX-native tooling.

---

## Consequences

- The proxy must be Python 3.12+. No mixing of Python versions across the observability library and proxy.
- OPA Rego policies are the canonical authorization layer; no inline permission checks in application code beyond the RBAC middleware gateway check.
- Model swappability via `OLLAMA_MODEL` env var is a first-class requirement; the auditor service must not hardcode model names.
- All secrets flow via environment variables; no Vault SDK dependency in v1 (simplifies local dev).
- ModSecurity custom rules for MCP JSON-RPC patterns must be maintained in `gateway/modsecurity/` as version-controlled `.conf` files.

---

*End of ADR-001*
