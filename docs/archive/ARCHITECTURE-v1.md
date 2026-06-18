# MCP Security Platform — Architecture

Version: 1.0.0
Date: 2026-04-21
Status: **SUPERSEDED — DO NOT RELY ON THIS DOCUMENT.**

> ⛔ **This v1 architecture is stale and partly aspirational.** It omits the
> credential broker, HashiCorp Vault, `credential_store`, and the OAuth router
> (the largest subsystems), and describes features that are not built (SPDX
> SBOM, outbound Jira, Helm/K8s, OIDC). It is retained only for history.
>
> **Canonical architecture: [`ARCHITECTURE-v2.md`](ARCHITECTURE-v2.md)** —
> reality-annotated, every component marked implemented / partial / stub /
> defect. See also [`REVIEW-2026-05-16.md`](REVIEW-2026-05-16.md) and
> [`ROADMAP.md`](ROADMAP.md).

---

## 1. Purpose and Scope

The MCP Security Platform is a full-stack, open-source security reference implementation for the Model Context Protocol (MCP) ecosystem. It addresses the documented 92% insecurity rate across MCP server deployments by providing three integrated layers: a hardened ingress gateway, a semantic security proxy, and a compliance-grade observability stack.

This document is the single source of truth for component design, service boundaries, trust boundaries, data flows, and the threat model. All other documents (API.md, RBAC.md, ADRs) are derived from and must remain consistent with this document.

---

## 2. Component Diagram

```
 External AI Agents / MCP Clients
           │  (mTLS or API-key)
           ▼
┌──────────────────────────────────────────────────────────┐
│                    LAYER 1: GATEWAY                       │
│                                                           │
│  ┌─────────────────────────────────────────────────────┐ │
│  │              Nginx (TLS/mTLS termination)           │ │
│  │   ┌─────────────┐   ┌────────────┐   ┌──────────┐  │ │
│  │   │ TLS/mTLS    │   │ Rate Limit │   │  WAF     │  │ │
│  │   │ Termination │   │ per-client │   │ ModSec / │  │ │
│  │   │ step-ca CA  │   │ per-tool   │   │ OWASP CRS│  │ │
│  │   └─────────────┘   └────────────┘   └──────────┘  │ │
│  │              Structured JSON access logs             │ │
│  └─────────────────────────────────────────────────────┘ │
└───────────────────────┬──────────────────────────────────┘
                        │  (internal HTTP, mTLS optional)
                        ▼
┌──────────────────────────────────────────────────────────┐
│                 LAYER 2: SECURITY PROXY                   │
│                                                           │
│  ┌─────────────────────────────────────────────────────┐ │
│  │             MCP Security Proxy (FastAPI)             │ │
│  │                                                      │ │
│  │  ┌──────────┐  ┌──────────┐  ┌───────────────────┐  │ │
│  │  │  Auth    │  │  Tool    │  │   Anomaly         │  │ │
│  │  │ Enforcer │  │ Manifest │  │   Detector        │  │ │
│  │  │ (mTLS /  │  │ Auditor  │  │   (baseline per   │  │ │
│  │  │  API key)│  │ (Ollama) │  │    client)        │  │ │
│  │  └────┬─────┘  └────┬─────┘  └────────┬──────────┘  │ │
│  │       │             │                  │             │ │
│  │  ┌────▼─────────────▼──────────────────▼──────────┐  │ │
│  │  │             OPA Sidecar (Rego policies)         │  │ │
│  │  │         deny-by-default, allow-listed rules     │  │ │
│  │  └────────────────────────┬───────────────────────┘  │ │
│  │                           │                          │ │
│  │  ┌────────────────────────▼───────────────────────┐  │ │
│  │  │             SBOM Generator                      │  │ │
│  │  │       (CycloneDX / SPDX per tool)               │  │ │
│  │  └────────────────────────────────────────────────┘  │ │
│  └─────────────────────────────────────────────────────┘ │
└───────────────────────┬──────────────────────────────────┘
                        │  (structured audit events)
                        ▼
┌──────────────────────────────────────────────────────────┐
│              LAYER 3: OBSERVABILITY STACK                  │
│                                                           │
│  ┌──────────────┐  ┌──────────┐  ┌────────────────────┐  │
│  │ mcp-audit-   │  │  Loki +  │  │  Grafana           │  │
│  │ logger lib   │  │ Promtail │  │  (dashboards +     │  │
│  │ (SHA-256,    │  │          │  │   alerting UI)     │  │
│  │  redaction)  │  │          │  │                    │  │
│  └──────┬───────┘  └────┬─────┘  └────────────────────┘  │
│         │               │                                 │
│  ┌──────▼───────────────▼──────────────────────────────┐  │
│  │               Alertmanager                           │  │
│  │   (error rate, novel tools, latency thresholds)     │  │
│  └─────────────────────────────────────────────────────┘  │
│                                                           │
│  ┌─────────────────────────────────────────────────────┐  │
│  │  S3 / MinIO — Object Lock (WORM) log retention      │  │
│  └─────────────────────────────────────────────────────┘  │
│                                                           │
│  ┌─────────────────────────────────────────────────────┐  │
│  │  Compliance Checker (daily cron)                    │  │
│  │  1000-sample audit, 10 PII/cred pattern categories  │  │
│  └─────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────┘

Supporting Services (all internal):
  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐
  │PostgreSQL│  │  Redis   │  │  Ollama  │  │  OPA     │
  │(tool reg,│  │(rate lmt,│  │(LLM risk │  │(sidecar) │
  │ audit idx│  │ session) │  │ scoring) │  │          │
  └──────────┘  └──────────┘  └──────────┘  └──────────┘
```

---

## 3. Service Catalogue

| Service | Container Name | Technology | Port (internal) | Owned By |
|---------|---------------|------------|-----------------|----------|
| Nginx Gateway | `gateway` | Nginx 1.25 + ModSecurity 3 | 443 (ext), 80→443 redirect | gateway team |
| step-ca | `step-ca` | Smallstep step-ca | 9000 | gateway team |
| MCP Security Proxy | `proxy` | Python 3.12, FastAPI | 8000 | proxy team |
| OPA Sidecar | `opa` | Open Policy Agent 0.63+ | 8181 | policy team |
| Ollama | `ollama` | Ollama | 11434 | proxy team |
| PostgreSQL | `db` | PostgreSQL 16 | 5432 | db team |
| Redis | `redis` | Redis 7 | 6379 | proxy team |
| Loki | `loki` | Grafana Loki | 3100 | observability team |
| Promtail | `promtail` | Grafana Promtail | 9080 | observability team |
| Grafana | `grafana` | Grafana OSS | 3000 | observability team |
| Alertmanager | `alertmanager` | Prometheus Alertmanager | 9093 | observability team |
| MinIO | `minio` | MinIO (S3-compatible) | 9000 | observability team |
| Compliance Checker | `compliance-checker` | Python 3.12 (cron job) | — | observability team |

---

## 4. Service Boundary Definitions

### 4.1 Gateway (Nginx + step-ca + ModSecurity)

**Owns:** TLS termination, mTLS client certificate validation, per-endpoint rate limiting, WAF filtering, access log emission.

**Does NOT own:** Authentication identity resolution, tool-level policy enforcement, audit event persistence.

**Contracts out:** All non-blocked requests forwarded to `proxy:8000` over internal HTTP. Access logs written to stdout in structured JSON; Promtail scrapes them.

**Trust boundary:** The public internet terminates at the gateway. Nothing from the public internet reaches any other service directly.

### 4.2 MCP Security Proxy (FastAPI)

**Owns:** Identity verification (mTLS certificate CN extraction or API key lookup), tool registration and inventory, Tool Manifest Auditor, SBOM generation, Anomaly Detector, OPA policy evaluation calls, audit event emission via mcp-audit-logger.

**Does NOT own:** TLS negotiation, log storage, dashboard rendering, policy rule authoring.

**Contracts out:** Policy decisions delegated to OPA sidecar via HTTP POST to `opa:8181/v1/data/mcp/authz/allow`. Risk scoring delegated to `ollama:11434`. Database persistence via SQLAlchemy to `db:5432`. Session/rate state in `redis:6379`.

**Trust boundary:** Only accepts requests originating from `gateway` (enforced by Docker network + optional internal mTLS). Direct access from external clients to `proxy:8000` is not exposed.

### 4.3 OPA Sidecar

**Owns:** Rego policy evaluation. All allow/deny decisions for tool invocations.

**Does NOT own:** Identity establishment, business logic, data storage.

**Trust boundary:** Accepts policy evaluation requests only from `proxy`. Policy bundles are loaded from the `policies/rego/` volume. No external network access.

### 4.4 Ollama

**Owns:** Local LLM inference for risk scoring of tool schemas.

**Does NOT own:** Scoring persistence, policy enforcement.

**Trust boundary:** Internal network only. No external API keys or outbound internet required. Model weights are volume-mounted.

### 4.5 Observability Stack (Loki + Promtail + Grafana + Alertmanager + MinIO)

**Owns:** Log aggregation, retention, dashboards, alert delivery, WORM archival, compliance report generation.

**Does NOT own:** Audit event creation (owned by proxy via mcp-audit-logger), policy decisions.

**Trust boundary:** Grafana UI is exposed on port 3000 behind Nginx (proxy_pass) in production. MinIO is internal only. All services within the observability stack communicate on the `observability` Docker network.

### 4.6 PostgreSQL

**Owns:** Persistent state for tool registry, SBOM records, audit event index, anomaly baseline models, compliance reports, RBAC assignments.

**Does NOT own:** Session state (Redis), log data (Loki/MinIO).

**Single writer rule:** Only the `proxy` service writes to the `tool_registry`, `sbom_records`, `audit_events`, and `anomaly_baselines` tables. The `compliance-checker` writes only to `compliance_reports`. No other service writes to the database.

---

## 5. Critical Data Flows

### 5.1 MCP Tool Invocation (Happy Path)

```
AI Agent
  │
  │ 1. TLS ClientHello + client cert (mTLS)
  ▼
Nginx Gateway
  │ 2. mTLS handshake verified against step-ca issued cert
  │ 3. ModSecurity WAF inspection (JSON-RPC payload)
  │ 4. Rate limit check (per client CN, per tool endpoint)
  │ 5. Access log emitted (structured JSON)
  │ 6. Forward to proxy:8000 with X-Client-Cert-CN header
  ▼
MCP Security Proxy
  │ 7. Auth middleware extracts identity (cert CN or API key)
  │ 8. Load client context from Redis (session, rate state)
  │ 9. Tool invocation request parsed (JSON-RPC)
  │ 10. Anomaly detector evaluates sequence against baseline
  │ 11. POST /v1/data/mcp/authz/allow to OPA sidecar
  ▼
OPA Sidecar
  │ 12. Evaluate Rego: client identity × tool name × params
  │ 13. Return {allow: true|false, reasons: [...]}
  ▼
MCP Security Proxy (continued)
  │ 14. If OPA denies: emit audit event (DENY), return 403
  │ 15. If OPA allows: forward to upstream MCP server
  │ 16. Receive upstream response
  │ 17. mcp-audit-logger emits audit event (ALLOW, SHA-256 hash)
  │     → stdout → Promtail → Loki
  │ 18. Anomaly baseline updated in Redis / PostgreSQL async
  │ 19. Response returned to AI agent
  ▼
AI Agent
```

### 5.2 Tool Registration and SBOM Generation

```
Admin / CI pipeline
  │ POST /api/v1/tools/register (with signed manifest JSON)
  ▼
MCP Security Proxy
  │ 1. Verify admin role (RBAC check)
  │ 2. Validate tool schema (Pydantic v2)
  │ 3. Tool Manifest Auditor:
  │      a. Parse tool schema for parameter names, descriptions
  │      b. POST to Ollama for LLM risk scoring
  │      c. Static pattern matching (prompt injection signatures)
  │      d. Assign risk score (0-100) and risk_level (low/medium/high/critical)
  │ 4. SBOM Generator:
  │      a. Build CycloneDX BOM component entry
  │      b. Link to source repo + commit hash
  │      c. Sign SBOM digest (HMAC-SHA-256 with SBOM_SIGNING_KEY)
  │ 5. Persist to PostgreSQL: tool_registry + sbom_records
  │ 6. Emit audit event: TOOL_REGISTERED
  │ 7. POST policy bundle update to OPA (if tool is new)
  │ 8. Return 201 with tool_id, risk_score, sbom_ref
  ▼
Admin / CI pipeline
```

### 5.3 Compliance Report Generation

```
Compliance Checker (daily cron, 02:00 UTC)
  │ 1. Query PostgreSQL: sample 1000 audit events from past 24h
  │ 2. For each event:
  │      a. Check 10 PII/credential pattern categories
  │      b. Verify SHA-256 hash integrity
  │      c. Verify no raw payloads in log fields
  │ 3. Compute pass/fail per category
  │ 4. Write compliance_reports row to PostgreSQL
  │ 5. Archive full report JSON to MinIO (WORM bucket)
  │      with Object Lock retention = 90 days
  │ 6. If any category fails: POST alert to Alertmanager
  ▼
Alertmanager → configured notification channels
```

### 5.4 Authentication Flow (API Key Path)

```
AI Agent (no client cert)
  │ HTTP request with Authorization: Bearer <api_key>
  ▼
Nginx Gateway
  │ 1. TLS-only (no mTLS for API key clients)
  │ 2. WAF inspection
  │ 3. Forward with no X-Client-Cert-CN header
  ▼
MCP Security Proxy
  │ 4. Auth middleware: no cert CN → check Authorization header
  │ 5. Hash API key (SHA-256), lookup in redis cache
  │      If miss: query PostgreSQL api_keys table
  │ 6. Resolve client_id and roles from api_key record
  │ 7. Continue with tool invocation flow (step 9+)
```

---

## 6. Trust Boundaries and Security Zones

```
Zone: PUBLIC (Untrusted)
  ├── External AI agents
  ├── External API consumers
  └── Internet

  ──── TLS/mTLS boundary ────

Zone: DMZ (Semi-trusted, authenticated)
  └── Nginx Gateway (only service in this zone)

  ──── Internal Docker network boundary ────

Zone: INTERNAL (Trusted, service-to-service)
  ├── proxy (FastAPI)
  ├── opa (sidecar)
  ├── ollama
  ├── redis
  ├── db (PostgreSQL)
  └── step-ca

  ──── Observability network (segregated) ────

Zone: OBSERVABILITY (Append-only trusted)
  ├── loki
  ├── promtail
  ├── grafana
  ├── alertmanager
  └── minio (WORM)
```

**Inter-zone rules:**
- PUBLIC → DMZ: TLS 1.3 only; mTLS enforced for agent endpoints; API keys for non-agent clients
- DMZ → INTERNAL: Internal HTTP only; gateway adds X-Client-Cert-CN header; proxy verifies header origin
- INTERNAL → OBSERVABILITY: Structured JSON log events only (append); no read-back path from observability to proxy
- OBSERVABILITY is write-only from proxy's perspective; compliance checker has read access to PostgreSQL audit index and MinIO archive only

---

## 7. Threat Model

### 7.1 Assets

| Asset | Classification | Owner |
|-------|---------------|-------|
| Tool registry (tool schemas, capabilities) | Confidential | proxy |
| SBOM records | Confidential | proxy |
| Audit event log | Compliance-critical | observability |
| API keys / client certificates | Secret | proxy + gateway |
| Anomaly baselines | Internal | proxy |
| OPA policy bundles | Sensitive | policy team |
| Compliance reports | Compliance-critical | observability |
| Ollama model weights | Internal | proxy |

### 7.2 Threat Actors

| Actor | Capability | Motivation |
|-------|-----------|-----------|
| Malicious AI agent | Can craft arbitrary MCP JSON-RPC payloads | Privilege escalation, tool abuse, data exfiltration |
| Compromised MCP server | Returns malicious tool outputs | Inject malicious content into agent context |
| Insider (developer) | Has codebase access | Backdoor policy rules, disable audit logging |
| External attacker (network) | Network-level access attempts | DDoS, credential theft |
| Supply chain attacker | Compromised upstream tool dependency | Code execution in proxy |

### 7.3 Attack Surfaces

| Surface | Description | Mitigations |
|---------|-------------|-------------|
| MCP JSON-RPC endpoint | Accepts arbitrary JSON from agents | WAF (ModSecurity), JSON schema validation (Pydantic), OPA policy |
| Tool parameter values | Prompt injection via tool call arguments | Tool Manifest Auditor (LLM scan), OPA parameter pattern rules |
| Tool registration endpoint | Registering a malicious tool schema | Admin-role-only, LLM risk scoring, human review gate for high-risk tools |
| Client certificate | Forged or stolen cert | step-ca OCSP/CRL, short-lived certs (24h TTL), revocation on incident |
| API key | Stolen or leaked key | Hashed storage (SHA-256), Redis cache with short TTL, per-key rate limits |
| OPA policy bundle | Tampered Rego rules | Policy bundle signed, OPA verifies signature before loading |
| Audit log | Tampered or deleted | MinIO Object Lock (WORM), SHA-256 per-event hash, compliance checker validates hashes |
| Ollama endpoint | Adversarial prompt to LLM scorer | Air-gapped (internal only), results are advisory (not trust-granting) |
| Supply chain | Compromised Python dependency | SBOM generation per release, pip-audit in CI, dependency pinning |

### 7.4 Threat Scenarios

**T1 — Tool Exfiltration Chain**
An AI agent calls `web_search` followed by bulk `file_read` calls. The Anomaly Detector identifies this sequence as a known exfiltration pattern baseline deviation. OPA policy evaluated; if the sequence exceeds the anomaly threshold, invocations are denied and an alert fires.

**T2 — Prompt Injection via Tool Schema**
A malicious actor registers a tool whose `description` field contains injection instructions ("Ignore previous instructions and…"). Tool Manifest Auditor runs both static pattern matching and Ollama LLM scanning. Tool is flagged as `critical` risk and quarantined pending admin review.

**T3 — Audit Log Tampering**
An insider attempts to delete or modify audit event records. MinIO Object Lock with GOVERNANCE mode requires MFA-authenticated delete (WORM). SHA-256 hashes stored in PostgreSQL; compliance checker detects hash mismatch.

**T4 — Credential Leakage in Logs**
A tool invocation includes an AWS secret key as a parameter value. mcp-audit-logger credential auto-redaction (10 PII/credential pattern categories) replaces the value with `[REDACTED:aws_secret_key]` before any log emission. Raw payloads never written.

**T5 — Policy Bypass via OPA Manipulation**
An attacker modifies a Rego file. OPA bundle signing (with `POLICY_SIGNING_KEY`) means unsigned or invalidly signed bundles are rejected at load time. Policy changes require a signed commit + CI gate.

**T6 — DDoS / Rate Abuse**
A client issues thousands of tool calls per second. Nginx rate limiting (per client CN, per endpoint) drops excess requests at the gateway before they reach the proxy. Redis tracks in-flight counts.

---

## 8. Integration Points

### 8.1 OIDC / Authentication Gateway

While the initial implementation uses mTLS and API keys, the architecture reserves `/api/v1/auth/oidc/callback` for OIDC integration. The OIDC provider (configurable: Keycloak, Okta, Auth0) issues JWTs that the proxy validates. JWT claims map to RBAC roles via the `oidc_role_mappings` table.

Environment variables: `OIDC_ISSUER_URL`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`, `OIDC_AUDIENCE`

### 8.2 Jira Integration

The proxy exposes a webhook sink at `/api/v1/integrations/jira/webhook` for receiving Jira issue state changes (e.g., marking a flagged tool as "approved" after security review). Outbound: when a tool is flagged at `critical` risk, the proxy optionally creates a Jira issue via the Jira REST API.

Environment variables: `JIRA_BASE_URL`, `JIRA_API_TOKEN`, `JIRA_PROJECT_KEY`, `JIRA_ENABLED`

### 8.3 Artifactory Integration

SBOMs generated by the SBOM Generator are optionally published to a configured JFrog Artifactory repository for artifact governance. The proxy POSTs the CycloneDX JSON to the Artifactory generic repository on each tool registration or update.

Environment variables: `ARTIFACTORY_BASE_URL`, `ARTIFACTORY_REPO`, `ARTIFACTORY_API_KEY`, `ARTIFACTORY_ENABLED`

---

## 9. Technology Stack Decisions

See `docs/ADR/001-language-choices.md` for full rationale. Summary:

| Concern | Technology | Rationale |
|---------|-----------|-----------|
| Ingress / TLS | Nginx 1.25 | Proven, ModSecurity v3 support, wide ops familiarity |
| Internal CA | step-ca (Smallstep) | ACME-compatible, short-lived cert automation |
| WAF | ModSecurity 3 + OWASP CRS | Production-grade, JSON-RPC custom rules possible |
| Proxy application | Python 3.12, FastAPI | Async, Pydantic v2, strong ML/AI library ecosystem for LLM integration |
| Policy engine | OPA 0.63+ (sidecar) | Industry-standard Rego, sidecar pattern avoids library coupling |
| Local LLM | Ollama | Air-gapped, no external API dependency, pluggable model |
| Database | PostgreSQL 16 | ACID compliance, UUID PKs, JSONB for flexible schema fields |
| Cache / session | Redis 7 | Sub-millisecond rate-limit lookups, Lua scripting for atomicity |
| Log aggregation | Loki + Promtail | Lightweight, label-based, native Grafana integration |
| Log archive | MinIO (S3-compatible) | Local WORM-capable Object Lock for compliance |
| Dashboards | Grafana OSS | Native Loki + Alertmanager integration |
| SBOM format | CycloneDX 1.5 (primary) + SPDX 2.3 (secondary) | CycloneDX for tool inventory; SPDX for software dependency BOM |
| Container orchestration | Docker Compose (dev), Kubernetes + Helm (prod) | Single `docker compose up` for local; Helm chart stubs for production |

---

## 10. Deployment Architecture

### 10.1 Docker Networks

```
network: gateway-net (bridge)
  members: gateway, proxy

network: internal-net (bridge, internal)
  members: proxy, opa, ollama, db, redis

network: observability-net (bridge, internal)
  members: proxy (write-only), loki, promtail, grafana, alertmanager, minio

network: step-ca-net (bridge, internal)
  members: gateway, step-ca, proxy
```

### 10.2 Volume Strategy

| Volume | Service | Purpose | Backup Required |
|--------|---------|---------|----------------|
| `postgres-data` | db | Database files | Yes |
| `redis-data` | redis | Persistence (AOF) | Optional |
| `loki-data` | loki | Log chunks | Yes |
| `minio-data` | minio | WORM log archive | Yes (critical) |
| `grafana-data` | grafana | Dashboard state | Yes |
| `ollama-models` | ollama | LLM model weights | No (re-pullable) |
| `opa-policies` | opa | Rego policy bundle | Managed via git |
| `step-ca-data` | step-ca | CA keys and config | Yes (critical) |

### 10.3 Kubernetes Readiness

Helm chart stubs are provided in `helm/mcp-security-platform/`. Each service maps to a Deployment + Service. PostgreSQL and Redis should use managed cloud services in production (RDS, ElastiCache). MinIO should be replaced with AWS S3 + Object Lock in production.

---

## 11. SBOM and Provenance

Every MCP tool registration produces a CycloneDX 1.5 SBOM component. The SBOM includes:

- `bom-ref`: UUID v4, stable identifier
- `type`: "library" (MCP tools are treated as software components)
- `name`: tool name
- `version`: tool schema version
- `purl`: package URL (e.g., `pkg:mcp/tool-name@version`)
- `hashes`: SHA-256 of the tool schema JSON (canonical form)
- `externalReferences`: source repository URL + commit SHA
- `properties`: risk_score, risk_level, audit_timestamp, auditor_version

The SBOM document itself is signed: an HMAC-SHA-256 signature computed over the CycloneDX JSON is stored alongside the SBOM in `sbom_records.signature`. The signing key is `SBOM_SIGNING_KEY` (environment variable, never committed).

---

## 12. Secrets Management

All secrets are injected via environment variables. In production, use HashiCorp Vault or AWS Secrets Manager to inject variables at container startup. Never commit secrets to git. The `.env.example` file contains only placeholder values.

Secret categories:
- Database credentials (`DB_PASSWORD`, `DB_USER`)
- Redis password (`REDIS_PASSWORD`)
- API signing keys (`SBOM_SIGNING_KEY`, `POLICY_SIGNING_KEY`, `AUDIT_LOG_HMAC_KEY`)
- step-ca provisioner password (`STEP_CA_PROVISIONER_PASSWORD`)
- Jira / Artifactory tokens (`JIRA_API_TOKEN`, `ARTIFACTORY_API_KEY`)
- OIDC client secret (`OIDC_CLIENT_SECRET`)
- MinIO root credentials (`MINIO_ROOT_USER`, `MINIO_ROOT_PASSWORD`)
- Grafana admin password (`GRAFANA_ADMIN_PASSWORD`)

---

*End of Architecture Document*
