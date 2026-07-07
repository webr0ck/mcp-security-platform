# Audit, Logging & Observability Specification

**Spec ID:** SPEC-04 · **Status:** matches code at HEAD (`4dfa7b5`)

This document specifies, normatively, how the MCP Security Platform records,
protects, and ships audit and observability data. It is written so a
re-implementer in any language can reproduce the guarantees without reading the
Python. Requirement levels use RFC 2119 keywords (**MUST**, **SHOULD**, **MAY**);
each requirement carries a *Reference implementation:* pointer to code at HEAD.
Controls not enforced today are marked **(roadmap)**; the README
[Enforced-vs-Roadmap table](../../README.md#enforced-today-vs-roadmap) remains
authoritative for per-control status. Tamper-evidence claims are stated with the
README's candor: there is **no hash-chain/Merkle in the live path**; the
transparency log is an explicit **stub**; MinIO Object-Lock is **GOVERNANCE**,
which is **not WORM**.

---

## 1. Synchronous audit before response (INV-001)

The core invariant: **there is no path where a tool executes — or where
authentication is rejected — without a durable audit record written first.**

- Every tool invocation (REST `/api/v1/tools/{id}/invoke` and `/mcp` `tools/call`)
  and every auth-layer rejection (401/403) **MUST** emit a synchronous audit
  event **before** the response is returned. *Reference implementation:*
  `proxy/app/services/invocation.py::_emit_audit_event` (invocation path),
  `proxy/app/middleware/audit.py::AuditMiddleware.dispatch` (401/403 path).
- **Emission failure ⇒ HTTP 500.** A failure to persist the audit event
  (DB write error, logger error) **MUST** raise `AuditEmissionError`, which
  `AuditMiddleware` converts to a `500 AUDIT_EMISSION_FAILED`. The original
  401/403 is **not** returned when its audit emission fails — no audit record,
  no response. *Ref:* `invocation.py:1465-1502`, `audit.py:38-53,83-133`.
- **Every deny point on the invocation path audits before raising.** Quarantine,
  entitlement, taint-floor, credential-injection, SSRF/rebind, OPA deny, and
  response-filter denials each emit a synchronous deny/error event before the
  exception propagates. *Ref:* `invocation.py` Steps 1.2, 1.5, 1.6, 3, 3c, 3c-pre, 6a.
- **`/mcp` meta-tool audit is fail-closed (emit-or-500).** Built-in meta-tools
  (no `tool_registry` row) route through `_emit_audit_event` with `tool_id=None`
  (event type `INTERNAL_TOOL_INVOCATION`); an emission failure raises and becomes
  a 500. *Ref:* `invocation.py::emit_internal_tool_event:1510-1543`.
- **De-duplication:** when a route handler already emitted a tool-specific deny
  audit, it sets `request.state.invocation_audit_emitted=True` so the generic
  401/403 middleware audit does not double-record. *Ref:* `audit.py:103-104`.

---

## 2. Event content rules

*Reference implementation:* `observability/mcp-audit-logger/mcp_audit_logger/schema.py`,
`invocation.py::_emit_audit_event`.

- **Raw args are never persisted.** Tool arguments **MUST NOT** be stored; only a
  SHA-256 hash is recorded. The audit event records a `prompt_hash` /
  arg-hash, `outcome`, `latency_ms`, and an `opa_decision_id`. *Ref:* README
  Audit row; `invocation.py` `_emit_audit_event` args; ARCHITECTURE §7.
- **`audit_id` is returned to the caller.** The event id is echoed in the response
  `meta.audit_id` (and in error `data.audit_id`) so a caller can correlate.
  *Ref:* `invocation.py:1088-1089,1004-1027`.
- **Taint state is recorded on the ALLOW path, not just DENY (GAP-1, commit
  17f86e3).** The `tainted` field is written on allow/error audits as well, so a
  tainted-session allow of a low-floor sink is never silently unrecorded. It is
  **advisory enrichment** and deliberately **not** part of the integrity hash.
  *Ref:* `invocation.py:958-975`, `schema.py:112-119`.
- **"Who" enrichment (Task 1.2 / LOG-F04):** `source_ip`, `principal_type`
  (`human`/`agent`/`service`), `roles` (snapshot), and `session_jti` are recorded
  where resolved. *Ref:* `schema.py:82-110`, `invocation.py` `_emit_audit_event`.

---

## 3. Redaction (INV-002)

- **Structured audit-field redaction — 10 mandatory categories.** Before any log
  emission, every string field is scanned and matches replaced with
  `[REDACTED:<category>]`. The 10 categories (secrets + PII) are: `aws_access_key`,
  `aws_secret_key`, `github_token`, `private_key`, `url_password`, `jwt_token`,
  `db_connection_string`, `email_address` (GDPR), `ip_address`, `api_key`. This is
  a set of plain functions called explicitly from `logger.emit()`, unit-tested
  (positive + negative per category) and gated by `make security-check`.
  *Reference implementation:*
  `observability/mcp-audit-logger/mcp_audit_logger/redaction.py:20-49`;
  `tests/test_redaction.py`.
- **`RedactingFilter` on ALL logs.** Independently, a `logging.Filter`
  (`RedactingFilter`) is attached to the **root** and `app` loggers so incidental
  leakage in exceptions / httpx errors is scrubbed across the whole Loki-shipped
  surface (not just structured audit events). It applies 2 conservative patterns
  — a Bearer/token/api-key prefix pattern (`[REDACTED:token]`) and a JWT pattern
  (`[REDACTED:jwt]`) — mutates `record.msg`/`record.args`, and never drops a
  record. *Reference implementation:* `proxy/app/core/log_filter.py:33-82`,
  applied in `proxy/app/main.py:46-48`.
- The hash is computed over **pre-redaction** data so integrity verification is
  meaningful; the redacted form is what ships to logs. *Ref:* `hasher.py:5-6`,
  `logger.py:74-84`.

> **Discrepancy note:** an earlier brief cited "50+ patterns". The actual surface
> is **10 structured redaction categories** (INV-002) plus **2 root-logger
> `RedactingFilter` patterns** — not 50+. Both are unit-tested.

A re-implementation **MUST** keep the redaction category set identical between the
writer (`redaction.py`) and the compliance verifier (`checker.py` PII scan) — the
checker's comment mandates the two lists match exactly.

---

## 4. Tamper evidence (honest specification)

*Reference implementation:* `observability/mcp-audit-logger/mcp_audit_logger/hasher.py`,
`invocation.py::_compute_hmac_signature`, `observability/compliance-checker/checker.py`.

- **Per-event SHA-256.** Each event carries a SHA-256 over a single authoritative
  canonicalization, `canonical_audit_json()`, of a **fixed 9-field set**:
  `event_id, event_type, timestamp, client_id, tool_name, tool_id, outcome,
  request_id, platform_version`. Canonicalization is
  `json.dumps(sort_keys=True, separators=(",",":"), default=str)`. The writer
  and verifier **MUST** share this one canonicalizer (a past bug where the model's
  `_compute_hash` diverged from the emit path was fixed to delegate here).
  `outcome` is read from `original_outcome` when present so the error→deny DB
  remap still verifies. *Ref:* `hasher.py:34-108`, `schema.py:145-172`.
- **HMAC-signed in production.** Events are additionally HMAC-SHA-256 signed over
  the same canonical JSON. `AUDIT_LOG_HMAC_KEY` is a **required** settings field
  (no default) — production startup is blocked without it. Key rotation is
  supported via `AUDIT_LOG_HMAC_KEY__<KEY_ID>`. When present, the HMAC is the
  **primary** tamper check; absent, the verifier falls back to plain-hash compare.
  *Ref:* `invocation.py:1257-1295` (`hmac_signature`, `hmac_key_id` columns),
  `core/config.py:96`, `checker.py:215-255`.
- **NO hash-chain / Merkle in the live path.** `prev_hash` was deliberately
  deleted; sequence/Merkle tamper-evidence is out of scope for this build.
  Per-event HMAC is the mechanism. A re-implementation **MAY** add a chain but
  **MUST NOT** claim one exists today. *Ref:* `schema.py:121-125`.
- **Transparency log is an explicit stub.** `transparency_log.py` (cites RFC-0002
  §5.4) provides the client interface for Rekor/Sigstore inclusion proofs but
  performs **no** real Merkle-path verification. It is **fail-closed**: it returns
  `verified=False` (`log_url_not_configured` / `not_implemented`) whenever a proof
  cannot be confirmed. Real Rekor submission + verification is **(roadmap)**.
  *Ref:* `proxy/app/services/transparency_log.py`.
- **MinIO Object-Lock GOVERNANCE ≠ WORM.** The audit archive bucket uses
  Object-Lock in **GOVERNANCE** mode (default `MINIO_OBJECT_LOCK_MODE=GOVERNANCE`),
  which a privileged key can bypass — it is **not** true MFA-WORM. COMPLIANCE mode
  is the production-correct choice; GOVERNANCE is the accepted reference/lab
  posture and is stated as a gap. **INV-007:** the archive bucket carries a
  **90-day** retain-until and **no app/API/Make path may delete it**; the delete
  step after archival is gated off by default
  (`ENABLE_AUDIT_DELETE_AFTER_ARCHIVE=0`) and requires a DBA-granted privilege.
  *Ref:* `checker.py:84-92,258-304,482-501,552-567,818-834`.
- **Daily compliance sampler is advisory.** See §6.

---

## 5. Pipeline & observability

- **Log flow:** structured JSON events on **stdout → Promtail → Loki → Grafana**
  dashboards; **Alertmanager** for alerting. A re-implementation **MAY** swap Loki
  / Promtail / Grafana for any equivalent collector — these are **not** part of
  the security boundary. *Ref:* ARCHITECTURE §7; README Audit row.
- **Wazuh syslog emitter (secondary, best-effort).** After the primary audit
  (PostgreSQL) succeeds, a UDP syslog datagram (RFC 3164) **MAY** be sent to a
  Wazuh manager when `WAZUH_SYSLOG_HOST` is set. It carries `client_id,
  tool_name, outcome, anomaly_score, risk_level, request_id, principal_type,
  deny_reasons`, priority-mapped (`deny`→user.err 11, `score≥0.7`→user.warning
  12, else user.info 14), capped at 1024 bytes. It **MUST NOT** affect INV-001 —
  any failure is swallowed at WARNING. *Reference implementation:*
  `proxy/app/services/wazuh_syslog.py`, called from `invocation.py:1477-1493`.
  Decoded by `deployments/poc/wazuh/decoders/mcp-audit-decoder.xml`; taint-floor
  denies are matched by Wazuh rules 100001-100003
  (`deployments/poc/wazuh/rules/mcp-taint-floor.xml`).
- **Gateway access logs** are structured JSON (per client-CN / source-IP) at
  Layer 1. *Ref:* ARCHITECTURE §2.

---

## 6. Compliance checker (advisory)

*Reference implementation:* `observability/compliance-checker/checker.py`,
`entrypoint.py`.

- **Cadence:** a pure-Python cron scheduler (non-root UID 1001) runs
  `COMPLIANCE_CRON_SCHEDULE` (default `0 2 * * *` = 02:00 UTC daily), running both
  the compliance check and the archival job; it also runs once immediately on
  startup. *Ref:* `entrypoint.py:11-12,72-191`.
- **Sampling:** SELECT from `audit_events` over the last 24h, `ORDER BY RANDOM()
  LIMIT COMPLIANCE_SAMPLE_SIZE` (default **1000**). *Ref:* `checker.py:93,665-734`.
- **Integrity verification (`verify_hash_integrity`):** uses the shared
  `canonical_audit_json`. HMAC is the primary check when a signature is present
  (fail = mismatch); otherwise plain SHA-256 via `hmac.compare_digest`. Pre-V028
  rows (all canonical columns NULL) and the V028-V030 window are returned as
  `"legacy"` (unverifiable, **not** a mismatch). *Ref:* `checker.py:132-255`.
- **PII/credential scan:** each sampled event is serialized and checked against
  the **same 10 categories** as `redaction.py`. *Ref:* `checker.py:99-129`.
- **Advisory posture:** on failure the checker writes a `compliance_reports` row
  (status `fail`), POSTs a `severity: critical` Alertmanager alert, and returns
  exit code 1 for cron health — it **does not block or roll back** anything.
  Object-lock verification is non-fatal (warn + proceed). *Ref:*
  `checker.py:307-339,836-842`.
- **Archival (INV-007):** rows older than `AUDIT_ARCHIVAL_CUTOFF_DAYS` (default
  **90**) are archived to the MinIO `compliance-archive` bucket as JSONL with
  Object-Lock GOVERNANCE + 90-day retention, copied to `audit_events_archive`
  (`ON CONFLICT DO NOTHING`), and deleted from `audit_events` **only** when
  `ENABLE_AUDIT_DELETE_AFTER_ARCHIVE=1` and all rows archived. An
  `AUDIT_ARCHIVAL_RUN` event is emitted to stdout (the compliance role cannot
  INSERT audit rows — see §7). *Ref:* `checker.py:342-652`.

---

## 7. Database posture — append-only audit (INV-011)

*Reference implementation:* `infra/db/migrations/V003__db_roles.sql`,
`V009__role_assignments_grants.sql`.

- **Single-writer roles.** Only `proxy_app` may write registry/audit/credential
  tables; only `compliance_checker_app` may write `compliance_reports`. A
  re-implementation **MUST** enforce writer segregation at the database, not just
  in app code. *Ref:* `V003:41-136`.
- **`audit_events` is append-only.** `proxy_app` is granted **INSERT only**;
  `UPDATE`/`DELETE` are explicitly **REVOKED**. This is enforced by **two**
  complementary mechanisms: (1) role grants (no UPDATE/DELETE granted), and (2) a
  **BEFORE UPDATE OR DELETE trigger** (`fn_audit_events_immutability_guard`) that
  raises `insufficient_privilege` for **any** role — defense in depth against a
  future mis-grant. The same guard covers `audit_events_archive`. *Ref:*
  `V003:78-96,142-192`.
- **`role_assignments` is append-only** too: `proxy_app` gets `SELECT, INSERT`;
  `UPDATE`/`DELETE` revoked (grant = insert active row, revoke = insert tombstone;
  latest-event-wins at read time). *Ref:* `V009:22-26`; ARCHITECTURE §6.6.
- **No hard delete anywhere:** `REVOKE DELETE ON ALL TABLES` from both app roles;
  soft-delete via `deleted_at` is the only removal path. `compliance_checker_app`
  is SELECT-only on `audit_events` (so its archival events go to stdout, not a
  DB insert). *Ref:* `V003:96,116-139`.

---

## 8. Normative audit event schema

Every audit event **MUST** be an `AuditEvent` validated at construction; a missing
required field raises `AuditSchemaError` (no partial records — INV-001). The
detections layer (SPEC-03 §10) and the compliance checker depend on this contract,
so the field names and enum values are normative. *Reference implementation:*
`schema.py:21-198`.

### 8.1 Enums

- **`AuditOutcome`:** `allow`, `deny`, `error` (error = policy allowed but the
  upstream invocation could not complete — distinct from allow). On the DB write,
  `error` is remapped to `deny` (CHECK constraint), with the pre-remap value kept
  in `original_outcome` for hash recomputation. *Ref:* `schema.py:21-28`,
  `invocation.py:1419-1446`.
- **`AuditEventType`** (14 values — enumerate all): `TOOL_INVOCATION`,
  `TOOL_REGISTERED`, `TOOL_STATUS_CHANGED`, `TOOL_DELETED`,
  `AUDIT_RERUN_TRIGGERED`, `COMPLIANCE_RUN_TRIGGERED`, `ANOMALY_ALERT_RESOLVED`,
  `POLICY_EVAL_MANUAL`, `INTERNAL_TOOL_INVOCATION`, `API_KEY_CREATED`,
  `API_KEY_REVOKED`, `CREDENTIAL_UPLOADED`, `CREDENTIAL_REVOKED`,
  `CREDENTIAL_MODE_CHANGED`. *Ref:* `schema.py:31-45`.
  - `INTERNAL_TOOL_INVOCATION` is used for events with no `tool_id` (auth-failure
    401/403 rows and `/mcp` meta-tools) so the TOOL_INVOCATION `tool_id`
    requirement does not reject them.
  - `AUDIT_ARCHIVAL_RUN` is **not** a schema enum value — the compliance checker
    emits it only as a raw stdout JSON dict.

### 8.2 Required vs optional fields

| Field | Required | Notes |
|---|---|---|
| `event_id` (UUID) | yes (auto) | uuid4 |
| `event_type` | yes | default `TOOL_INVOCATION` |
| `timestamp` (UTC) | yes (auto) | isoformat persisted verbatim (`event_ts_iso`) to avoid TIMESTAMPTZ render drift breaking hash verify |
| `client_id` | yes | empty ⇒ `AuditSchemaError` |
| `platform_version` | yes | default `1.0.0` |
| `tool_name`, `tool_id`, `outcome` | yes **iff** `event_type=TOOL_INVOCATION` | enforced in `_validate` |
| `request_id` | present | used for correlation |
| `tool_version`, `latency_ms`, `deny_reasons[]`, `anomaly_score`, `opa_decision_id`, `is_testing` | optional | |
| `source_ip`, `principal_type`, `roles[]`, `session_jti` | optional | "who" enrichment |
| `tainted` | optional | advisory; **not** in the integrity hash |
| `sha256_hash` | computed | `init=False`, set in `__post_init__` |

The persisted `audit_events` row additionally carries `hmac_signature`,
`hmac_key_id`, `original_outcome`, `event_ts`, `event_ts_iso`, `caller_roles`
(TEXT[]), and `opa_decision_id`. *Ref:* `invocation.py:1394-1463`.

---

## 9. What a re-implementer MUST preserve vs MAY swap

| Concern | Requirement |
|---|---|
| Synchronous audit **before** response; emission failure ⇒ 500 | **MUST NOT** swap — this is INV-001 |
| INV-002 redaction (10 categories) applied before emission; writer/verifier lists identical | **MUST NOT** swap |
| Append-only audit at the DB (single-writer grants + immutability trigger) | **MUST NOT** swap — INV-011 |
| The 9-field canonicalization + shared canonicalizer for hash/HMAC | **MUST** preserve (writer and verifier must agree byte-for-byte) |
| Audit event schema field names + `AuditEventType`/`AuditOutcome` values | **MUST** keep stable enough that the Sigma rules (SPEC-03 §10) still match |
| HMAC required in production (`AUDIT_LOG_HMAC_KEY` forced at startup) | **MUST** preserve for a production-grade build |
| Loki / Promtail / Grafana / Alertmanager | **MAY** swap for any equivalent collector — not a security boundary |
| Wazuh syslog emitter | **MAY** swap/omit — best-effort secondary path, must never affect INV-001 |
| MinIO GOVERNANCE Object-Lock | **SHOULD** upgrade to COMPLIANCE/WORM in production (current gap) |
| Hash-chain / Merkle / transparency log | **(roadmap)** — MAY add; MUST NOT claim as present today |

---

## 10. Discrepancies found

1. **"50+ redaction patterns"** — the actual surface is **10** structured
   redaction categories (INV-002, `redaction.py`) plus **2** root-logger
   `RedactingFilter` patterns (`log_filter.py`). Documented accurately in §3.
2. **`AUDIT_ARCHIVAL_RUN`** appears in the compliance checker's stdout emission
   but is **not** a member of the `AuditEventType` enum (§8.1). It is not a
   schema-validated event.
3. **RFC-0002 §5.4** is cited by `transparency_log.py`, but no RFC document exists
   in the repo at HEAD — the citation is a code-comment anchor. The module is a
   fail-closed stub (§4).

---

## 11. Metrics, dashboards, alerts, runbooks (CR-17 / WP-D1)

**`GET /metrics`** on the proxy (`proxy/app/routers/metrics.py` +
`app/services/metrics.py`, public path — no secrets in a counter/gauge) and
on scanner-worker (`scanner_worker/metrics.py`, its own tiny
`prometheus_client.start_http_server(9100)` since it's a bare poll loop, not
an ASGI app). Deliberately a small, hand-picked set tied to CR-17's own hard
invariants rather than blanket auto-instrumentation:

| Series | Kind | Updated |
|---|---|---|
| `mcp_authz_decisions_total{decision}` | counter | inline, `services/policy.py::evaluate_policy` (every OPA call) |
| `mcp_opa_up` / `mcp_vault_up` | gauge | inline, on every OPA call / `kms.py::get_master_secret` call |
| `mcp_audit_emit_failures_total` | counter | inline, `middleware/audit.py::_audit_500_response` (the INV-001 boundary itself) |
| `mcp_credential_broker_failures_total{error_type}` | counter | inline, `services/invocation.py`'s `CredentialInjectionError` handler |
| `mcp_scan_queue_depth{status}` | gauge | scrape-time DB query (reuses `scan_queue.queue_depth()`) |
| `mcp_quarantine_backlog` | gauge | scrape-time DB query (`tool_registry.status='quarantined'`) |
| `mcp_stale_scan_count` | gauge | scrape-time DB query (`server_registry` past `RESCAN_INTERVAL_HOURS`, mirrors the `SCAN_FRESHNESS_ENFORCED` gate) |
| `mcp_scanner_worker_jobs_{claimed,completed,requeued,dead_letter}_total`, `mcp_scanner_worker_job_duration_seconds` | counter/histogram | inline, `scanner_worker/worker.py::_process_one` |

**Prometheus** (`observability/prometheus/`, new `prometheus` service in
`docker-compose.yml`) scrapes both targets every 15s and evaluates
`rules.yml`'s 8 alert rules, firing into the **same Alertmanager** the Loki
ruler already used (one alerting pipeline, two rule sources — log-derived
security detections vs metric-derived availability/invariant alerts). All
thresholds carry `initial_default: "true"` per the D4 decision (no
production reference environment exists yet to calibrate against).

**Dashboards** extend both Grafana instances already in the lab:
`observability/grafana/dashboards/observability-cr17.json` (the base/
production-shaped `grafana` service, 12 panels) and
`lab/grafana/provisioning/dashboards/wp-d1-observability.json` (`lab-grafana`,
8 panels, includes a Loki-based submission-funnel panel alongside the
Prometheus ones since no Prometheus counter exists for submission lifecycle
stages).

**9 runbooks** under `docs/runbooks/`: `vault-init-unseal.md`,
`opa-bundle-signing.md`, `keycloak-client-setup.md`,
`git-provider-setup.md`, `private-cidr-allowlisting.md`,
`scanner-failure.md`, `quarantine-release.md`, `audit-restore.md`,
`incident-triage.md` — each walked once against the live lab.

**Synthetic probe** (`lab/scripts/synthetic_probe.py`, `make -f
Makefile.lab lab-probe`): login (real Keycloak password grant) → low-risk
invoke (`echo-sa`/`whoami`, the same fixture the AT1 auth matrix uses) →
audit-emission check (polls `audit_events` for the matching
`TOOL_INVOCATION` row — fails the probe if the invocation succeeded but left
no audit trail, not just if the invocation itself failed). Confirmed green
against the live lab.

**CR-15 remainder** (`init-engine.sh`/`init-standard.sh` preflight +
`make smoke-engine`/`smoke-standard`) was **not** folded in — out of capacity
for this pass; still open.
