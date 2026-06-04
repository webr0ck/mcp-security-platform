# MCP Security Platform — Detection Rules

Sigma-format detection rules for the MCP Security Platform audit stream.
One rule per file. Threat taxonomy aligned with [ATR spec](https://agentthreatrule.org/en/spec).

## Logsource

All rules use:
```yaml
logsource:
  product: mcp-security-platform
  service: audit
```

This maps to structured JSON emitted by `mcp-proxy` to stdout, collected by Promtail/Filebeat.

## Audit event fields

| Field | Type | Values |
|---|---|---|
| `event_type` | string | `TOOL_INVOCATION`, `CREDENTIAL_UPLOADED`, `CREDENTIAL_REVOKED`, `CREDENTIAL_MODE_CHANGED`, `TOOL_STATUS_CHANGED`, `API_KEY_CREATED`, `API_KEY_REVOKED`, … |
| `outcome` | string | `allow`, `deny`, `error` |
| `client_id` | string | resolved client identity |
| `tool_name` | string | registered tool name |
| `tool_id` | string | UUID |
| `anomaly_score` | float | 0.0 – 1.0 |

## Rules

| File | Level | Description |
|---|---|---|
| `mcp-tool-invocation-denied.yml` | medium | Any single OPA deny |
| `mcp-policy-probe-burst.yml` | high | 5+ denies in 60s from same client |
| `mcp-high-anomaly-score.yml` | high | Allowed invocation with anomaly_score ≥ 0.8 |
| `mcp-credential-change.yml` | medium | Credential uploaded/revoked/mode changed |
| `mcp-quarantined-tool-access.yml` | critical | Invocation attempt on quarantined tool |

## Compiling to SIEM backends

```bash
# Install sigma-cli
pip install sigma-cli

# Compile to Elasticsearch/OpenSearch query (for Wazuh indexer)
sigma convert -t opensearch -p mcp detections/

# Compile to Loki LogQL (for Grafana alerting)
sigma convert -t loki detections/

# Compile to Splunk SPL
sigma convert -t splunk detections/
```

Create a pipeline file `sigma-pipeline-mcp.yml` to map the `mcp-security-platform` product to your index pattern.
