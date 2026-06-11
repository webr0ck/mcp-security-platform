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
| `mcp-high-anomaly-score.yml` | high | Allowed invocation with anomaly_score > 0.85 |
| `mcp-high-anomaly-denied.yml` | high | Denied invocation with anomaly_score > 0.85 (OPA blocked) |
| `mcp-credential-change.yml` | medium | Credential uploaded/revoked/mode changed |
| `mcp-quarantined-tool-access.yml` | critical | Invocation attempt on quarantined tool |
| `mcp-slow-exfiltration.yml` | medium | Same tool invoked 30+ times in 1h (experimental) |
| `mcp-tool-lifecycle-event.yml` | medium | Tool registered, status changed, or deleted |

## Compiling to SIEM backends

The rules are manually authored Sigma YAML; sigma-cli compilation is not yet automated.
The LogQL equivalents for Loki alerting are maintained by hand in
`observability/loki/rules/mcp_alerts.yml` and are mounted into the Loki ruler.

When sigma-cli is available, the following commands will convert the rules:

```bash
# Install sigma-cli (pin versions for reproducibility)
pip install sigma-cli==1.0.2 pysigma-backend-loki==1.0.0

# Compile to Loki LogQL (for Grafana alerting)
sigma convert -t loki -p sigma-pipeline-mcp.yml detections/

# Compile to Elasticsearch/OpenSearch query (for Wazuh indexer)
sigma convert -t opensearch -p sigma-pipeline-mcp.yml detections/

# Compile to Splunk SPL
sigma convert -t splunk -p sigma-pipeline-mcp.yml detections/
```

Create a pipeline file `sigma-pipeline-mcp.yml` to map the `mcp-security-platform` product
to your index pattern before running the above commands.
