# Wazuh Runtime Rules

Source of truth: `detections/*.yml` (Sigma format, ATR-aligned).

The XML files here are compiled from the Sigma rules for Wazuh's native rule engine.
To recompile after updating a Sigma rule:

```bash
# Install sigma-cli with opensearch/wazuh backend
pip install sigma-cli
sigma convert -t wazuh -p wazuh detections/ -o deployments/poc/wazuh/rules/
```

The `mcp-audit-rules.xml` is the compiled runtime artifact — do not edit directly.
